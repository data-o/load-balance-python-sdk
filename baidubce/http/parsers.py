# Copyright 2014 Baidu, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
# except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the
# License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import re
import base64
import json
import xml.etree.cElementTree
import logging

import baidubce.utils

from baidubce import compat
from baidubce.exception import BceClientError
from baidubce.exception import BceServerError
from baidubce.utils import merge_dicts, lowercase_dict, dict_to_python_object_deep

if compat.PY3:
    import http.client as http_client
else:
    import httplib as http_client

LOG = logging.getLogger(__name__)

class XmlParser(object):
    def __init__(self):
        self._namespace_re = re.compile('{.*}')
 
    def parser_error(self, http_response, response):
        if http_response.status < 301:
            return False

        body = http_response.read()

        if self._is_generic_error_response(http_response, body):
            parsed = self._do_generic_error_parse(http_response)
        else:
            parsed = self._do_error_parse(http_response, body)

        error_info = parsed.get('Error', {})
        response_metadata = parsed.get('ResponseMetadata', {})
        bse = BceServerError(error_info.get('Message', error_info.get('Code', '')), 
                code=error_info.get('Code', ''),
                request_id=response_metadata.get('RequestId', ''))
        bse.status_code = http_response.status
        http_response.close()
        raise bse
        return True 

    def parser_xml(self, http_response, response):
        if http_response.status >= 301:
            return False

        body = http_response.read()
        if body is None or len(body) == 0:
            http_response.close()
            return True

        xml_contents = body
        root = self._parse_xml_string_to_dom(xml_contents)
        parsed = self._build_name_to_xml_node(root)
        parsed = self._replace_nodes(parsed)

        temp_obj = dict_to_python_object_deep(parsed)
        if isinstance(temp_obj, baidubce.utils.Expando):
            response.__dict__.update(temp_obj.__dict__)
        else:
            setattr(response, 'contents', temp_obj)

        http_response.close()
        return True

    def _is_generic_error_response(self, http_response, body):
        # There are times when a service will respond with a generic
        # error http_response such as:
        # '<html><body><b>Http/1.1 Service Unavailable</b></body></html>'
        #
        # This can also happen if you're going through a proxy.
        # In this case the protocol specific _do_error_parse will either
        # fail to parse the http_response (in the best case) or silently succeed
        # and treat the HTML above as an XML response and return
        # non sensical parsed data.
        # To prevent this case from happening we first need to check
        # whether or not this response looks like the generic response.
        if http_response.status >= 500:
            if body is None or len(body) == 0:
                return True
    
            return body.startswith(b'<html>') or not body
    
    def _do_generic_error_parse(self, http_response):
        # There's not really much we can do when we get a generic
        # html response.
        LOG.debug("Received a non protocol specific error response from the "
                  "service, unable to populate error code and message.")
        return {
            'Error': {'Code': str(http_response.status),
                      'Message': http_response.reason},
            'ResponseMetadata': {},
        }
    
    
    def _do_error_parse(self, http_response, body):
        # We're trying to be service agnostic here, but S3 does have a slightly
        # different response structure for its errors compared to other
        # rest-xml serivces (route53/cloudfront).  We handle this by just
        # trying to parse both forms.
        # First:
        # <ErrorResponse xmlns="...">
        #   <Error>
        #     <Type>Sender</Type>
        #     <Code>InvalidInput</Code>
        #     <Message>Invalid resource type: foo</Message>
        #   </Error>
        #   <RequestId>request-id</RequestId>
        # </ErrorResponse>
        if body:
            # If the body ends up being invalid xml, the xml parser should not
            # blow up. It should at least try to pull information about the
            # the error response from other sources like the HTTP status code.
            try:
                return self._parse_error_from_body(http_response, body)
            except Exception as e:
                LOG.debug(
                    'Exception caught when parsing error response body:',
                    exc_info=True)
        return self._parse_error_from_http_status(http_response)
    
    def _replace_nodes(self, parsed):
        if isinstance(parsed, list):
            xml_list = []
            for value in parsed:
                xml_list.append(self._replace_nodes(value))
            parsed = xml_list
        elif isinstance(parsed, dict):
            for key, value in parsed.items():
                if list(value):
                    sub_dict = self._build_name_to_xml_node(value)
                    parsed[key] = self._replace_nodes(sub_dict)
                else:
                    parsed[key] = value.text
        elif xml.etree.cElementTree.iselement(parsed):
            if list(parsed):
                parsed = self._build_name_to_xml_node(parsed)
                parsed = self._replace_nodes(parsed)
            else:
                parsed = parsed.text
        return parsed
    
    def _parse_error_from_body(self, http_response, body):
        xml_contents = body
        root = self._parse_xml_string_to_dom(xml_contents)
        parsed = self._build_name_to_xml_node(root)
        parsed = self._replace_nodes(parsed)
        if root.tag == 'Error':
            # This is an S3 error response.  First we'll populate the
            # response metadata.
            metadata = self._populate_response_metadata(http_response)
            # The RequestId and the HostId are already in the
            # ResponseMetadata, but are also duplicated in the XML
            # body.  We don't need these values in both places,
            # we'll just remove them from the parsed XML body.
            parsed.pop('RequestId', '')
            parsed.pop('HostId', '')
            return {'Error': parsed, 'ResponseMetadata': metadata}
        elif 'RequestId' in parsed:
            # Other rest-xml serivces:
            parsed['ResponseMetadata'] = {'RequestId': parsed.pop('RequestId')}
        default = {'Error': {'Message': '', 'Code': ''}}
        merge_dicts(default, parsed)
        return default
    
    def _populate_response_metadata(self, http_response):
        metadata = {}
        headers = dict(http_response.getheaders())
        if 'x-amzn-requestid' in headers:
            metadata['RequestId'] = headers['x-amzn-requestid']
        elif 'x-amz-request-id' in headers:
            metadata['RequestId'] = headers['x-amz-request-id']
            # HostId is what it's called whenver this value is returned
            # in an XML response body, so to be consistent, we'll always
            # call is HostId.
            metadata['HostId'] = headers.get('x-amz-id-2', '')
        return metadata
    
    def _parse_error_from_http_status(self, http_response):
        headers = dict(http_response.getheaders())
        return {
            'Error': {
                'Code': str(http_response.status),
                'Message': http_client.responses.get(
                    http_response.status, ''),
            },
            'ResponseMetadata': {
                'RequestId': headers.get('x-amz-request-id', ''),
                'HostId': headers.get('x-amz-id-2', ''),
            }
        }
    
    def _parse_xml_string_to_dom(self, xml_string):
        try:
            parser = xml.etree.cElementTree.XMLParser(
                target=xml.etree.cElementTree.TreeBuilder(),
                encoding='utf-8')
            parser.feed(xml_string)
            root = parser.close()
        except Exception as e:
            raise BceClientError(
                "Unable to parse response (%s), "
                "invalid XML received:\n%s" % (e, xml_string))
        return root
    
    def _build_name_to_xml_node(self, parent_node):
        # If the parent node is actually a list. We should not be trying
        # to serialize it to a dictionary. Instead, return the first element
        # in the list.
        if isinstance(parent_node, list):
            xml_list = []
            for node in parent_node:
                xml_list.append(self._build_name_to_xml_node(node))
            return xml_list

        xml_dict = {}
        one_key = ""
        for item in parent_node:
            key = self._node_tag(item)
            one_key = key
            if key in xml_dict:
                # If the key already exists, the most natural
                # way to handle this is to aggregate repeated
                # keys into a single list.
                # <foo>1</foo><foo>2</foo> -> {'foo': [Node(1), Node(2)]}
                if isinstance(xml_dict[key], list):
                    xml_dict[key].append(item)
                else:
                    # Convert from a scalar to a list.
                    xml_dict[key] = [xml_dict[key], item]
            else:
                xml_dict[key] = item

        if len(xml_dict) == 1 and isinstance(xml_dict[one_key], list):
            return xml_dict[one_key]
        return xml_dict
    
    def _node_tag(self, node):
        return self._namespace_re.sub('', node.tag)
