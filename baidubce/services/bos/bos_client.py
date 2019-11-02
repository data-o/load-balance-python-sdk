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

"""
This module provides a client class for BOS.
"""

import io
import copy
import http.client
import os
import json
import logging
import shutil
import threading

from builtins import str
from builtins import bytes
from future.utils import iteritems, iterkeys, itervalues

import baidubce
from baidubce import bce_client_configuration
from baidubce import utils
from baidubce.auth.s3_v4_signer import S3SigV4Auth
from baidubce.auth.bce_credentials import BceCredentials
from baidubce.bce_base_client import BceBaseClient
from baidubce.exception import BceClientError
from baidubce.exception import BceServerError
from baidubce.exception import BceHttpClientError
from baidubce.http import bce_http_client
from baidubce.http import handler
from baidubce.http import http_content_types
from baidubce.http import http_headers
from baidubce.http import http_methods
from baidubce.http.parsers import XmlParser
from baidubce.services import bos
from baidubce.services.bos import bos_handler
from baidubce.utils import required
from baidubce import compat


_logger = logging.getLogger(__name__)

FETCH_MODE_SYNC = "sync"
FETCH_MODE_ASYNC = "async"

ENCRYPTION_ALGORITHM= "AES256"


class BosClient(BceBaseClient):
    """
    sdk client
    """
    def __init__(self, config):
        #if config is None:
        #    config = BceCredentials()
        BceBaseClient.__init__(self, config)
        self._parser = XmlParser()

    def list_buckets(self, config=None):
        """
        List buckets of user

        :param config: None
        :type config: BceClientConfiguration
        :returns: all buckets owned by the user.
        :rtype: baidubce.bce_response.BceResponse
        """
        return self._send_request(http_methods.GET, config=config)

    @required(bucket_name=(bytes, str))
    def create_bucket(self, bucket_name, config=None):
        """
        Create bucket with specific name

        :param bucket_name: the name of bucket
        :type bucket_name: string or unicode
        :param config: None
        :type config: BceClientConfiguration
        :returns:
        :rtype: baidubce.bce_response.BceResponse
        """
        return self._send_request(http_methods.PUT, bucket_name, config=config)

    @required(bucket_name=(bytes, str))
    def does_bucket_exist(self, bucket_name, config=None):
        """
        Check whether there is a bucket with specific name

        :param bucket_name: None
        :type bucket_name: str
        :return:True or False
        :rtype: bool
        """
        try:
            self._send_request(http_methods.HEAD, bucket_name, config=config)
            return True
        except BceHttpClientError as e:
            if isinstance(e.last_error, BceServerError):
                if e.last_error.status_code == http.client.FORBIDDEN:
                    return True
                if e.last_error.status_code == http.client.NOT_FOUND:
                    return False
            raise e

    @required(bucket_name=(bytes, str))
    def delete_bucket(self, bucket_name, config=None):
        """
        Delete a Bucket(Must Delete all the Object in Bucket before)

        :type bucket: string
        :param bucket: None
        :return:
            **HttpResponse Class**
        """
        return self._send_request(http_methods.DELETE, bucket_name, config=config)

    @required(bucket_name=(bytes, str))        
    def list_objects(self, bucket_name,
                     max_keys=1000, prefix=None, marker=None, delimiter=None,
                     config=None):
        """
        Get Object Information of bucket

        :type bucket: string
        :param bucket: None

        :type delimiter: string
        :param delimiter: None

        :type marker: string
        :param marker: None

        :type max_keys: int
        :param max_keys: value <= 1000

        :type prefix: string
        :param prefix: None

        :return:
            **_ListObjectsResponse Class**
        """
        params = {}
        if max_keys is not None:
            params['max-keys'] = max_keys
        if prefix is not None:
            params['prefix'] = prefix
        if marker is not None:
            params['marker'] = marker
        if delimiter is not None:
            params['delimiter'] = delimiter

        response = self._send_request(http_methods.GET, bucket_name, params=params, config=config)
        #when only one object
        if response.contents and isinstance(response.contents, utils.Expando):
            response.contents = [response.contents]
        return response


    @required(bucket_name=(bytes, str))
    def list_all_objects(self, bucket_name, prefix=None, delimiter=None, config=None):
        """

        :param bucket_name:
        :param prefix:
        :param delimiter:
        :param config:
        :return:
        """
        marker = None
        while True:
            response = self.list_objects(
                bucket_name, marker=marker, prefix=prefix, delimiter=delimiter, config=config)
            for item in response.contents:
                yield item
            if response.is_truncated == 'true':
                marker = response.next_marker
            else:
                break

    @staticmethod
    def _get_range_header_dict(range):
        if range is None:
            return None
        if not isinstance(range, (list, tuple)):
            raise TypeError('range should be a list or a tuple')
        if len(range) != 2:
            raise ValueError('range should have length of 2')
        return {http_headers.RANGE: 'bytes=%d-%d' % tuple(range)}


    @staticmethod
    def _parse_bos_object(http_response, response):
        """Sets response.body to http_response and response.user_metadata to a dict consists of all http
        headers starts with 'x-bce-meta-'.

        :param http_response: the http_response object returned by HTTPConnection.getresponse()
        :type http_response: httplib.HTTPResponse

        :param response: general response object which will be returned to the caller
        :type response: baidubce.BceResponse

        :return: always true
        :rtype bool
        """
        user_metadata = {}
        headers_list = http_response.getheaders()
        if compat.PY3:
            temp_heads = []
            for k, v in headers_list:
                k = k.lower()
                temp_heads.append((k, v))
            headers_list = temp_heads

        prefix = compat.convert_to_string(
                http_headers.BCE_USER_METADATA_PREFIX
        )
        for k, v in headers_list:
            if k.startswith(prefix):
                k = k[len(prefix):]
                user_metadata[compat.convert_to_unicode(k)] = \
                    compat.convert_to_unicode(v)
        response.metadata.user_metadata = user_metadata
        response.data = http_response
        return True

    @required(bucket_name=(bytes, str), key=(bytes, str))
    def get_object(self, bucket_name, key, range=None, config=None):
        """

        :param bucket_name:
        :param key:
        :param range:
        :param config:
        :return:
        """
#         key = compat.convert_to_bytes(key)
        return self._send_request(
            http_methods.GET,
            bucket_name,
            key,
            headers=BosClient._get_range_header_dict(range),
            config=config,
            body_parser=BosClient._parse_bos_object)

    @staticmethod
    def _save_body_to_file(http_response, response, file_name, buf_size):
        f = open(file_name, 'wb')
        try:
            shutil.copyfileobj(http_response, f, buf_size)
            http_response.close()
        finally:
            f.close()
        return True

    @required(bucket_name=(bytes, str), key=(bytes, str))
    def get_object_as_string(self, bucket_name, key, range=None, config=None):
        """

        :param bucket_name:
        :param key:
        :param range:
        :param config:
        :return:
        """
#         key = compat.convert_to_bytes(key)
        response = self.get_object(bucket_name, key, range=range, config=config)
        s = response.data.read()
        response.data.close()
        return s

    @required(bucket_name=(bytes, str), key=(bytes, str), file_name=(bytes, str))
    def get_object_to_file(self, bucket_name, key, file_name, range=None, config=None):
        """
        Get Content of Object and Put Content to File

        :type bucket: string
        :param bucket: None

        :type key: string
        :param key: None

        :type file_name: string
        :param file_name: None

        :type range: tuple
        :param range: (0,9) represent get object contents of 0-9 in bytes. 10 bytes date in total.
        :return:
            **HTTP Response**
        """
#         key = compat.convert_to_bytes(key)
#         file_name = compat.convert_to_bytes(file_name)
        return self._send_request(
            http_methods.GET,
            bucket_name,
            key,
            headers=BosClient._get_range_header_dict(range),
            config=config,
            body_parser=lambda http_response, response: BosClient._save_body_to_file(
                http_response,
                response,
                file_name,
                self._get_config_parameter(config, 'recv_buf_size')))

    @required(bucket_name=(bytes, str), key=(bytes, str))
    def get_object_meta_data(self, bucket_name, key, config=None):
        """
        Get head of object

        :type bucket: string
        :param bucket: None

        :type key: string
        :param key: None
        :return:
            **_GetObjectMetaDataResponse Class**
        """
#         key = compat.convert_to_bytes(key)
        return self._send_request(http_methods.HEAD, bucket_name, key, config=config)

    @required(bucket_name=(bytes, str),
              key=(bytes, str),
              data=object,
              content_length=compat.integer_types,
              content_md5=(bytes, str))
    def put_object(self, bucket_name, key, data,
                   content_length,
                   content_md5,
                   content_type=None,
                   content_sha256=None,
                   user_metadata=None,
                   storage_class=None,
                   user_headers=None,
                   config=None):
        """
        Put object and put content of file to the object

        :type bucket: string
        :param bucket: None

        :type key: string
        :param key: None

        :type fp: FILE
        :param fp: None

        :type file_size: long
        :type offset: long
        :type content_length: long
        :return:
            **HTTP Response**
        """
        headers = self._prepare_object_headers(
            content_length=content_length,
            content_md5=content_md5,
            content_type=content_type,
            content_sha256=content_sha256,
            user_metadata=user_metadata,
            storage_class=storage_class,
            user_headers=user_headers)

        buf_size = self._get_config_parameter(config, 'recv_buf_size')

        if content_length > bos.MAX_PUT_OBJECT_LENGTH:
            raise ValueError('Object length should be less than %d. '
                             'Use multi-part upload instead.' % bos.MAX_PUT_OBJECT_LENGTH)

        return self._send_request(
            http_methods.PUT,
            bucket_name,
            key,
            body=data,
            headers=headers,
            config=config)

    @required(bucket=(bytes, str), key=(bytes, str), data=(bytes, str))
    def put_object_from_string(self, bucket, key, data,
                               content_md5=None,
                               content_type=None,
                               content_sha256=None,
                               user_metadata=None,
                               storage_class=None,
                               user_headers=None,
                               config=None):
        """
        Create object and put content of string to the object

        :type bucket: string
        :param bucket: None

        :type key: string
        :param key: None

        :type input_content: string
        :param input_content: None

        :type options: dict
        :param options: None
        :return:
            **HTTP Response**
        """
        if isinstance(data, str):
            data = data.encode(baidubce.DEFAULT_ENCODING)

        fp = None
        try:
            fp = io.BytesIO(data)
            if content_md5 is None:
                content_md5 = utils.get_md5_from_fp(
                    fp, buf_size=self._get_config_parameter(config, 'recv_buf_size'))
            return self.put_object(bucket, key, fp,
                                   content_length=len(data),
                                   content_md5=content_md5,
                                   content_type=content_type,
                                   content_sha256=content_sha256,
                                   user_metadata=user_metadata,
                                   storage_class=storage_class,
                                   user_headers=user_headers,
                                   config=config)
        finally:
            if fp is not None:
                fp.close()

    @required(bucket=(bytes, str), key=(bytes, str), file_name=(bytes, str))
    def put_object_from_file(self, bucket, key, file_name,
                             content_length=None,
                             content_md5=None,
                             content_type=None,
                             content_sha256=None,
                             user_metadata=None,
                             storage_class=None,
                             user_headers=None,
                             config=None):

        """
        Put object and put content of file to the object

        :type bucket: string
        :param bucket: None

        :type key: string
        :param key: None

        :type file_name: string
        :param file_name: None

        :type options: dict
        :param options: None
        :return:
            **HttpResponse Class**
        """
        fp = open(file_name, 'rb')
        try:
            if content_length is None:
                fp.seek(0, os.SEEK_END)
                content_length = fp.tell()
                fp.seek(0)
            if content_md5 is None:
                recv_buf_size = self._get_config_parameter(config, 'recv_buf_size')
                content_md5 = utils.get_md5_from_fp(fp, length=content_length,
                                                    buf_size=recv_buf_size)
            if content_type is None:
                content_type = utils.guess_content_type_by_file_name(file_name)
            return self.put_object(bucket, key, fp,
                                   content_length=content_length,
                                   content_md5=content_md5,
                                   content_type=content_type,
                                   content_sha256=content_sha256,
                                   user_metadata=user_metadata,
                                   storage_class=storage_class,
                                   user_headers=user_headers,
                                   config=config)
        finally:
            fp.close()

    @required(bucket_name=(bytes, str), key=(bytes, str))
    def delete_object(self, bucket_name, key, config=None):
        """
        Delete Object

        :type bucket: string
        :param bucket: None

        :type key: string
        :param key: None
        :return:
            **HttpResponse Class**
        """
#         key = compat.convert_to_bytes(key)
        return self._send_request(http_methods.DELETE, bucket_name, key, config=config)

    @staticmethod
    def _prepare_object_headers(
            content_length=None,
            content_md5=None,
            content_type=None,
            content_sha256=None,
            etag=None,
            user_metadata=None,
            storage_class=None,
            user_headers=None):
        headers = {}

        if content_length is not None:
            if content_length and content_length < 0:
                raise ValueError('content_length should not be negative.')
            headers[http_headers.CONTENT_LENGTH] = str(content_length)

        if content_md5 is not None:
            headers[http_headers.CONTENT_MD5] = content_md5

        if content_type is not None:
            headers[http_headers.CONTENT_TYPE] = content_type
        else:
            headers[http_headers.CONTENT_TYPE] = http_content_types.OCTET_STREAM

        if content_sha256 is not None:
            headers[http_headers.BCE_CONTENT_SHA256] = content_sha256

        if etag is not None:
            headers[http_headers.ETAG] = '"%s"' % etag

        if user_metadata is not None:
            meta_size = 0
            if not isinstance(user_metadata, dict):
                raise TypeError('user_metadata should be of type dict.')
            for k, v in iteritems(user_metadata):
                normalized_key = http_headers.BCE_USER_METADATA_PREFIX + k
                headers[normalized_key] = v
                meta_size += len(normalized_key)
                meta_size += len(v)
            if meta_size > bos.MAX_USER_METADATA_SIZE:
                raise ValueError(
                    'Metadata size should not be greater than %d.' % bos.MAX_USER_METADATA_SIZE)

        if user_headers is not None:
            try:
                headers = BosClient._get_user_header(headers, user_headers, False)
            except Exception as e:
                raise e

        return headers


    @staticmethod
    def _get_user_header(headers, user_headers, is_copy=False):
        if not isinstance(user_headers, dict):
            raise TypeError('user_headers should be of type dict.')

        if not is_copy:
            user_headers_set = set([http_headers.CACHE_CONTROL,
                                    http_headers.CONTENT_ENCODING,
                                    http_headers.CONTENT_DISPOSITION,
                                    http_headers.EXPIRES])
        else:
            user_headers_set = set([http_headers.BCE_COPY_SOURCE_IF_NONE_MATCH,
                                    http_headers.BCE_COPY_SOURCE_IF_UNMODIFIED_SINCE,
                                    http_headers.BCE_COPY_SOURCE_IF_MODIFIED_SINCE])

        for k, v in iteritems(user_headers):
            if k in user_headers_set:
                headers[k] = v
        return headers

    def _get_config_parameter(self, config, attr):
        result = None
        if config is not None:
            result = getattr(config, attr)
        if result is not None:
            return result
        return getattr(self.config, attr)


    @staticmethod
    def _get_path(config, bucket_name=None, key=None):
        return utils.append_uri(bos.URL_PREFIX, bucket_name, key)

    def _merge_config(self, config):
        if config is None:
            return self.config
        else:
            new_config = copy.copy(self.config)
            new_config.merge_non_none_values(config)
            return new_config

    def _send_request(
            self, http_method, bucket_name=None, key=None,
            body=None, headers=None, params=None,
            config=None,
            body_parser=None):
        config = self._merge_config(config)
        path = BosClient._get_path(config, bucket_name, key)
        if body_parser is None:
            body_parser = self._parser.parser_xml

        if config.security_token is not None:
            raise TypeError('not implemented sts.')

        return bce_http_client.send_request(
            config, self.signer, [self._parser.parser_error, body_parser],
            http_method, path, body, headers, params)
