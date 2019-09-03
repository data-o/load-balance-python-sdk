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
This module provides authentication functions for bce services.
"""

import datetime
from builtins import str
from hashlib import sha256
import hmac
import logging
import functools
import time
import calendar

from baidubce.exception import BceClientError
from baidubce.http import http_headers
from baidubce import utils
from baidubce import compat

_logger = logging.getLogger(__name__)

EMPTY_SHA256_HASH = (
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
# This is the buffer size used when calculating sha256 checksums.
# Experimenting with various buffer sizes showed that this value generally
# gave the best result (in terms of performance).
PAYLOAD_BUFFER = 1024 * 1024
ISO8601 = '%Y-%m-%dT%H:%M:%SZ'
SIGV4_TIMESTAMP = '%Y%m%dT%H%M%SZ'
SIGNED_HEADERS_BLACKLIST = [
    'expect',
    'user-agent',
    'x-amzn-trace-id',
]
UNSIGNED_PAYLOAD = 'UNSIGNED-PAYLOAD'

DEFAULT_PORTS = {
    'http': 80,
    'https': 443
}


if compat.PY3:
    import http.client
    class HTTPHeaders(http.client.HTTPMessage):
        pass

    from urllib.parse import quote
    from urllib.parse import urlsplit
    from email.utils import formatdate

    def ensure_unicode(s, encoding=None, errors=None):
        # NOOP in Python 3, because every string is already unicode
        return s

else:
    from urllib import quote
    from urlparse import urlsplit
    from email.message import Message
    from email.Utils import formatdate

    class HTTPHeaders(Message):

        # The __iter__ method is not available in python2.x, so we have
        # to port the py3 version.
        def __iter__(self):
            for field, value in self._headers:
                yield field

    def ensure_unicode(s, encoding='utf-8', errors='strict'):
        if isinstance(s, compat.text_type):
            return s
        return unicode(s, encoding, errors)


class BaseSigner(object):
    REQUIRES_REGION = False

    def _add_auth(self, protocol, host, port, http_method, path, headers, params, body):
        raise BceClientError("Not implemented add_auth")

class SigV4Auth(BaseSigner):
    """
    Sign a request with Signature V4.
    """
    REQUIRES_REGION = True

    def __init__(self, credentials, service_name, region_name):
        self.credentials = credentials
        # We initialize these value here so the unit tests can have
        # valid values.  But these will get overriden in ``add_auth``
        # later for real requests.
        self._region_name = region_name
        self._service_name = service_name

    def _sign(self, key, msg, hex=False):
        if hex:
            sig = hmac.new(key, msg.encode('utf-8'), sha256).hexdigest()
        else:
            sig = hmac.new(key, msg.encode('utf-8'), sha256).digest()
        return sig

    def headers_to_sign(self, protocol, host, port, headers):
        """
        Select the headers from the request that need to be included
        in the StringToSign.
        """
        header_map = HTTPHeaders()
        for name, value in headers.items():
            lname = name.lower()
            if lname not in SIGNED_HEADERS_BLACKLIST:
                header_map[lname] = value

        if 'host' not in header_map:
            # Ensure we sign the lowercased version of the host, as that
            # is what will ultimately be sent on the wire.
            # TODO: We should set the host ourselves, instead of relying on our
            # HTTP client to set it for us.
            header_map['host'] = self._canonical_host(protocol, host, port).lower()
        return header_map

    def _canonical_host(self, protocol, host, port):
        if port != protocol.default_port:
            return host + b':' + port
        else:
            # No need to include the port if it's the default port.
            return host

    def canonical_query_string(self, path, params):
        # The query string can come from two parts.  One is the
        # params attribute of the request.  The other is from the request
        # url (in which case we have to re-split the url into its components
        # and parse out the query string component).
        if params:
            return self._canonical_query_string_params(params)
        else:
            return self._canonical_query_string_url(urlsplit(path))

    def _canonical_query_string_params(self, params):
        l = []
        for param in sorted(params):
            value = str(params[param])
            l.append('%s=%s' % (quote(param, safe='-_.~'),
                                quote(value, safe='-_.~')))
        cqs = '&'.join(l)
        return cqs

    def _canonical_query_string_url(self, parts):
        canonical_query_string = ''
        if parts.query:
            # [(key, value), (key2, value2)]
            key_val_pairs = []
            for pair in parts.query.split('&'):
                key, _, value = pair.partition('=')
                key_val_pairs.append((key, value))
            sorted_key_vals = []
            # Sort by the key names, and in the case of
            # repeated keys, then sort by the value.
            for key, value in sorted(key_val_pairs):
                sorted_key_vals.append('%s=%s' % (key, value))
            canonical_query_string = '&'.join(sorted_key_vals)
        return canonical_query_string

    def canonical_headers(self, headers_to_sign):
        """
        Return the headers that need to be included in the StringToSign
        in their canonical form by converting all header keys to lower
        case, sorting them in alphabetical order and then joining
        them into a string, separated by newlines.
        """
        headers = []
        sorted_header_names = sorted(set(headers_to_sign))

        for key in sorted_header_names:
            value = ','.join(self._header_value(v) for v in
                             sorted(headers_to_sign.get_all(key)))
            headers.append('%s:%s' % (key, ensure_unicode(value)))
        return '\n'.join(headers)

    def _header_value(self, value):
        # From the sigv4 docs:
        # Lowercase(HeaderName) + ':' + Trimall(HeaderValue)
        #
        # The Trimall function removes excess white space before and after
        # values, and converts sequential spaces to a single space.
        return ' '.join(value.split())

    def signed_headers(self, headers_to_sign):
        l = ['%s' % n.lower().strip() for n in set(headers_to_sign)]
        l = sorted(l)
        return ';'.join(l)

    def payload(self, headers, body):
        if not self._should_sha256_sign_payload(headers):
            # When payload signing is disabled, we use this static string in
            # place of the payload checksum.
            return UNSIGNED_PAYLOAD
        request_body = body
        if request_body and hasattr(request_body, 'seek'):
            position = request_body.tell()
            read_chunksize = functools.partial(request_body.read,
                                               PAYLOAD_BUFFER)
            checksum = sha256()
            for chunk in iter(read_chunksize, b''):
                checksum.update(chunk)
            hex_checksum = checksum.hexdigest()
            request_body.seek(position)
            return hex_checksum
        elif request_body:
            # The request serialization has ensured that
            # request.body is a bytes() type.
            return sha256(request_body).hexdigest()
        else:
            return EMPTY_SHA256_HASH

    def _should_sha256_sign_payload(self, headers):
        # defalut is false.
        return False

    def canonical_request(self, protocol, host, port, http_method, path, headers, params, body):
        cr = [http_method, path]
        cr.append(self.canonical_query_string(path, params))

        headers_to_sign = self.headers_to_sign(protocol, host, port, headers)
        cr.append(self.canonical_headers(headers_to_sign) + '\n')
        cr.append(self.signed_headers(headers_to_sign))
        if 'X-Amz-Content-SHA256' in headers:
            body_checksum = headers['X-Amz-Content-SHA256']
        else:
            body_checksum = self.payload(headers, body)
        cr.append(body_checksum)
        return '\n'.join(cr)

    def _utils_normalize_url_path(self, url):
        if not url:
            return '/'

        # RFC 3986, section 5.2.4 "Remove Dot Segments"
        # Also, AWS services require consecutive slashes to be removed,
        # so that's done here as well
        input_url = url.split('/')
        output_list = []
        for x in input_url:
            if x and x != '.':
                if x == '..':
                    if output_list:
                        output_list.pop()
                else:
                    output_list.append(x)
    
        if url[0] == '/':
            first = '/'
        else:
            first = ''
        if url[-1] == '/' and output_list:
            last = '/'
        else:
            last = ''
        return first + '/'.join(output_list) + last

    def _normalize_url_path(self, path):
        normalized_path = quote(self._utils_normalize_url_path(path), safe='/~')
        return normalized_path

    def scope(self, timestamp):
        scope = [self.credentials.access_key_id]
        scope.append(timestamp[0:8])
        scope.append(self._region_name)
        scope.append(self._service_name)
        scope.append('aws4_request')
        return '/'.join(scope)

    def credential_scope(self, timestamp):
        scope = []
        scope.append(timestamp[0:8])
        scope.append(self._region_name)
        scope.append(self._service_name)
        scope.append('aws4_request')
        return '/'.join(scope)

    def string_to_sign(self, timestamp, canonical_request):
        """
        Return the canonical StringToSign as well as a dict
        containing the original version of all headers that
        were included in the StringToSign.
        """
        sts = ['AWS4-HMAC-SHA256']
        sts.append(timestamp)
        sts.append(self.credential_scope(timestamp))
        sts.append(sha256(canonical_request.encode('utf-8')).hexdigest())
        return '\n'.join(sts)

    def signature(self, timestamp, string_to_sign):
        key = self.credentials.secret_access_key
        k_date = self._sign(('AWS4' + key).encode('utf-8'), timestamp[0:8])
        k_region = self._sign(k_date, self._region_name)
        k_service = self._sign(k_region, self._service_name)
        k_signing = self._sign(k_service, 'aws4_request')
        return self._sign(k_signing, string_to_sign, hex=True)

    def _add_auth(self, protocol, host, port, http_method, path, headers, params, body):
        if self.credentials is None:
            raise BceClientError(b'No credential is specified.' % http_headers.CONTENT_LENGTH)

        datetime_now = datetime.datetime.utcnow()
        timestamp = datetime_now.strftime(SIGV4_TIMESTAMP)

        # This could be a retry.  Make sure the previous
        # authorization header is removed first.
        self._modify_request_before_signing(headers, timestamp, body)
        canonical_request = self.canonical_request(protocol, host, port, http_method, 
                path, headers, params, body)

        _logger.debug("Calculating signature using v4 auth.")
        _logger.debug('CanonicalRequest:\n%s', canonical_request)
        string_to_sign = self.string_to_sign(timestamp, canonical_request)
        _logger.debug('StringToSign:\n%s', string_to_sign)
        signature = self.signature(timestamp, string_to_sign)
        _logger.debug('Signature:\n%s', signature)

        self._inject_signature_to_request(protocol, host, port, headers, timestamp, signature)

    def _inject_signature_to_request(self, protocol, host, port, headers, timestamp, signature):
        l = ['AWS4-HMAC-SHA256 Credential=%s' % self.scope(timestamp)]
        headers_to_sign = self.headers_to_sign(protocol, host, port, headers)
        l.append('SignedHeaders=%s' % self.signed_headers(headers_to_sign))
        l.append('Signature=%s' % signature)
        headers['Authorization'] = ', '.join(l)

    def _modify_request_before_signing(self, headers, timestamp, body):
        if 'Authorization' in headers:
            del headers['Authorization']
        self._set_necessary_date_headers(headers, timestamp)
        if self.credentials.token:
            if 'X-Amz-Security-Token' in headers:
                del headers['X-Amz-Security-Token']
            headers['X-Amz-Security-Token'] = self.credentials.token

    def _set_necessary_date_headers(self, headers, timestamp):
        # The spec allows for either the Date _or_ the X-Amz-Date value to be
        # used so we check both.  If there's a Date header, we use the date
        # header.  Otherwise we use the X-Amz-Date header.
        if 'Date' in headers:
            del headers['Date']
            datetime_timestamp = datetime.datetime.strptime(
                timestamp, SIGV4_TIMESTAMP)
            headers['Date'] = formatdate(
                int(calendar.timegm(datetime_timestamp.timetuple())))
            if 'X-Amz-Date' in headers:
                del headers['X-Amz-Date']
        else:
            if 'X-Amz-Date' in headers:
                del headers['X-Amz-Date']
            headers['X-Amz-Date'] = timestamp


class S3SigV4Auth(SigV4Auth):
    def __init__(self, credentials, service_name, region_name):
        super(S3SigV4Auth, self).__init__(
            credentials, service_name, region_name)

        if credentials == None:
            self._need_sign = False
            return

        self._need_sign = True

        self._default_region_name = region_name

    def sign(self, protocol, host, port, http_method, path, headers, params, body):
        """Sign a request before it goes out over the wire.

        :type protocol: str 
        :param protocol: The scheme, e.g. ``http``

        :type host: string
        :param host: not contain the port
        """
        if not self._need_sign:
            return

        super(S3SigV4Auth, self)._add_auth(protocol, host, port, http_method, path, headers, 
                params, body)

    def _modify_request_before_signing(self, headers, timestamp, body):
        super(S3SigV4Auth, self)._modify_request_before_signing(headers, timestamp, body)
        if 'X-Amz-Content-SHA256' in headers:
            del headers['X-Amz-Content-SHA256']

        headers['X-Amz-Content-SHA256'] = self.payload(headers, body)

    def _should_sha256_sign_payload(self, headers):
        # We require that both content-md5 be present and https be enabled
        # to implicitly disable body signing. The combination of TLS and
        # content-md5 is sufficiently secure and durable for us to be
        # confident in the request without body signing.
        if 'Content-MD5' not in headers:
            return True

        # If the S3-specific checks had no results, delegate to the generic
        # checks.
        return super(S3SigV4Auth, self)._should_sha256_sign_payload(headers)

    def _normalize_url_path(self, path):
        # For S3, we do not normalize the path.
        return path
