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
This module provide http request function for bce services.
"""
from future.utils import iteritems, iterkeys, itervalues
from builtins import str, bytes
import logging
import http.client
import sys
import time
import traceback
import threading
import os

import baidubce
from baidubce import compat
from baidubce import utils
from baidubce.bce_response import BceResponse
from baidubce.exception import BceHttpClientError
from baidubce.exception import BceClientError
from baidubce.http import http_headers
from baidubce.http import http_methods

_logger = logging.getLogger(__name__)
MAX_RETRY_TIME_BEFOR_ADD_BLACKLIST = 1


class BceHttpClient(object):
    """ 
    bce http client.
    """

    def __init__(self, signer):
        self.local_conns = threading.local()
        self.local_conns.conns = {}
        self.signer = signer
        self._pid = os.getpid()
        self._thread_id = threading.current_thread().ident

    def _get_new_connection(self, protocol, host, port, connection_timeout_in_millis):
        """
        :param protocol
        :type protocol: baidubce.protocol.Protocol
        :param endpoint
        :type endpoint: str
        :param connection_timeout_in_millis
        :type connection_timeout_in_millis int
        """
        conn = None
        if protocol.name == baidubce.protocol.HTTP.name:
            conn = http.client.HTTPConnection(
                host=host, port=port, timeout=connection_timeout_in_millis / 1000)
        elif protocol.name == baidubce.protocol.HTTPS.name:
            conn = http.client.HTTPSConnection(
                host=host, port=port, timeout=connection_timeout_in_millis / 1000)
        else:
            raise ValueError(
                'Invalid protocol: %s, either HTTP or HTTPS is expected.' % protocol)
        return conn


    def _get_connection(self, protocol, host, port, connection_timeout_in_millis):
        """
        get cached connection
        """
        if self._pid != os.getpid() or self._thread_id != threading.current_thread().ident:
           self._pid = os.getpid()
           self._thread_id = threading.current_thread().ident
           self.local_conns.conns = {}

        key = protocol.name + host + str(port)
        if key in self.local_conns.conns:
            return self.local_conns.conns[key]
        conn = self._get_new_connection(protocol, host, port, connection_timeout_in_millis)
        self.local_conns.conns[key] = conn
        return conn

    def _del_connection(self, conn, protocol, host, port):
        key = protocol.name + host + str(port)
        if key in self.local_conns.conns:
            del self.local_conns.conns[key]
        conn.close()

    def _send_http_request(self, conn, http_method, uri, headers, body, send_buf_size):
        # putrequest() need that http_method and uri is Ascii on Py2 and unicode \
        # on Py3
        conn.putrequest(http_method, uri, skip_host=True, skip_accept_encoding=True)

        for k, v in iteritems(headers):
            conn.putheader(k, v)
        conn.endheaders()

        if body:
            if isinstance(body, (bytes, str)):
                conn.send(body)
            else:
                total = int(headers[http_headers.CONTENT_LENGTH])
                sent = 0
                while sent < total:
                    size = total - sent
                    if size > send_buf_size:
                        size = send_buf_size
                    buf = body.read(size)
                    if not buf:
                        raise BceClientError(
                            'Insufficient data, only %d bytes available while %s is %d' % (
                                sent, http_headers.CONTENT_LENGTH, total))

                    conn.send(buf)
                    sent += len(buf)

        return conn.getresponse()

    def _check_headers(self, headers):
        """
        check value in headers, if \n in value, raise
        :param headers:
        :return:
        """
        for k, v in iteritems(headers):
            if isinstance(v, (bytes, str)) and \
            b'\n' in compat.convert_to_bytes(v):
                raise BceClientError(r'There should not be any "\n" in header[%s]:%s' % (k, v))

    def send_request(self, config, response_handler_functions, http_method, path, body,
            headers, params):
        """
        Send request to BCE services.
        :param config
        :type config: baidubce.BceClientConfiguration
        :param response_handler_functions:
        :type response_handler_functions: list
        :param request:
        :type request: baidubce.internal.InternalRequest
        :return:
        :rtype: baidubce.BceResponse
        """
        _logger.debug('%s request start: %s %s, %s, %s',
                      http_method, path, headers, params, body)
        headers = headers or {}
        endpoint = config.endpoints_provider.get_endpoint_by_pid()
        headers[http_headers.USER_AGENT] = baidubce.USER_AGENT
        headers[http_headers.HOST] = endpoint.host_and_port

        if isinstance(body, str):
            body = body.encode(baidubce.DEFAULT_ENCODING)
        if not body:
            headers[http_headers.CONTENT_LENGTH] = '0'
        elif isinstance(body, bytes):
            headers[http_headers.CONTENT_LENGTH] = str(len(body))
        elif http_headers.CONTENT_LENGTH not in headers:
            raise ValueError('No %s is specified.' % http_headers.CONTENT_LENGTH)

        # store the offset of fp body
        offset = None
        if hasattr(body, "tell") and hasattr(body, "seek"):
            offset = body.tell()

        encoded_params = utils.get_canonical_querystring(params, False)
        if len(encoded_params) > 0:
            uri = path + '?' + encoded_params
        else:
            uri = path
        self._check_headers(headers)

        retries_attempted = 0
        retries_endpoint_connction = 0
        errors = []
        while True:
            conn = None
            try:
                self.signer.sign(endpoint.protocol, endpoint.host, endpoint.port, http_method, path, 
                        headers, params, body)
                if retries_attempted > 0 and offset is not None:
                    body.seek(offset)

                conn = self._get_connection(endpoint.protocol, endpoint.host, endpoint.port, 
                        config.connection_timeout_in_mills)
                _logger.debug('request args:method=%s, uri=%s, headers=%s,patams=%s, body=%s',
                        http_method, uri, headers, params, body)
                http_response = self._send_http_request(
                    conn, http_method, uri, headers, body, config.send_buf_size)
                headers_list = http_response.getheaders()

                # on py3 ,values of headers_list is decoded with ios-8859-1 from
                # utf-8 binary bytes
                # headers_list[*][0] is lowercase on py2
                # headers_list[*][0] is raw value py3
                if compat.PY3 and isinstance(headers_list, list):
                    temp_heads = []
                    for k, v in headers_list:
                        k = k.encode('latin-1').decode('utf-8')
                        v = v.encode('latin-1').decode('utf-8')
                        k = k.lower()
                        temp_heads.append((k, v))
                    headers_list = temp_heads

                _logger.debug(
                    'request return: status=%d, headers=%s' % (http_response.status, headers_list))
                response = BceResponse()
                response.set_metadata_from_headers(dict(headers_list))

                for handler_function in response_handler_functions:
                    if handler_function(http_response, response):
                        break
                return response
            except Exception as e:
                if conn is not None:
                    self._del_connection(conn, endpoint.protocol, endpoint.host, endpoint.port)
                # insert ">>>>" before all trace back lines and then save it
                errors.append('\n'.join('>>>>' + line for line in traceback.format_exc().splitlines()))
                if config.retry_policy.is_network_error(e, retries_attempted):
                    retries_endpoint_connction += 1
                    if retries_endpoint_connction >= MAX_RETRY_TIME_BEFOR_ADD_BLACKLIST:
                        endpoint = config.endpoints_provider.add_endpoint_to_blacklist(endpoint)
                        retries_endpoint_connction = 0
                    else:
                        delay_in_millis = config.retry_policy.get_delay_before_next_retry_in_millis(
                            e, retries_attempted)
                        time.sleep(delay_in_millis / 1000.0)
                elif config.retry_policy.should_retry(e, retries_attempted):
                    retries_endpoint_connction = 0
                    delay_in_millis = config.retry_policy.get_delay_before_next_retry_in_millis(
                        e, retries_attempted)
                    time.sleep(delay_in_millis / 1000.0)
                else:
                    config.endpoints_provider.add_endpoint_to_blacklist(endpoint)
                    raise BceHttpClientError('Unable to execute HTTP request. Retried %d times. '
                                             'All trace backs:\n%s' % (retries_attempted,
                                                                       '\n'.join(errors)), e)
            retries_attempted += 1

    def send_get_request_without_retry(
            self,
            endpoint,
            response_handler_functions,
            path, params, use_new_connection=False):
        """
        Send request to BCE services.

        :param response_handler_functions:
        :type response_handler_functions: list

        :param request:
        :type request: baidubce.internal.InternalRequest

        :return:
        :rtype: baidubce.BceResponse
        """
        http_method = http_methods.GET

        _logger.debug('%s request start: %s, %s',
                      http_method, path, params)

        headers = {}
        headers[http_headers.USER_AGENT] = baidubce.USER_AGENT
        headers[http_headers.HOST] = endpoint.host_and_port
        headers[http_headers.CONTENT_LENGTH] = '0'

        encoded_params = utils.get_canonical_querystring(params, False)
        if len(encoded_params) > 0:
            uri = path + '?' + encoded_params
        else:
            uri = path

        self._check_headers(headers)

        conn = None

        try:
            self.signer.sign(endpoint.protocol, endpoint.host, endpoint.port, http_method, path,
                    headers, params, None)
            if use_new_connection:
                conn = self._get_new_connection(endpoint.protocol, endpoint.host,
                        endpoint.port, 50 * 1000)
            else:
                conn = self._get_connection(endpoint.protocol, endpoint.host,
                        endpoint.port, 50 * 1000)

            _logger.debug('request args:method=%s, uri=%s, headers=%s,patams=%s',
                    http_method, uri, headers, params)

            http_response = self._send_http_request(
                conn, http_method, uri, headers, None, 1024 * 1024)

            headers_list = http_response.getheaders()

            if compat.PY3 and isinstance(headers_list, list):
                temp_heads = []
                for k, v in headers_list:
                    k = k.encode('latin-1').decode('utf-8')
                    v = v.encode('latin-1').decode('utf-8')
                    k = k.lower()
                    temp_heads.append((k, v))
                headers_list = temp_heads

            _logger.debug(
                'request return: status=%d, headers=%s' % (http_response.status, headers_list))

            response = BceResponse()
            response.set_metadata_from_headers(dict(headers_list))
            for handler_function in response_handler_functions:
                if handler_function(http_response, response):
                    break
            return response
        except Exception as e:
            if conn is not None:
                self._del_connection(conn, endpoint.protocol, endpoint.host, endpoint.port)
            raise e
