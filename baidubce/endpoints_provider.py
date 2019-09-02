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
This module defines endpoints provider for BCE.
"""

import logging
import random
import threading
import time

import baidubce
import baidubce.protocol

from baidubce import compat
from baidubce import utils
from baidubce.http.bce_http_client import send_get_request_without_retry
from exception import BceClientError

MAX_RAND_GAP = 10
MIN_ENDPOINT_LENGTH = 4
MIN_ACTIVE_ENDPOINT_NUM = 1
KEEP_ALIVE_SLEEP_SECOND = 60

_logger = logging.getLogger(__name__)

class SingleEndpoint(object):
    """save the info of one endpoint"""
    def __init__(self, protocol, host, port, host_and_port):
        self.id = 0
        self.protocol = protocol
        self.host = host
        self.port = port
        self.host_and_port = host_and_port
        self.is_in_black_list = False
        self.next = None
        self.pre = None


class EndpointCollection(object):
    """save all endpoints"""

    def __init__(self, credentials, region, service_name, endpoints_path):
        self._signer = S3SigV4Auth(credentials, service_name, region)
        self._parser = XmlParser()
        self._valid_min_endpoint_id = 0
        self._endpoint_head = None
        self._blacklist = {}
        self._num_of_active_endpoint = 0
        self._mutex = threading.Lock()
        self._keep_alive_thread = None
        self._keep_alive_mutex = threading.Lock()
        self._keep_alive_start = False
        self._keep_alive_stop = False
        self._read_endpoints_from_file(endpoints_path)
        self.keep_endpoint_alive()

    def _read_endpoints_from_file(self, endpoints_path):
        content = []
        try:
            with open(endpoints_path) as f:
                content = f.readlines()
                endpoints = [l.strip() for l in content]
        except Exception as e:
            raise BceClientError("failed read endpoints from %s, error: %s", endpoints_path, e)

        for endpoint in content:
            if len(endpoint) < MIN_ENDPOINT_LENGTH:
                continue
            endpoint = compat.convert_to_bytes(endpoint)
            protocol, host, port = utils.parse_host_port(endpoint, baidubce.protocol.HTTP)
            if port != protocol.default_port:
                host_and_port = host +  b':' + compat.convert_to_bytes(port)
            else:
                host_and_port = host

            endpoint = SingleEndpoint(protocol, host, port, host_and_port)
            self._insert_endpoint_to_head(endpoint)
            self._num_of_active_endpoint += 1

    def _insert_endpoint_to_head(self, endpoint):
        if self._endpoint_head is None:
            self._endpoint_head = endpoint
            self._endpoint_head.next = endpoint
            self._endpoint_head.pre = endpoint
        else:
            endpoint.pre = self._endpoint_head.pre
            endpoint.next = self._endpoint_head
            self._endpoint_head.pre.next = endpoint
            self._endpoint_head.pre = endpoint

    def update_endpoint_from_stream(self, body):
        pass

    def add_endpoint_to_blacklist(self, endpoint):
        """
        add an endpoint into blacklist
        """
        with self._mutex:
            if endpoint is None or endpoint.is_in_black_list:
                return self._endpoint_head
            elif self._num_of_active_endpoint <= MIN_ACTIVE_ENDPOINT_NUM:
                return endpoint.next

            _logger.debug(b'add endpoint %s into blacklist', endpoint.host_and_port)
            self._num_of_active_endpoint -= 1

            if self._num_of_active_endpoint == 0:
                self._endpoint_head = None
            else:
                endpoint.next.pre = endpoint.pre
                endpoint.pre.next = endpoint.next
                self._endpoint_head = endpoint.next
            endpoint.next = None
            endpoint.pre = None

            self._blacklist[endpoint.host_and_port] = endpoint
            endpoint.is_in_black_list = True
            return self._endpoint_head

    def rm_endpoint_from_blacklist(self, endpoint):
        pass

    def get_next_endpoint(self, endpoint=None):
        """
        get a endpoint from collection
        """
        if endpoint is None or endpoint.next is None:
            ret = self._get_rand_endpoint()
        elif endpoint.id < self._valid_min_endpoint_id:
            ret = self._get_rand_endpoint()
        else:
            ret =  endpoint.next
        if ret is None:
            raise BceClientError("no endpoint provided")
        return ret

    def _get_rand_endpoint(self):
        """
        get a random endpoint from collection
        """
        retry_time = random.randint(0, MAX_RAND_GAP)
        temp_node = self._endpoint_head

        while temp_node is not None and retry_time > 0:
            temp_node = temp_node.next
            retry_time -= 1

        if temp_node is not None:
            return temp_node
        else:
            return self._endpoint_head

    def _is_endpoint_valid(self, endpoint):
        pass

    def _update_endpoint_by_api(self, last_epoch):
        endpoint = self._endpoint_head
        for i in range(0, self._num_of_active_endpoint):
            if endpoint is None:
                raise BceClientError("keep alive: no active endpoint!")

            try:
                path = b"/"
                params = {b'acl':b''}
                response = send_get_request_without_retry(endpoint, self._signer.signer,
                       [self._parser.parser_error, self._parser.parser_xml], path, params)
            except Exception as e:
                _logger.debug(b'failed get endpoints from %s, error (%s)', 
                        endpoint.host_and_port, e)
                continue

            last_epoch = self._update_endpoint_with_stream(response)
            return last_epoch
        raise BceClientError("failed get endpoints from server")

    def _update_endpoint_with_stream(self, response):
        print response
        return 0

    def keep_alive(self):
        last_epoch = 0
        while not self._keep_alive_stop:
           last_epoch = self._update_endpoint_by_api(last_epoch)
           time.sleep(KEEP_ALIVE_SLEEP_SECOND)


    def keep_endpoint_alive_start(self):
        with self._keep_alive_mutex:
            if self._keep_alive_start:
                return
            else:
                self._keep_alive_start = True
        try:
            self._keep_alive_thread = thread.start_new_thread(self.keep_alve)
        except Exception as e:
            raise BceClientError("failed start keep alive thread, %s", e)

    def stop_keep_endpoint_alive(self):
        pass


class GlobalEndpoints(object):
    """manage all endpoint collections"""

    def __init__(self):
        self._g_endpoints ={}
        self._mutex = threading.Lock()

    def find_endpoint_collection(self, credentials, region, service_name, endpoints_path):
        with self._mutex:
            if endpoints_path in self._g_endpoints:
                return self._g_endpoints[endpoints_path]
            endpoints_collection = EndpointCollection(credentials, region, service_name, 
                    endpoints_path, endpoints_path)
            self._g_endpoints[endpoints_path] = endpoints_collection
            return endpoints_collection