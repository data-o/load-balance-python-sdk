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

import random
import threading
import time
import logging
import os
import socket
import time

import baidubce
import baidubce.protocol
from requests.exceptions import ConnectionError

from baidubce import compat
from baidubce import utils
from baidubce.auth.s3_v4_signer import S3SigV4Auth
from baidubce.http.parsers import XmlParser
from baidubce.http.bce_http_client import BceHttpClient
from baidubce.exception import BceClientError

MIN_ENDPOINT_LENGTH = 4
MIN_ACTIVE_ENDPOINT_NUM = 1
KEEP_ALIVE_SLEEP_SECOND = 60000

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

    def set_id(self, my_id):
        """ set id """
        self.id = my_id


class EndpointCollection(object):
    """save all endpoints"""

    def __init__(self, credentials, region, service_name, endpoints_path):
        self._signer = S3SigV4Auth(credentials, service_name, region)
        self._parser = XmlParser()
        self._valid_min_endpoint_id = 0
        self._num_of_active_endpoint = 0
        self._last_epoch = None
        self._endpoint_head = None
        self._blacklist = {}
        self._mutex = threading.Lock()
        self._pid_to_endpoint = {}
        #for keep alve
        self._last_keep_alive_time = 0
        self._http_client = BceHttpClient(self._signer)
        self._keep_alive_mutex = threading.Lock()
        self._read_endpoints_from_file(endpoints_path)

    def _read_endpoints_from_file(self, endpoints_path):
        content = []
        try:
            with open(endpoints_path) as f:
                content = f.readlines()
                endpoints = [l.strip() for l in content]
        except Exception as e:
            raise BceClientError("failed read endpoints from %s, error: %s" % (endpoints_path, e))

        for endpoint in content:
            if len(endpoint) < MIN_ENDPOINT_LENGTH:
                continue
            protocol, host, port = utils.parse_host_port(endpoint, baidubce.protocol.HTTP)
            if port != protocol.default_port:
                host_and_port = host + ':' + str(port)
            else:
                host_and_port = host

            endpoint = SingleEndpoint(protocol, host, port, host_and_port)
            endpoint.set_id(self._valid_min_endpoint_id)

            self._endpoint_head = self._insert_endpoint_to_head(self._endpoint_head, endpoint)
            self._num_of_active_endpoint += 1

    def _insert_endpoint_to_head(self, head, endpoint):
        if head is None:
            head = endpoint
            head.next = endpoint
            head.pre = endpoint
        elif endpoint.host_and_port < head.host_and_port:
            endpoint.pre = head.pre
            endpoint.next = head
            head.pre.next = endpoint
            head.pre = endpoint
            head = endpoint
        else:
            temp = head.next
            while endpoint.host_and_port > temp.host_and_port and temp != head:
                temp = temp.next
            endpoint.pre = temp.pre
            endpoint.next = temp
            temp.pre.next = endpoint
            temp.pre = endpoint
        return head

    def add_endpoint_to_blacklist(self, endpoint):
        """
        add an endpoint into blacklist
        """
        with self._mutex:
            if endpoint is None or endpoint.is_in_black_list:
                return self._endpoint_head
            elif self._num_of_active_endpoint <= MIN_ACTIVE_ENDPOINT_NUM:
                return self.get_next_endpoint()

            _logger.debug('add endpoint %s into blacklist', endpoint.host_and_port)
            self._num_of_active_endpoint -= 1

            if self._num_of_active_endpoint == 0:
                self._endpoint_head = None
            else:
                endpoint.next.pre = endpoint.pre
                endpoint.pre.next = endpoint.next
                if endpoint == self._endpoint_head:
                    self._endpoint_head = endpoint.next
            endpoint.next = None
            endpoint.pre = None

            self._blacklist[endpoint.host_and_port] = endpoint
            endpoint.is_in_black_list = True
            return self.get_next_endpoint()

    def _rm_endpoint_from_blacklist(self, host):
        """
        remove endpoint from blacklist and insert to active list
        """
        with self._mutex:
            if host not in self._blacklist:
                return False
            endpoint = self._blacklist[host]
            if not endpoint.is_in_black_list:
                return False
            endpoint = self._blacklist[host]
            del self._blacklist[host]
            endpoint.is_in_black_list = False

            if endpoint.id >= self._valid_min_endpoint_id:
                self._endpoint_head = self._insert_endpoint_to_head(self._endpoint_head, 
                        endpoint)
                self._num_of_active_endpoint += 1
                return True
        return False

    def get_endpoint_by_pid(self):
        """
        get a endpoint from collection.
        the same thread will get the same endpoint.
        """
        self.keep_endpoint_alive()

        my_pid = os.getpid()
        key = my_pid * 1000 + threading.current_thread().ident
        endpoint = None

        if key in self._pid_to_endpoint:
            endpoint = self._pid_to_endpoint[key]

        if endpoint is None or endpoint.id < self._valid_min_endpoint_id or endpoint.is_in_black_list:
            endpoint = self._get_rand_endpoint(my_pid % self._num_of_active_endpoint)
            self._pid_to_endpoint[key] = endpoint

        if endpoint is None:
            raise BceClientError("no endpoint provided")
        return endpoint

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

    def _get_rand_endpoint(self, retry_time=-1):
        """
        get a random endpoint from collection
        """
        if retry_time < 0:
            retry_time = random.randint(0, self._num_of_active_endpoint)
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

    def _update_endpoint_by_api(self):
        endpoint = self.get_endpoint_by_pid()
        path = '/'
        params = {'rgw':''}
        for i in range(0, self._num_of_active_endpoint):
            if endpoint is None:
                raise BceClientError("keep alive: no active endpoint!")
            try:
                response = self._http_client.send_get_request_without_retry(endpoint,
                        [self._parser.parser_error, self._parser.parser_xml], path, params)
                _logger.debug('last epoch %s epoch now %s', self._last_epoch, 
                    response.metadata.last_epoch)

                if self._last_epoch != response.metadata.last_epoch:
                    self._last_epoch = response.metadata.last_epoch
                    return self._update_endpoint(response)
                else:
                    return False
            except Exception as e:
                _logger.debug('failed get endpoints from %s, error (%s)', 
                        endpoint.host_and_port, e)
            endpoint = endpoint.next

        _logger.debug('failed get endpoints from server')
        return False

    def _update_endpoint(self, response):
        if not response.contents:
            return False

        head = None
        endpoints_num = 0
        for rgw in response.contents:
            endpoint_str = rgw.ip + ':' + rgw.port
            protocol, host, port = utils.parse_host_port(endpoint_str, baidubce.protocol.HTTP)
            host_and_port = host
            if port != protocol.default_port:
               host_and_port += ':' + str(port)
            _logger.debug('** insert %s to active list', host_and_port)
            endpoint = SingleEndpoint(protocol, host, port, host_and_port)
            head = self._insert_endpoint_to_head(head, endpoint)
            endpoints_num += 1

        if endpoints_num <= 0:
            return False

        with self._mutex:
            for i in range(0, endpoints_num):
                head.set_id(self._valid_min_endpoint_id + 1)
                head = head.next

            # update current active endpoints
            self._endpoint_head = head
            # _valid_min_endpoint_id must be protected by lock
            self._valid_min_endpoint_id += 1
            self._num_of_active_endpoint = endpoints_num
            # clear balcklist
            self._blacklist.clear()

        return True

    def _probing_response_deal(self, http_response, response):
        body = http_response.read()
        http_response.close()

    def _probing_blacklist(self):
        path = "/"
        params = {'rgw':''}
        need_update = False
        keys = list(self._blacklist.keys())
        for host in keys:
            try:
                endpoint = self._blacklist[host]
                # need use new connection
                self._http_client.send_get_request_without_retry(endpoint,
                        [self._probing_response_deal], path, params, True)
                ret = self._rm_endpoint_from_blacklist(host)
                need_update = (need_update or ret)
            except Exception as e:
                continue

        # remove all connections
        if need_update:
            self._pid_to_endpoint.clear()

    def keep_alive(self):
        """ keep alive """
        ret = self._update_endpoint_by_api()
        # probing blacklist when we can't fetch endpoints from server
        if not ret:
           self._probing_blacklist()

    def keep_endpoint_alive(self):
        """ start to keep alive """
        now = int(time.time()*1000)
        if now - self._last_keep_alive_time < KEEP_ALIVE_SLEEP_SECOND:
            return

        with self._keep_alive_mutex:
            if now - self._last_keep_alive_time >= KEEP_ALIVE_SLEEP_SECOND:
                self._last_keep_alive_time = now
                self.keep_alive()


class GlobalEndpoints(object):
    """manage all endpoint collections"""

    def __init__(self):
        self._g_endpoints ={}
        self._mutex = threading.Lock()

    def find_endpoint_collection(self, credentials, region, service_name, endpoints_path):
        """ the endpoint collection """
        with self._mutex:
            if endpoints_path in self._g_endpoints:
                return self._g_endpoints[endpoints_path]
            endpoints_collection = EndpointCollection(credentials, region, service_name, 
                    endpoints_path)
            self._g_endpoints[endpoints_path] = endpoints_collection
            return endpoints_collection
