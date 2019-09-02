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
This module defines a common configuration class for BCE.
"""
import os
import threading

from future.utils import iteritems
from builtins import str
from builtins import bytes
from baidubce.retry.retry_policy import BackOffRetryPolicy
from baidubce import compat
from baidubce import gloabal_enpoints

DEFAULT_REGION = "bj"
DEFAULT_SERVICE_NAME = "s3"
DEFAULT_CONNECTION_TIMEOUT_IN_MILLIS = 50 * 1000
DEFAULT_SEND_BUF_SIZE = 1024 * 1024
DEFAULT_RECV_BUF_SIZE = 10 * 1024 * 1024

config_folder = os.path.expanduser('~') + os.sep + '.aws'
credential_path = config_folder + os.sep + 'credentials'
endpoints_path = config_folder + os.sep + 'endpoints'

class BceClientConfiguration(object):
    """Configuration of Bce client."""

    def __init__(self,
                 credentials=None,
                 endpoints=endpoints_path,
                 region=DEFAULT_REGION,
                 service_name=DEFAULT_SERVICE_NAME,
                 connection_timeout_in_mills=DEFAULT_CONNECTION_TIMEOUT_IN_MILLIS,
                 send_buf_size=DEFAULT_SEND_BUF_SIZE,
                 recv_buf_size=DEFAULT_RECV_BUF_SIZE,
                 retry_policy=BackOffRetryPolicy(),
                 security_token=None):
        self.credentials = credentials
        self.region = region
        self.service_name = service_name
        self.connection_timeout_in_mills = connection_timeout_in_mills
        self.send_buf_size = send_buf_size
        self.recv_buf_size = recv_buf_size
        if retry_policy is None:
            self.retry_policy = BackOffRetryPolicy()
        else:
            self.retry_policy = retry_policy
        self.security_token = security_token

        self.endpoints_provider = gloabal_enpoints.find_endpoint_collection(credentials, 
                region, service_name, endpoints)

        # thread specific data
        self.personal_data = threading.local()
        self.personal_data.endpoint = self.endpoints_provider.get_next_endpoint()
        
    def merge_non_none_values(self, other):
        """

        :param other:
        :return:
        """
        for k, v in iteritems(other.__dict__):
            if v is not None:
                self.__dict__[k] = v


