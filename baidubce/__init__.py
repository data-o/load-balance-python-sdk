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
This module defines some common string constants.
"""
import sys

from builtins import str
from builtins import bytes
from . import compat
from baidubce.http import endpoints_provider

SDK_VERSION = '0.1.0'
DEFAULT_SERVICE_DOMAIN = 'bcebos.com'
URL_PREFIX = '/v1'
DEFAULT_ENCODING = 'UTF-8'

USER_AGENT = 'abcstorage-sdk-python/%s/%s/%s' % (SDK_VERSION, sys.version, sys.platform)
USER_AGENT = USER_AGENT.replace('\n', '')

gloabal_enpoints = endpoints_provider.GlobalEndpoints()
