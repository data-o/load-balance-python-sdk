# Copyright 2014 Baidu, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License") you may not use this file
# except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the
# License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

"""
This module defines string constants for HTTP headers
"""

# Standard HTTP Headers

AUTHORIZATION = b"Authorization"

CACHE_CONTROL = b"Cache-Control"

CONTENT_DISPOSITION = b"Content-Disposition"

CONTENT_ENCODING = b"Content-Encoding"

CONTENT_LENGTH = b"Content-Length"

CONTENT_MD5 = b"Content-MD5"

CONTENT_RANGE = b"Content-Range"

CONTENT_TYPE = b"Content-Type"

DATE = b"Date"

ETAG = b"ETag"

EXPIRES = b"Expires"

HOST = b"Host"

LAST_MODIFIED = b"Last-Modified"

RANGE = b"Range"

SERVER = b"Server"

USER_AGENT = b"User-Agent"

# BCE Common HTTP Headers

BCE_PREFIX = b"x-bce-"

BCE_CONTENT_SHA256 = b"x-amz-content-sha256"

BCE_DATE = b"x-amz-date"

BCE_REQUEST_ID = b"x-amz-request-id"

BCE_USER_METADATA_PREFIX = b"x-amz-meta-"