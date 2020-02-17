#!/usr/bin/env python
#coding=utf8

# Copyright 2014 Baidu, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
"""
Test models of BOS.
"""
# compatibility py2 and py3
from __future__ import absolute_import
from builtins import str
from builtins import bytes
from future.utils import iteritems
from future.utils import iterkeys
from future.utils import itervalues

import os
import sys
import random
import unittest
import http.client
import io
import json
import socket
import time

import coverage
import baidubce
import bos_test_config
from io import BytesIO
from baidubce.auth.s3_v4_signer import S3SigV4Auth
from baidubce.auth import bce_credentials
from baidubce import utils
from baidubce import compat
from baidubce.services.bos import bos_client
from baidubce.exception import BceHttpClientError
from baidubce.exception import BceServerError
from baidubce.exception import BceClientError
from baidubce.http import http_methods
from baidubce.http import handler
from baidubce.http import endpoints_provider
from baidubce.bce_response import BceResponse
from baidubce import protocol
from baidubce.utils import Expando
from baidubce.utils import required
from baidubce.http import bce_http_client
from baidubce.bce_client_configuration import BceClientConfiguration
from baidubce.retry.retry_policy import NoRetryPolicy
from baidubce.retry.retry_policy import BackOffRetryPolicy
import imp

imp.reload(sys)
if compat.PY2:
    sys.setdefaultencoding('utf8')

cov = coverage.coverage()
cov.start()

http_request = None


class MockHttpResponse(object):
    """
    mock http response
    """
    def __init__(self, status, content=None, header_list=None):
        """
        constructor
        :param status:
        :param content:
        :param header_list:
        :return:
        """
        self.status = status
        self.content = content
        self.header_list = header_list
        self.reason = "Mock"

    def read(self):
        """
        mock read
        :return:
        """
        return self.content

    def getheaders(self):
        """
        mock getheaders
        :return:
        """
        return self.header_list

    def close(self):
        """
        mock close
        :return:
        """
        pass


class MockHttpConnection(object):
    """
    mock http connection
    """
    def __init__(self):
        """
        constructor
        :return:
        """
        self.header = {}
        self.content = ""
        self.send_called = 0
        self.putrequest_called = 0
        self.putheader_called = 0
        self.endheaders_called = 0
        self.getresponse_called = 0
        self.close_called = 0

    def putrequest(self, method, uri, skip_host, skip_accept_encoding):
        """
        mock putrequest
        :param method:
        :param uri:
        :param skip_host:
        :param skip_accept_encoding:
        :return:
        """
        self.putrequest_called += 1

    def putheader(self, k, v):
        """
        mock putheader
        :param k:
        :param v:
        :return:
        """
        self.putheader_called += 1
        self.header[k] = v

    def endheaders(self):
        """
        mock endheaders
        :return:
        """
        self.endheaders_called += 1

    def getresponse(self):
        """
        mock getresponse
        :return:
        """
        self.getresponse_called += 1
        return None

    def send(self, buf):
        """
        mock send
        :param buf:
        :return:
        """
        self.content += buf
        self.send_called += 1

    def close(self):
        """
        mock close
        :return:
        """
        self.close_called += 1


class MockInputStream(object):
    """
    mock input stream
    """
    def __init__(self, content):
        """
        constructor
        :param content:
        :return:
        """
        self.content = content
        self.counter = 0

    def read(self, size):
        """
        mock read
        :param size:
        :return:
        """
        if self.counter >= len(self.content):
            return ""
        else:
            ret = self.content[self.counter:self.counter + size]
            self.counter += size
            return ret

    def close(self):
        """
        mock close
        :return:
        """
        pass


class MockSigner(object):
    """
    mock sign
    """
    def sign(self, protocol, host, port, http_method, path, headers, params, body):
        """
        mock sign function
        :param credentials:
        :param method:
        :param path:
        :param headers:
        :param params:
        :return:
        """
        return "Mocked"


def mock_get_connection(protocol, host, port, timeout):
    """
    mock get_connection
    :param protocol:
    :param endpoint:
    :param timeout:
    :return:
    """
    return MockHttpConnection()


def mock_send_http_request_wrapper(throw, header_list):
    """
    factory function of mock send_http_request
    :param throw:
    :param header_list:
    :return:
    """
    def mock_send_http_request(conn, method, uri, headers, body, send_buf_size):
        """
        mock send_http_request
        :param conn:
        :param method:
        :param uri:
        :param headers:
        :param body:
        :param send_buf_size:
        :return:
        """
        if throw:
            raise socket.error
        else:
            return MockHttpResponse(200, header_list=header_list)
    return mock_send_http_request


def mock_handler_function_wrapper(ret):
    """
    factory function of mock handler
    :param ret:
    :return:
    """
    def mock_handler_function(http_response, response):
        """
        mock handler
        :param http_response:
        :param response:
        :return:
        """
        return ret
    return mock_handler_function


def mock_sign_function(credentials, method, path, headers, params):
    """
    mock sign function
    :param credentials:
    :param method:
    :param path:
    :param headers:
    :param params:
    :return:
    """
    return "Mocked"


def mock_client_send_request_wrapper(throw, status_code):
    """
    factory function of mock send_request
    :param throw:
    :param status_code:
    :return:
    """
    def mock_send_request(http_method, bucket_name=None, key=None,
                          body=None, headers=None, params=None,
                          config=None, body_parser=None):
        """
        mock send_request
        :param http_method:
        :param bucket_name:
        :param key:
        :param body:
        :param headers:
        :param params:
        :param config:
        :param body_parser:
        :return:
        """
        if throw:
            e = BceServerError("error", status_code=status_code)
            raise BceHttpClientError("error", e)
        else:
            pass
    return mock_send_request


class TestClient(unittest.TestCase):
    """TestClient"""
    BUCKET = "test-bucket%d" % os.getpid()
    KEY = "test_object%d" % os.getpid()
    FILENAME = "temp_file%d" % os.getpid()

    def setUp(self):
        """Start test"""
        self.bos = bos_client.BosClient(bos_test_config.config)
        if not self.bos.does_bucket_exist(self.BUCKET):
            self.bos.create_bucket(self.BUCKET)

    def tearDown(self):
        """Finish test"""
        # delete all objects on test bucket
        response = self.bos.list_all_objects(self.BUCKET)
        for obj in response:
            self.bos.delete_object(self.BUCKET, obj.key)
        # delete test bucket
        self.bos.delete_bucket(self.BUCKET)
        # delete locale file for testing
        if os.path.isfile(self.FILENAME):
            os.remove(self.FILENAME)

    def check_headers(self, response, headers_list=None):
        """check headers"""
        ordinary_headers_list = ['content_length',
                                'bce_debug_id',
                                'date',
                                'bce_request_id',
                                'server']

        for item in ordinary_headers_list:
            self.assertTrue(hasattr(response.metadata, item))

        if isinstance(headers_list, list):
            for item in headers_list:
                self.assertTrue(hasattr(response.metadata, item))

    def get_file(self, size):
        """create a file with size is size(MB)"""
        file = open(self.FILENAME, "w")
        file.seek(1024 * 1024 * size)
        file.write('\x00')
        file.close()


class TestDoesBucketExist(TestClient):
    """test does bucket exist"""
    def test_does_bucket_exist(self):
        """test does bucket exist function"""
        old_func = self.bos._send_request
        # test success
        self.bos._send_request = mock_client_send_request_wrapper(False, None)
        self.assertTrue(self.bos.does_bucket_exist("asdf"))
        # test forbidden
        self.bos._send_request = mock_client_send_request_wrapper(True, http.client.FORBIDDEN)
        self.assertTrue(self.bos.does_bucket_exist("asdf"))
        # test not found
        self.bos._send_request = mock_client_send_request_wrapper(True, http.client.NOT_FOUND)
        self.assertFalse(self.bos.does_bucket_exist("asdf"))
        # test others
        self.bos._send_request = mock_client_send_request_wrapper(True, http.client.NO_CONTENT)
        self.assertRaises(BceHttpClientError, self.bos.does_bucket_exist, "asdf")
        self.bos._send_request = old_func


class TestGetObjectMetaData(TestClient):
    """test get_object_meta_data function"""
    def test_get_object_meta_data(self):
        """test get_object_meta_data function normally"""
        options = dict()
        options["private"] = "This is private."
        err = None
        try:
            self.bos.put_object_from_string(self.BUCKET,
                                            self.KEY,
                                            "This is a string.",
                                            user_metadata=options)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)

        err = None
        try:
            response = self.bos.get_object_meta_data(self.BUCKET, self.KEY)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
        self.check_headers(response)
        self.assertEqual(response.metadata.etag, '13562b471182311b6eea8d241103e8f0')
        self.assertEqual(int(response.metadata.content_length), len("This is a string."))
        self.assertEqual(response.metadata.x_amz_meta_private, "This is private.")


class TestGetObject(TestClient):
    """test get_object function"""
    def test_get_object(self):
        """test get_object function normally"""
        err = None
        try:
            response = self.bos.put_object_from_string(self.BUCKET,
                                                       self.KEY,
                                                       "This is a string.",
                                                       user_metadata={"private": "private"})
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
        self.check_headers(response)

        err = None
        try:
            response = self.bos.get_object(self.BUCKET, self.KEY)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)

        self.check_headers(response)
        self.assertEqual(response.metadata.etag, '13562b471182311b6eea8d241103e8f0')
        self.assertDictEqual(response.metadata.user_metadata, {u"private":u"private"})
        data = BytesIO(response.data.read())
        response.data.close()

    def test_get_object_as_string(self):
        """test get_object_as_string function normally"""
        err = None
        try:
            response = self.bos.put_object_from_string(self.BUCKET,
                                                       self.KEY,
                                                       "This is a string.")
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
        self.check_headers(response)

        err = None
        try:
            response = self.bos.get_object_as_string(self.BUCKET, self.KEY)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)

        self.assertEqual(response, b"This is a string.")

    def test_get_object_to_file(self):
        """test get_object_to_file function normally"""
        err = None
        try:
            response = self.bos.put_object_from_string(self.BUCKET, self.KEY, "This is a string.")
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
        self.check_headers(response)

        err = None
        try:
            response = self.bos.get_object_to_file(self.BUCKET, self.KEY, b"Filename")
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
            os.remove("Filename")

        self.check_headers(response)
        self.assertEqual(response.metadata.etag, '13562b471182311b6eea8d241103e8f0')

    def test_get_object_to_file_with_range(self):
        """test get_object_to_file function with range"""
        err = None
        try:
            response = self.bos.put_object_from_string(self.BUCKET, self.KEY, "a" * 1000)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
        self.check_headers(response)

        fp = open(self.FILENAME, "w")
        fp.write('a' * 100)
        fp.close()

        fp = open(self.FILENAME, "rb")
        md5 = utils.get_md5_from_fp(fp)
        fp.close()
        os.remove(self.FILENAME)

        err = None
        try:
            response = self.bos.get_object_to_file(self.BUCKET,
                                                   self.KEY,
                                                   self.FILENAME,
                                                   range=(0, 99))
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNone(err)
        self.check_headers(response)
        self.assertEqual(response.metadata.content_range, 'bytes 0-99/1000')

        fp = open(self.FILENAME, "rb")
        get_md5 = utils.get_md5_from_fp(fp)
        fp.close()
        self.assertEqual(get_md5, md5)


class TestListBuckets(TestClient):
    """test list_bucket function"""
    def test_list_bucket(self):
        """test list_bucket function normally"""

        if self.bos.does_bucket_exist("aaaaaaxzr1"):
            self.bos.delete_bucket("aaaaaaxzr1")
        if self.bos.does_bucket_exist("aaaaaaxzr2"):
            self.bos.delete_bucket("aaaaaaxzr2")

        time1 = utils.get_canonical_time()
        self.bos.create_bucket("aaaaaaxzr1")

        time2 = utils.get_canonical_time()
        self.bos.create_bucket("aaaaaaxzr2")

        response = self.bos.list_buckets()
        self.check_headers(response)

        self.assertEqual(response.owner.id, bos_test_config.OWNER_ID)
        self.assertEqual(response.owner.display_name, bos_test_config.DISPLAY_NAME)
        for bucket in response.buckets:
            if bucket.name == "aaaaaaxzr1":
                self.assertEqual(
                    compat.convert_to_bytes(bucket.creation_date)[0:19], 
                    compat.convert_to_bytes(time1)[0:19])
            elif bucket.name == "aaaaaaxzr2":
                self.assertEqual(
                    compat.convert_to_bytes(bucket.creation_date)[0:19], 
                    compat.convert_to_bytes(time2)[0:19])
        self.bos.delete_bucket("aaaaaaxzr1")
        self.bos.delete_bucket("aaaaaaxzr2")


class TestListObjects(TestClient):
    """test list_objects function"""
    def test_list_objects(self):
        """test list_objects function normally"""
        for i in range(0, 10):
            self.bos.put_object_from_string(
                self.BUCKET, 
                "test_object_%s" % compat.convert_to_bytes(random.random()),
                "This is a string.")

        response = self.bos.list_objects(self.BUCKET, prefix="", delimiter="")
        self.check_headers(response)
        self.assertEqual(response.is_truncated, 'false')
        self.assertEqual(response.max_keys, '1000')
        self.assertEqual(response.name, self.BUCKET)
        self.assertEqual(response.prefix, None)

        # TODO: test prefix and marker with Chineses
        for i in range(0, 5):
            key1 = "test_%s" % compat.convert_to_string(random.random())
            key2 = "testfile_%s" % compat.convert_to_string(random.random())
            self.bos.put_object_from_string(
                self.BUCKET, 
                key1,
                "This is a string.")
            self.bos.put_object_from_string(
                self.BUCKET, 
                key2,
                "This is a string.")

        prefix = 'test'
        marker = 'testfile'
        response = self.bos.list_objects(self.BUCKET, prefix = prefix)
        self.check_headers(response)
        self.assertEqual(len(response.contents), 20)
        self.assertEqual(response.prefix, prefix)
        response = self.bos.list_objects(self.BUCKET, marker = marker)
        self.check_headers(response)
        self.assertEqual(len(response.contents), 5)
        self.assertEqual(response.marker, marker)


    def test_list_object_with_max_keys(self):
        """test list_objects function with max_keys"""
        for i in range(0, 9):
            self.bos.put_object_from_string(
                self.BUCKET, 
                "test_object_%s" % compat.convert_to_bytes(random.random()),
                "This is a string.")

            response = self.bos.list_objects(self.BUCKET)

            all_list = list()
            tmp_list = list()

            for item in response.contents:
                all_list.append(item.key)

            response = self.bos.list_objects(self.BUCKET, max_keys=4)
            for item in response.contents:
                tmp_list.append(item.key)

            response = self.bos.list_objects(self.BUCKET, max_keys=5, marker=tmp_list[-1])
            for item in response.contents:
                tmp_list.append(item.key)

            self.assertListEqual(all_list, tmp_list)

    def test_list_all_object(self):
        """test list_all_objects function"""
        object_keys = []
        for i in range(0, 9):
            object_key = "test_object_%s" % random.random()
            self.bos.put_object_from_string(self.BUCKET, object_key,
                                            "This is a string.")
            object_keys.append(object_key)
        for item in self.bos.list_all_objects(self.BUCKET):
            self.assertTrue(item.key in object_keys)


class TestPutObject(TestClient):
    """test put_object"""
    def test_put_object_from_string(self):
        """test put_object_from_string function normally"""
        response = self.bos.put_object_from_string(self.BUCKET, self.KEY, "Hello World")
        self.check_headers(response)
        response = self.bos.put_object_from_string(self.BUCKET, self.KEY, u"Hello World")
        self.check_headers(response)
        response = self.bos.put_object_from_string(self.BUCKET,
                                                   self.KEY,
                                                   u"Hello World")
        self.check_headers(response)
        err = None
        try:
            response = self.bos.put_object_from_string(self.BUCKET, self.KEY, 123)
        except TypeError as e:
            err = e
        finally:
            self.assertIsNotNone(err)

    def test_put_object_user_headers(self):
        """test put_object_from_string user headers"""
        user_headers = {"Cache-Control":"private", 
                        "Content-Disposition":"attachment; filename=\"abc.txt\"", 
                        "Expires":"123456"}
        response = self.bos.put_object_from_string(bucket=self.BUCKET,
                                                   key="test_put_user_headers",
                                                   data='Hello World',
                                                   user_headers=user_headers)
        self.check_headers(response)

        response = self.bos.get_object_meta_data(bucket_name=self.BUCKET, 
                                                 key='test_put_user_headers')
        self.assertEqual(response.metadata.expires, "123456")
        self.assertEqual(response.metadata.content_disposition, 'attachment; filename="abc.txt"')
        self.assertEqual(response.metadata.cache_control, 'private')

    def test_put_object_from_file(self):
        """test put_object_from_file function normally"""
        self.get_file(20)
        response = self.bos.put_object_from_file(self.BUCKET, self.KEY, self.FILENAME)
        self.check_headers(response, ["etag"])

    def test_put_object_from_file_user_headers(self):
        """test put_object_from_file user headers"""

        user_headers = {"Cache-Control":"private", 
                        "Content-Disposition":"attachment; filename=\"abc.txt\"", 
                        "Expires":"123456"}

        self.get_file(5)
        response = self.bos.put_object_from_file(bucket=self.BUCKET,
                                                 key="test_put_file_user_headers",
                                                 file_name=self.FILENAME,
                                                 user_headers=user_headers)
        self.check_headers(response)

        response = self.bos.get_object_meta_data(bucket_name=self.BUCKET, 
                                                 key='test_put_file_user_headers')
        self.assertEqual(response.metadata.expires, "123456")
        self.assertEqual(response.metadata.content_disposition, 'attachment; filename="abc.txt"')
        self.assertEqual(response.metadata.cache_control, 'private')


    def test_put_object_from_file_user_metadata(self):
        """test put_object_from_file user metadata"""

        user_metadata = {'company': 'baidu', 'work': 'develop'}
        object_key = 'testfile'
        self.get_file(5)
        response = self.bos.put_object_from_file(bucket=self.BUCKET,
                                                 key=object_key,
                                                 file_name=self.FILENAME,
                                                 user_metadata = user_metadata)

        response = self.bos.get_object_meta_data(bucket_name=self.BUCKET, 
                                                 key=object_key)
        self.assertEqual(response.metadata.x_amz_meta_company, 'baidu')
        self.assertEqual(response.metadata.x_amz_meta_work, 'develop')

    def test_put_object_exceptions(self):
        """test of exceptions in put object"""
        # key is None
        err = None
        try:
            self.bos.put_object(self.BUCKET, None, None, 100, None)
        except ValueError as e:
            err = e
        finally:
            self.assertIsNotNone(err)
        # too long
        err = None
        try:
            self.bos.put_object(self.BUCKET, self.KEY, None, 6 * 1024 * 1024 * 1024, None)
        except ValueError as e:
            err = e
        finally:
            self.assertIsNotNone(err)


class TestAuthorization(unittest.TestCase):
    """TestAuthorization"""
    def test_get_sign(self):
        """test_get_sign"""
        method = "PUT"
        uri = "/bucket/object1"
        params = {
            "A": None,
            "b": "",
            "C": "d"
        }

        headers = {
            "Host": "192.168.0.1",
            "abc": "123",
            "x-bce-meta-key1": "ABC"
        }

        endpoint = endpoints_provider.SingleEndpoint("http", 
                "192.168.0.1", 
                "8080", 
                "192.168.0.1:8080")
        signer = S3SigV4Auth(bce_credentials.BceCredentials("my_ak", "my_sk"), "s3", "beijing")
        auth = signer.sign(endpoint.protocol, 
                           endpoint.host, 
                           endpoint.port,
                           method,
                           uri,
                           headers,
                           params,
                           None)
        # self.assertEqual('bce-auth-v1/bb37e6dfffc948a59eb5ddd254263809/2014-06-13T05:57:36Z/'
        #                  '1800//a20b4334ce9ba6fbddcb4064cd62a4d57ab2d78b44160b5d6ea9321beb8ca8cd',
        #                 bce_v1_signer.sign(bos_test_config.config.credentials,
        #                                    http_methods.PUT,
        #                                    uri,
        #                                    headers,
        #                                    params,
        #                                    1402639056,
        #                                    1800))


class TestUtil(unittest.TestCase):
    """TestUtil"""
    def test_get_timestamp(self):
        """test_get_timestamp"""
        self.assertEqual("1970-01-01T00:00:01Z", utils.get_canonical_time(1))
        if compat.PY3:
            self.assertRegex(compat.convert_to_string(utils.get_canonical_time()),
                                 "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
        else:
            self.assertRegexpMatches(compat.convert_to_string(utils.get_canonical_time()),
                                 "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")

    def test_is_ip(self):
        """test_is_ip"""
        self.assertEqual(True, utils.is_ip("192.168.0.1"))
        self.assertEqual(True, utils.is_ip("localhost"))
        self.assertEqual(False, utils.is_ip("276.20.22.22"))
        self.assertEqual(False, utils.is_ip("123"))
        self.assertEqual(False, utils.is_ip("-1.33.22.11"))
        self.assertEqual(False, utils.is_ip("aaabbbccc"))
        self.assertEqual(False, utils.is_ip(123))

    def test_convert_to_standard_string(self):
        """test_convert_utf8"""
        self.assertEqual(b"aaa", utils.convert_to_standard_string(u"aaa"))
        self.assertEqual("北京".encode("utf-8"), utils.convert_to_standard_string("北京"))

    def test_convert_header2map(self):
        """test_convert_header2map"""
        tmp_map = {"region": "beijing", "sex": "female", "age": 21}
        tmp_list = (("region", "beijing"), ("sex", "female"), ("age", 21))
        self.assertEqual(tmp_map, utils.convert_header2map(tmp_list))

    def test_check_redirect(self):
        """test_check_redirect"""
        tmp_res = http.client.HTTPSConnection("localhost")
        tmp_res.status = 301
        self.assertEqual(True, utils.check_redirect(tmp_res))
        tmp_res.status = 302
        self.assertEqual(True, utils.check_redirect(tmp_res))
        tmp_res.status = 100
        self.assertEqual(False, utils.check_redirect(tmp_res))
        tmp_res.status = "aaa"
        self.assertEqual(False, utils.check_redirect(tmp_res))
        self.assertFalse(utils.check_redirect(123))

    #def test_get_resource(self):
    def test_normalize_string(self):
        """test_normalize_string"""
        self.assertEqual(b"www.baidu.com", utils.normalize_string("www.baidu.com"))
        self.assertEqual(b"www.bai%5E%26%2A.com", utils.normalize_string("www.bai^&*.com"))
        self.assertEqual(b"www.baidu.com", utils.normalize_string("www.baidu.com", True))

    #def test_append_param
    def test_check_bucket_valid(self):
        """test_check_bucket_valid"""
        self.assertEqual(True, utils.check_bucket_valid("test"))
        self.assertEqual(False, utils.check_bucket_valid(""))
        self.assertEqual(False, utils.check_bucket_valid("as&*"))
        self.assertEqual(False, utils.check_bucket_valid(" asfd"))
        self.assertFalse(utils.check_bucket_valid("asdf-"))
        self.assertFalse(utils.check_bucket_valid("asdf_"))

    def test_safe_get_element(self):
        """test safe_get_element"""
        self.assertEqual(utils.safe_get_element("asdf", {}), "")
        self.assertEqual(utils.safe_get_element("asdf", {"asdf":1}), 1)

    def test_get_normalized_char_list(self):
        """test _get_normalized_char_list"""
        chars = ['%00', '%01', '%02', '%03', '%04', '%05', '%06', '%07', '%08', '%09', '%0A',
                 '%0B', '%0C', '%0D', '%0E', '%0F', '%10', '%11', '%12', '%13', '%14', '%15',
                 '%16', '%17', '%18', '%19', '%1A', '%1B', '%1C', '%1D', '%1E', '%1F', '%20',
                 '%21', '%22', '%23', '%24', '%25', '%26', '%27', '%28', '%29', '%2A', '%2B',
                 '%2C', '-', '.', '%2F', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '%3A',
                 '%3B', '%3C', '%3D', '%3E', '%3F', '%40', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
                 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
                 'X', 'Y', 'Z', '%5B', '%5C', '%5D', '%5E', '_', '%60', 'a', 'b', 'c', 'd', 'e',
                 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
                 'v', 'w', 'x', 'y', 'z', '%7B', '%7C', '%7D', '~', '%7F', '%80', '%81', '%82',
                 '%83', '%84', '%85', '%86', '%87', '%88', '%89', '%8A', '%8B', '%8C', '%8D',
                 '%8E', '%8F', '%90', '%91', '%92', '%93', '%94', '%95', '%96', '%97', '%98',
                 '%99', '%9A', '%9B', '%9C', '%9D', '%9E', '%9F', '%A0', '%A1', '%A2', '%A3',
                 '%A4', '%A5', '%A6', '%A7', '%A8', '%A9', '%AA', '%AB', '%AC', '%AD', '%AE',
                 '%AF', '%B0', '%B1', '%B2', '%B3', '%B4', '%B5', '%B6', '%B7', '%B8', '%B9',
                 '%BA', '%BB', '%BC', '%BD', '%BE', '%BF', '%C0', '%C1', '%C2', '%C3', '%C4',
                 '%C5', '%C6', '%C7', '%C8', '%C9', '%CA', '%CB', '%CC', '%CD', '%CE', '%CF',
                 '%D0', '%D1', '%D2', '%D3', '%D4', '%D5', '%D6', '%D7', '%D8', '%D9', '%DA',
                 '%DB', '%DC', '%DD', '%DE', '%DF', '%E0', '%E1', '%E2', '%E3', '%E4', '%E5',
                 '%E6', '%E7', '%E8', '%E9', '%EA', '%EB', '%EC', '%ED', '%EE', '%EF', '%F0',
                 '%F1', '%F2', '%F3', '%F4', '%F5', '%F6', '%F7', '%F8', '%F9', '%FA', '%FB',
                 '%FC', '%FD', '%FE', '%FF']
        self.assertListEqual([compat.convert_to_bytes(k) for k in chars],
            utils._get_normalized_char_list())


class TestHandler(TestClient):
    """test abort handler"""
    def test_parse_error(self):
        """test abort parse_error function in handler"""
        # test normal 2xx
        http_response = MockHttpResponse(status=208)
        self.assertFalse(handler.parse_error(http_response, None))

        # test abnormal 1xx
        http_response = MockHttpResponse(status=108)
        err = None
        try:
            handler.parse_error(http_response, None)
        except BceClientError as e:
            err = e
        finally:
            self.assertIsNotNone(err)

        # test abnormal 3xx 4xx 5xx with json body
        json_content = {"message": "error",
                        "code": 123,
                        "requestId": 12345}
        http_response = MockHttpResponse(status=508, content=json.dumps(json_content))
        err = None
        try:
            handler.parse_error(http_response, None)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNotNone(err)
            self.assertEqual(compat.convert_to_string(err), "error")
            self.assertEqual(err.code, 123)
            self.assertEqual(err.request_id, 12345)
            self.assertEqual(err.status_code, 508)

        # test abnormal 3xx 4xx 5xx without json body
        http_response = MockHttpResponse(status=508)
        response = BceResponse()
        response.metadata.bce_request_id = 12345
        err = None
        try:
            handler.parse_error(http_response, response)
        except BceServerError as e:
            err = e
        finally:
            self.assertIsNotNone(err)
            self.assertEqual(compat.convert_to_string(err), "Mock")
            self.assertEqual(err.request_id, 12345)
            self.assertEqual(err.status_code, 508)

    def test_parse_json(self):
        """test abort parse_json function in handler"""
        # test has body
        json_content = {"message": "error",
                        "code": 123,
                        "requestId": 12345}
        http_response = MockHttpResponse(status=508, content=json.dumps(json_content))
        response = BceResponse()
        self.assertTrue(handler.parse_json(http_response, response))
        self.assertTrue(hasattr(response, "message"))
        self.assertTrue(hasattr(response, "code"))
        self.assertTrue(hasattr(response, "request_id"))
        # test doesn't have body
        http_response = MockHttpResponse(status=508)
        response = BceResponse()
        old_len = len(response.__dict__)
        self.assertTrue(handler.parse_json(http_response, response))
        self.assertEqual(len(response.__dict__), old_len)


class TestBceHttpClient(TestClient):
    """test abort bce_http_client"""
    def test_parse_host_port(self):
        """test about parse host port"""
        # test default port for http
        endpoint = "1.2.3.4"
        default_protocol = baidubce.protocol.HTTP
        ret_protocol, host, port = utils.parse_host_port(endpoint, default_protocol)
        self.assertEqual(ret_protocol, baidubce.protocol.HTTP)
        self.assertEqual(host, endpoint)
        self.assertEqual(port, default_protocol.default_port)

        # test default port for https
        endpoint = "1.2.3.4"
        default_protocol = baidubce.protocol.HTTPS
        ret_protocol, host, port = utils.parse_host_port(endpoint, default_protocol)
        self.assertEqual(ret_protocol, baidubce.protocol.HTTPS)
        self.assertEqual(host, endpoint)
        self.assertEqual(port, default_protocol.default_port)

        # test specific port
        endpoint = "1.2.3.4:8080"
        default_protocol = baidubce.protocol.HTTP
        ret_protocol, host, port = utils.parse_host_port(endpoint, default_protocol)
        self.assertEqual(ret_protocol, baidubce.protocol.HTTP)
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8080)

        # test value error
        endpoint = "1.2.3.4:abcd"
        default_protocol = baidubce.protocol.HTTP
        self.assertRaises(ValueError, utils.parse_host_port, endpoint, default_protocol)

        # protocol unsupported
        endpoint = "ftp://1.2.3.4"
        default_protocol = baidubce.protocol.HTTP
        self.assertRaises(ValueError, utils.parse_host_port, endpoint, default_protocol)

        # test of endpoint dominates the protocol
        endpoint = "http://1.2.3.4:8080"
        default_protocol = baidubce.protocol.HTTPS
        ret_protocol, host, port = utils.parse_host_port(endpoint, default_protocol)
        self.assertEqual(ret_protocol, baidubce.protocol.HTTP)
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8080)

    def test_get_connection(self):
        """test abort get connection"""

        http_client = bce_http_client.BceHttpClient(None)

        # test unknown protocol
        test_protocol = Expando({'name': 'unknown', 'default_port': 65535})
        host = "1.2.3.4"
        port = 8080
        connection_timeout = 1000
        self.assertRaises(ValueError,
                          http_client._get_connection,
                          test_protocol, host, port, connection_timeout)

        # test http protocol
        test_protocol = protocol.HTTP
        host = "1.2.3.4"
        port = 8080
        connection_timeout = 1000
        conn = http_client._get_connection(test_protocol, host, port, connection_timeout)
        self.assertEqual(conn.host, "1.2.3.4")
        self.assertEqual(conn.port, 8080)
        self.assertEqual(conn.timeout, 1)

        # test https protocol
        test_protocol = protocol.HTTPS
        host = "1.2.3.4"
        port = 8080
        connection_timeout = 1000
        conn = http_client._get_connection(test_protocol, host, port, connection_timeout)

    def test_send_http_request_normal(self):
        """test abort send http request"""
        # test body is None
        http_client = bce_http_client.BceHttpClient(None)
        conn = MockHttpConnection()
        method = http_methods.GET
        uri = "/unknown/unknown"
        headers = {"Content-Length": 15,
                   "Content-Encoding": "utf8",
                   }
        body = None
        send_buf_size = -1

        http_client._send_http_request(conn,
                                           method,
                                           uri,
                                           headers,
                                           body,
                                           send_buf_size)
        self.assertEqual(conn.putrequest_called, 1)
        self.assertEqual(conn.putheader_called, 2)
        self.assertEqual(conn.endheaders_called, 1)
        self.assertEqual(conn.send_called, 0)
        self.assertEqual(conn.content, "")
        self.assertEqual(conn.getresponse_called, 1)

        # test body is string
        conn = MockHttpConnection()
        method = http_methods.GET
        uri = "/unknown/unknown"
        headers = {"Content-Length": 15,
                   "Content-Encoding": "utf8",
                   }
        body = "Test with string"
        send_buf_size = -1
        http_client._send_http_request(conn,
                                           method,
                                           uri,
                                           headers,
                                           body,
                                           send_buf_size)
        self.assertEqual(conn.putrequest_called, 1)
        self.assertEqual(conn.putheader_called, 2)
        self.assertEqual(conn.endheaders_called, 1)
        self.assertEqual(conn.send_called, 1)
        self.assertEqual(conn.content, body)
        self.assertEqual(conn.getresponse_called, 1)

        # test body is input stream
        conn = MockHttpConnection()
        method = http_methods.GET
        uri = "/unknown/unknown"
        headers = {"Content-Length": 16,
                   "Content-Encoding": "utf8",
                   }
        body = MockInputStream("Test with string")
        send_buf_size = 5
        http_client._send_http_request(conn,
                                           method,
                                           uri,
                                           headers,
                                           body,
                                           send_buf_size)
        self.assertEqual(conn.putrequest_called, 1)
        self.assertEqual(conn.putheader_called, 2)
        self.assertEqual(conn.endheaders_called, 1)
        self.assertEqual(conn.send_called, len("Test with string") // 5 + 1)
        self.assertEqual(conn.content, "Test with string")
        self.assertEqual(conn.getresponse_called, 1)

    def test_send_http_request_exception(self):
        """test abort send http request"""
        # test body is not sufficient
        http_client = bce_http_client.BceHttpClient(None)
        conn = MockHttpConnection()
        method = http_methods.GET
        uri = "/unknown/unknown"
        headers = {"Content-Length": 100,
                   "Content-Encoding": "utf8",
                   }
        body = MockInputStream("Test with string")
        send_buf_size = 5
        self.assertRaises(BceClientError,
                          http_client._send_http_request,
                          conn,
                          method,
                          uri,
                          headers,
                          body,
                          send_buf_size)
        self.assertEqual(conn.putrequest_called, 1)
        self.assertEqual(conn.putheader_called, 2)
        self.assertEqual(conn.endheaders_called, 1)
        self.assertEqual(conn.send_called, len("Test with string") // 5 + 1)

    def test_send_request(self):
        """test abort send request"""
        signer = MockSigner()
        http_client = bce_http_client.BceHttpClient(signer)
        old_get_connection = http_client._get_connection
        old_send_http_request = http_client._send_http_request
        http_client._get_connection = mock_get_connection
        handlers = [mock_handler_function_wrapper(True), mock_handler_function_wrapper(False)]
        uri = "/unknown/unknown"
        params = {"test": "test"}
        # test with socket exception
        body = None
        headers = None
        http_client._send_http_request = mock_send_http_request_wrapper(True, None)
        bos_test_config.config.retry_policy = BackOffRetryPolicy()
        self.assertRaises(BceHttpClientError,
                          http_client.send_request,
                          bos_test_config.config,
                          handlers,
                          http_methods.GET,
                          uri,
                          body,
                          headers,
                          params)

        # test with value exception
        bos_test_config.config.retry_policy = NoRetryPolicy()
        body = 1
        headers = {"x-bce-date": "12345"}
        http_client._send_http_request = mock_send_http_request_wrapper(False, None)
        self.assertRaises(ValueError,
                          http_client.send_request,
                          bos_test_config.config,
                          handlers,
                          http_methods.GET,
                          uri,
                          body,
                          headers,
                          params)

        # test others
        body = u"abcde"
        headers = {"x-bce-date": "12345"}
        params = None
        http_client._send_http_request = mock_send_http_request_wrapper(False, {"err": "err"})
        response = http_client.send_request(bos_test_config.config,
                                                handlers,
                                                http_methods.GET,
                                                uri,
                                                body,
                                                headers,
                                                params)
        self.assertEqual(response.metadata.err, "err")
        http_client._get_connection = old_get_connection
        http_client._send_http_request = old_send_http_request


class TestBceClientConfiguration(TestClient):
    """test BceClientConfiguration"""
    def test_init(self):
        """
        test init
        """
        file_name = "endpoints.test"
        fp = open(file_name, "w")
        fp.write('192.168.0.1:8080\n')
        fp.write('192.168.0.2:8080')
        fp.close()

        """test BceClientConfiguration"""
        conf = BceClientConfiguration(1, file_name, 3, 4, 5, 6, 7)
        self.assertEqual(conf.credentials, 1)
        self.assertEqual(conf.region, 3)
        self.assertEqual(conf.service_name, 4)
        self.assertEqual(conf.connection_timeout_in_mills, 5)
        self.assertEqual(conf.send_buf_size, 6)
        self.assertEqual(conf.recv_buf_size, 7)

        os.remove(file_name)


class TestGetRangeHeaderDict(TestClient):
    """test _get_range_header_dict"""
    def test_get_range_header_dict(self):
        """test _get_range_header_dict"""
        self.assertIsNone(bos_client.BosClient._get_range_header_dict(None))
        self.assertDictEqual(bos_client.BosClient._get_range_header_dict((0, 99)),
                          {"Range":'bytes=0-99'})
        err = None
        try:
            bos_client.BosClient._get_range_header_dict(123)
        except TypeError as e:
            err = e
        finally:
            self.assertIsNotNone(err)
        err = None
        try:
            bos_client.BosClient._get_range_header_dict([1, 2, 3])
        except ValueError as e:
            err = e
        finally:
            self.assertIsNotNone(err)


class MyClass(object):
    """
    wrapper class
    """
    @required(a=int, b=list, c=(bytes, str))
    def my_func(self, a, b, c, d=None):
        """
        sample function to use required
        :param a:
        :param b:
        :param c:
        :param d:
        :return:
        """
        return True


class TestDecorator(TestClient):
    """test required decorator"""
    def positive_test(self):
        """
        test of positive cases
        :return:
        """
        self.assertTrue(MyClass().my_func(1, [], "a"))
        self.assertTrue(MyClass().my_func(1, [], u"a", 123))
        self.assertTrue(MyClass().my_func(1, [], "a", "abc"))
        self.assertTrue(MyClass().my_func(1, [], u"a", None))
        self.assertTrue(MyClass().my_func(a=1, b=[], c="a"))
        self.assertTrue(MyClass().my_func(a=1, b=[], c=u"a", d=123))
        self.assertTrue(MyClass().my_func(a=1, b=[], c="a", d="abc"))
        self.assertTrue(MyClass().my_func(a=1, b=[], c=u"a", d=None))

    def negative_test_value(self):
        """
        test of negative cases
        :return:
        """
        self.assertRaises(ValueError, MyClass().my_func, None, [], "a")
        self.assertRaises(ValueError, MyClass().my_func, 1, None, "a")
        self.assertRaises(ValueError, MyClass().my_func, 1, [], None)
        self.assertRaises(ValueError, MyClass().my_func, a=None, b=[], c="a")
        self.assertRaises(ValueError, MyClass().my_func, a=1, b=None, c="a")
        self.assertRaises(ValueError, MyClass().my_func, a=1, b=[], c=None)

    def negative_test_type(self):
        """
        test of negative cases
        :return:
        """
        self.assertRaises(TypeError, MyClass().my_func, "a", [], "a")
        self.assertRaises(TypeError, MyClass().my_func, 1, 1, "a")
        self.assertRaises(TypeError, MyClass().my_func, 1, [], [])
        self.assertRaises(TypeError, MyClass().my_func, a="a", b=[], c="a")
        self.assertRaises(TypeError, MyClass().my_func, a=1, b=1, c="a")
        self.assertRaises(TypeError, MyClass().my_func, a=1, b=[], c=[])


def run_test():
    """start run test"""
    runner = unittest.TextTestRunner()
    runner.run(unittest.makeSuite(TestClient))
    runner.run(unittest.makeSuite(TestGetObjectMetaData))
    runner.run(unittest.makeSuite(TestGetObject))
    runner.run(unittest.makeSuite(TestListBuckets))
    runner.run(unittest.makeSuite(TestListObjects))
    runner.run(unittest.makeSuite(TestPutObject))
    runner.run(unittest.makeSuite(TestAuthorization))
    runner.run(unittest.makeSuite(TestUtil))
    runner.run(unittest.makeSuite(TestHandler))
    runner.run(unittest.makeSuite(TestBceHttpClient))
    runner.run(unittest.makeSuite(TestDoesBucketExist))
    runner.run(unittest.makeSuite(TestBceClientConfiguration))
    runner.run(unittest.makeSuite(TestGetRangeHeaderDict))
    runner.run(unittest.makeSuite(TestDecorator))

run_test()
cov.stop()
cov.save()
cov.html_report()

