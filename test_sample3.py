#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import time
import threading, multiprocessing
import logging
import os
import sys

from io import BytesIO
 
from baidubce.bce_client_configuration import BceClientConfiguration
from baidubce.auth.bce_credentials import BceCredentials
from baidubce.services.bos.bos_client import BosClient

def test_basic_api(bos_client):
    bucket_name = 'pxython-sdk3'
    object_key = 'test.go'
    file_name = 'test_sample3.py'

    #create bucket
    print("create bucket")
    ret = bos_client.create_bucket(bucket_name)

    print("list bucekts")
    ret = bos_client.list_buckets()
    for bucket in ret.buckets:
       print(bucket.name)

    print("put object")
    ret = bos_client.put_object_from_file(bucket_name, object_key, file_name)

    print("list objects")
    ret = bos_client.list_objects(bucket_name)
    for obj in ret.contents:
        print(obj.key)

    print("put object")
    ret = bos_client.put_object_from_file(bucket_name, "xxx1", file_name)

    print("list all objects")
    ret = bos_client.list_all_objects(bucket_name)
    for obj in ret:
        print(obj.key)

    print("get object")
    ret = bos_client.get_object(bucket_name, object_key)
    print(ret)

    print("delete object")
    ret = bos_client.delete_object(bucket_name, object_key)
    ret = bos_client.delete_object(bucket_name, "xxx1")

    print("delete bucket 1")
    ret = bos_client.delete_bucket(bucket_name)

    print("delete bucket 2")
    ret = bos_client.does_bucket_exist("python-sdk2")
 
def download_data(items, cpu_id, start, end, bos_client, bucket_name):
    t0 = time.time()
    for i in range(start, end):
        ret = bos_client.get_object(bucket_name, items[i])
        data = BytesIO(ret.data.read())
        ret.data.close()
    print("process %d \t finish \t %d ~%d, \t use time: %f"%(cpu_id, start, end, time.time() - t0))
 
def read_data(bos_client, bucket_name, filelist, cpu_num):
    """read_data
    """
    fl = [item.strip() for item in open(filelist).readlines()]
    items = [ (file_item) for file_item in fl]

    objects_num = len(items)
    if objects_num == 0:
        raise ValueError("the number of objects is 0")

    each_cpu_process_num = int(objects_num/cpu_num)

    process = []
    for i in range(cpu_num):
        t = multiprocessing.Process(target=download_data, 
                args=(items, i, i*each_cpu_process_num, (i+1)*each_cpu_process_num, bos_client,
                    bucket_name))
        process.append(t)

    t0 = time.time()
    for t in process:
        t.start()

    for t in process:
        t.join()

    print (cpu_num, ' process read ', time.time() - t0, ' file_list: ', len(fl))

def test_multi_prcesses_download(bos_client, filelist, bucket_name, cpu_num):
    #logger = logging.getLogger('baidubce.http.bce_http_client')
    #logger1 = logging.getLogger('baidubce.http.endpoints_provider')
    #fh = logging.FileHandler("sample.log")
    #fh = logging.StreamHandler()
    #fh.setLevel(logging.DEBUG)
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    #fh.setFormatter(formatter)
    #logger.setLevel(logging.DEBUG)
    #logger.addHandler(fh)
    #logger1.setLevel(logging.DEBUG)
    #logger1.addHandler(fh)

    read_data(bos_client, bucket_name, filelist, cpu_num)

if __name__ == '__main__':
    """
    HOW TO USE:
    python test_sample.py ${file_list} ${bucket_name} ${process_num}
    """

    filelist = '4K'
    if len(sys.argv) > 1:
        filelist = sys.argv[1].strip()

    bucket_name = "boto-bucket"
    if len(sys.argv) > 2:
        bucket_name = sys.argv[2].strip()

    cpu_num = multiprocessing.cpu_count()
    if len(sys.argv) > 3:
        cpu_num = int(sys.argv[3].strip())

    if cpu_num <= 0:
        raise ValueError("cpu num less than 1")

    config = BceClientConfiguration(credentials=BceCredentials('4THNDAQ8QB988ENO630I', 'vP3L629Oe7BruQYJdp28bn9gY4U7dwXROvLIQBEa'))
    bos_client = BosClient(config)

    test_multi_prcesses_download(bos_client, filelist, bucket_name, cpu_num)
    #test_basic_api(bos_client)
