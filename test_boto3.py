#!/usr/bin/env python
# -*- coding: utf-8 -*-
import random
import time
import threading, multiprocessing
import logging
import os
import sys

from io import BytesIO
import boto3
 
def download_data(items, cpu_id, start, end, bucket):
    data = BytesIO()
    t0 = time.time()
    for i in range(start, end):
        ret = bucket.Object(items[i]).download_fileobj(data)
    print("process %d \t finish \t %d ~%d, \t use time: %f"%(cpu_id, start, end, time.time() - t0))
 
def read_data(bucket, filelist, cpu_num):
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
                args=(items, i, i*each_cpu_process_num, (i+1)*each_cpu_process_num,
                    bucket))
        process.append(t)

    t0 = time.time()
    for t in process:
        t.start()

    for t in process:
        t.join()

    print (cpu_num, ' process read ', time.time() - t0, ' file_list: ', len(fl))

def test_multi_prcesses_download(s3, filelist, bucket_name, cpu_num):
    bucket = s3.Bucket(bucket_name)
    read_data(bucket, filelist, cpu_num)

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

    s3 = boto3.resource('s3', endpoint_url='http://192.168.0.1:8080')
    test_multi_prcesses_download(s3, filelist, bucket_name, cpu_num)
