[TOC]

# 1. 概述

ABC Storage 高性能版 Python SDK 为用户提供了高效的对象存储访问接口， 并且支持负载均衡和后端容错功能。 

本文档主要介绍ABC Storage 提供的高性能版 Python SDK 的安装和使用方法。

# 2. 安装SDK

## 2.1. 运行环境

Python SDK工具包支持在Python 2.7、python3.x环境下运行。

## 2.2. 安装 

1. 进入SDK载目录

2. 安装SDK之前，需要先执行命令 "pip install future" 安装future依赖。

3. 执行以下命令安装SDK包：
```
python setup.py install
```

## 2.3. SDK目录结构

```
baidubce
       ├── auth                            //公共权限目录
       ├── http                            //Http请求模块
       ├── services                        //服务公共目录
       │     └── bos                       //百度对象存储目录
       │           ├──bos_client.py        //百度对象存储客户端入口类
       │           └──parsers.py           //HTTP reponse处理函数
       ├── bce_base_client.py              //客户端入口类的基类
       ├── bce_client_configuration.py     //HttpClient 配置类
       ├── bce_response.py                 //客户端的请求类
       ├── exception.py                    //客户端的异常类
       ├── protocol.py                     //网络协议定义
       ├── region.py                       //区域处理模块
       ├── retry_policy.py                 //服务公共配置类
       └── utils.py                        //公用工具类
```

> **注：** BOS 为百度对象存储 (Baidu Object Storage) 的缩写， 本SDK 基于百度共有云 [BCE BOS Python SDK](https://cloud.baidu.com/doc/BOS/s/Sjwvyqetg)。

## 2.4. 卸载SDK

预期卸载 SDK 时，使用pip卸载“bce-python-sdk”即可。

# 3. 初始化

## 3.1. 快速入门

1. 初始化一个BosClient。

    BosClient是Python SDK与后端对象存储服务交互的客户端，python SDK 对后端对象存储的操作都是通过 BosClient 来完成。  所以在使用python SDK 的时，需要首先初始化 BosClient。

2. 新建一个Bucket。

    Bucket是对象存储中的命名空间，相当于数据的容器，可以存储若干数据实体（Object）。您可以参考新建Bucket来完成新建一个Bucket的操作。

3. 上传Object。

    Object是对象存储中最基本的数据单元，您可以把Object简单的理解为文件。您可以参考上传Object完成对Object的上传。

4. 列出指定Bucket中的全部Object。

    当您完成一系列上传后，可以参考查看Bucket中Object列表来查看指定Bucket下的全部Object。

5. 获取指定Object

    您可以参考获取Object来实现对一个或者多个Object的获取。


## 3.2. BosClient 初始化

BosClient 是对象存储服务的Python客户端，为调用者与后端存储服务进行交互提供了一系列的方法。 创建BosClient 前，必须先创建存储网关列表；在创建 BosClient 时，必须要为 BosClient 指定AK/SK。 

### 3.2.1. 配置存储网关列表：

**新建配置文件 `~/.aws /endpoints`**

在此文件中写入初始的网关列表 。 存储网关列表中记录着部分或者全部存储网关的地址, 每
条地址占一行 ，具体格式如下:

```
http://10.0.0.1:8080 
http://10.0.0.2:8080 
http://10.0.0.3:8080
```

**说明：** 本地必须要保存一份初始网关列表，SDK初始化时需要通过初始网关列表获取服务端
的地址。 初始化完成后 SDK 会去服务端拉取最新的网关列表， 并定时保活 。 但是请注意，
SDK 并不会更新初始网关列表，所以当初始化网关列表中所有地址均失效时， 需要手动更新
此列表。

### 3.2.2. 创建建BosClient

1.在新建BosClient之前，需要先创建配置文件对BosClient进行配置，具体配置信息如下所示：

```
#!/usr/bin/env python
#coding=utf-8

#导入Python标准日志模块
import logging

#从Python SDK导入BOS配置管理模块以及安全认证模块
from baidubce.bce_client_configuration import BceClientConfiguration
from baidubce.auth.bce_credentials import BceCredentials
from baidubce.services.bos.bos_client import BosClient

#设置BosClient的 Access Key ID和Secret Access Key
access_key_id = "AK"
secret_access_key = "SK"

#设置日志文件的句柄和日志级别(若无需日志， 则不用配置日志)
logger = logging.getLogger('baidubce.http.bce_http_client')
fh = logging.FileHandler("sample.log")
fh.setLevel(logging.DEBUG)

#设置日志文件输出的顺序、结构和内容(若无需日志， 则不用配置日志)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(fh)

#创建BceClientConfiguration
config = BceClientConfiguration(credentials=BceCredentials(access_key_id, secret_access_key)，
        endpoints=endpoints_path)
#注意： 针对日志文件，Logging有如下级别：DEBUG，INFO，WARNING，ERROR，CRITICAL。
```

如果你未使用  endpoints 指定初始化网关列表， 将默认使用 `~/.aws/endpoints`。

2. 在完成上述配置之后，参考如下代码新建一个BosClient。

```
bos_client = BosClient(config)
```

### 3.2.3. 配置BosClient

**设置网络参数:**

您可以设置一些网络参数：

```
#设置请求超时时间
config.connection_timeout_in_mills = TIMEOUT
        
#设置接收缓冲区大小
config.recv_buf_size(BUF_SIZE)
    
#设置发送缓冲区大小
config.send_buf_size(BUF_SIZE)
    
#设置连接重试策略
#三次指数退避重试
config.retry_policy = BackOffRetryPolicy()
#不重试
config.retry_policy = NoRetryPolicy()
```

**参数说明:**

通过 BceClientConfiguration 能指定的所有参数如下表所示：

|参数 | 说明 |
| --- | --- |
| send_buf_size  | 发送缓冲区大小|
| recv_buf_size | 接收缓冲区大小|
| connection_timeout_in_mills | 请求超时时间（单位：毫秒）|
| retry_policy | 连接重试策略，初始化Client时默认为三次指数退避 |


# 4. Bucket管理

Bucket既是对象存储上的命名空间，也是权限控制、日志记录等高级功能的管理实体。

Bucket名称在所有区域中具有全局唯一性，且不能修改。

说明：

存储在对象存储上的每个Object都必须包含在一个Bucket中。

您最多可创建100个Bucket（管理员可以配置），但每个Bucket中存放的Object的数量和大小总和没有限制（但是最好单Bucket不超过1千万文件）。

## 4.1. 新建Bucket

如下代码可以新建一个Bucket：

```
if not bos_client.does_bucket_exist(bucket_name):
    bos_client.create_bucket(bucket_name)
```

**注意：** 由于Bucket的名称在所有区域中是唯一的，所以需要保证bucketName不与其他所有区域上的Bucket名称相同。 Bucket的命名有以下规范：

* 只能包括小写字母，数字，短横线（-）。
* 必须以小写字母或者数字开头。
* 长度必须在3-63字节之间。

## 4.2. 列举Bucket

用如下方式可以列出您所有的Bucket：

```
response = bos_client.list_buckets()
for bucket in response.buckets:
     print bucket.name
```

list_buckets方法返回的解析类中可供调用的参数如下：

| 参数 | 说明 |
| --- | --- |
| owner |  Bucket Owner信息|
|+id | Bucket Owner的用户ID|
|+display_name |  Bucket Owner的名称|
|buckets | 存放多个Bucket信息的容器 |
|bucket | 存放一个Bucket信息的容器 |
|+name |  Bucket名称 |
|+creation_date |  Bucket创建时间 |

## 4.3. 删除Bucket

如下代码可以删除一个Bucket：

```
bos_client.delete_bucket(bucket_name)
```

**注意：**

* 如果Bucket不为空（即Bucket中有Object和未完成的三步上传Part存在），则Bucket无法被删除，必须清空Bucket后才能成功删除。

## 4.4. 判断Bucket是否存在

若您需要判断某个Bucket是否存在，则如下代码可以做到：

```
# 获取Bucket的存在信息,需要传入bucket名称，返回值为布尔型
exists = bos_client.does_bucket_exist(bucket_name)
# 输出结果
if exists:
    print "Bucket exists"
else:
    print "Bucket not exists"
```

# 5. 文件管理

## 5.1. 上传文件

在对象存储中，用户操作的基本数据单元是Object。 Bucket中的Object数量不限，但单个Object最大允许存储5TB的数据。 Object包含Key、Meta和Data。 其中，Key是Object的名字；Meta是用户对该Object的描述，由一系列Name-Value对组成；Data是Object的数据。


### 5.1.1. Object的命名规范如下：

* 使用UTF-8编码。
* 长度必须在1-1023字节之间。
* 首字母不能为'/'。

### 5.1.2. 简单上传

BOS在简单上传的场景中，支持以指定文件形式、以数据流方式、以字符串方式执行Object上传，请参考如下代码：

如下代码可以进行Object上传：

```
data = open(file_name, 'rb')
#以数据流形式上传Object
bos_client.put_object(bucket_name, object_key, data, content_length,content_md5)

#从字符串中上传的Object
bos_client.put_object_from_string(bucket_name, object_key, string)

#从文件中上传的Object
bos_client.put_object_from_file(bucket_name, object_key, file_name)
```

其中，data为流对象，不同类型的Object采用不同的处理方法，从字符串中的上传使用StringIO的返回，从文件中的上传使用open()的返回，因此我们提供了封装好的接口方便您进行快速上传。

## 5.2. 下载文件

### 5.2.1. 您可以通过如下代码将Object读取到一个流中：

```
response = bos_client.get_object(bucket_name, object_key)
s = response.data

#  处理Object
...

# 关闭流
response.data.close()
```

### 5.2.2. 直接下载Object到文件或字符串

您可以参考如下代码将Object下载到指定文件：

```
bos_client.get_object_to_file(bucket_name, object_key, file_name)
```

您可以参考如下代码将Object下载到字符串：

```
result = bos_client.get_object_as_string(bucket_name, object_key)
print result
```

