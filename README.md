# ABC Storage 高性能版 Python SDK

ABC Storage 高性能版 Python SDK 为用户提供了高效的对象存储访问接口， 并且支持负载均衡和后端容错功能。 

本文档主要介绍ABC Storage 提供的高性能版 Python SDK 的安装和使用方法。

## 快速开始

请参考 [使用文档](./doc/README.md)

## 测试

```
cp test/bos_test_config.py ./
cp test/test_client_py2_and_py3.py ./

# 修改 bos_test_config.py 填写正确的 AK SK 和用户名等信息
vim test/bos_test_config.py

# 直接执行
python test_client_py2_and_py3.py
```

## 如何贡献

当前，我们只实现了文件上传下载和遍历接口，欢迎您修改和完善此项目， 请直接提交PR 或 issues。

* 提交代码时请保证良好的代码风格。
* 提交 issues 时， 请翻看历史 issues， 尽量不要提交重复的issues。

## 讨论

欢迎提 issues。

