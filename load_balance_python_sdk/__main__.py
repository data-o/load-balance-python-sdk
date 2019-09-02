# -*- coding: UTF-8 -*-
################################################################################
#
# Copyright (c) 2019 Baidu.com, Inc. All Rights Reserved
#
################################################################################
"""
本文件允许模块包以python -m load_balance_python_sdk方式直接执行。

Authors: liupeng37(liupeng37@baidu.com)
Date:    2019/09/02 10:20:18
"""

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals


import sys
from load_balance_python_sdk.cmdline import main
sys.exit(main())
