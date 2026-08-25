#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sqlinject.py -- CTF SQL 注入自动化工具（全终端操作）

五步方法论一键化：确认注入 -> 探测列数 -> 爆库 -> 爆表爆列 -> 提取数据
支持 GET/POST 参数、Cookie、User-Agent、Referer 注入点，
支持布尔/时间盲注与常见 WAF 绕过（空格替换、关键字双写、大小写混淆）。

仅用于本地靶场学习（如 sqli-labs/DVWA），禁止未授权测试。

用法示例:
    ./sqlinject.py -u "http://127.0.0.1/sqli-labs/Less-2/?id=1"
    ./sqlinject.py -u "http://127.0.0.1/Less-11/" -d "uname=admin&passwd=1"
    ./sqlinject.py -u "http://127.0.0.1/Less-20/" --cookie "uname=1"
    ./sqlinject.py -u "http://127.0.0.1/Less-18/" -A "' and 1=1 or '" -d "uname=Dhakkan&passwd=dumb"
    ./sqlinject.py -u "http://127.0.0.1/Less-5/?id=1" --blind bool
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sqlinject.cli import main

if __name__ == "__main__":
    sys.exit(main())
