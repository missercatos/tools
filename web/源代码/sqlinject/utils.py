# -*- coding: utf-8 -*-
"""终端输出配色与 HTTP 请求封装（纯标准库，无第三方依赖）"""
import urllib.request
import urllib.parse
import ssl
import time

ssl._create_default_https_context = ssl.create_default_context
try:
    ssl._create_default_https_context = ssl._create_unverified_context
except Exception:
    pass


class C:
    """ANSI 终端颜色"""
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARN = "\033[93m"
    FAIL = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


def info(msg):
    print(f"{C.BLUE}[*]{C.END} {msg}")


def ok(msg):
    print(f"{C.GREEN}[+]{C.END} {msg}")


def warn(msg):
    print(f"{C.WARN}[!]{C.END} {msg}")


def err(msg):
    print(f"{C.FAIL}[x]{C.END} {msg}")


def result(label, value):
    print(f"  {C.CYAN}{label}{C.END}: {C.BOLD}{value}{C.END}")


DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) sqlinject/1.0"


class Http:
    """极简 HTTP 客户端：返回 (响应文本, 耗时秒)"""

    def __init__(self, timeout=15, cookie=None, ua=None, extra_headers=None,
                 proxy=None, delay=0.0):
        self.timeout = timeout
        self.cookie = cookie
        self.ua = ua or DEFAULT_UA
        self.extra_headers = extra_headers or {}
        self.proxy = proxy
        self.delay = delay

    def send(self, url, method="GET", data=None, inject_cookie=None,
             inject_ua=None, inject_header=None):
        """inject_*: 本次请求临时覆盖对应输入点（不污染会话配置）"""
        headers = {"User-Agent": self.ua}
        cookie = self.cookie
        if self.extra_headers:
            headers.update(self.extra_headers)
        if inject_cookie is not None:
            cookie = inject_cookie
        if cookie:
            headers["Cookie"] = cookie
        if inject_ua is not None:
            headers["User-Agent"] = inject_ua
        if inject_header is not None:
            k, v = inject_header.split(":", 1)
            headers[k.strip()] = v.strip()

        body = None
        if method == "POST" and data is not None:
            body = (urllib.parse.urlencode(data)
                    if isinstance(data, dict) else str(data)).encode()
            headers.setdefault("Content-Type",
                               "application/x-www-form-urlencoded")

        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method)
        if self.proxy:
            handler = urllib.request.ProxyHandler(
                {"http": self.proxy, "https": self.proxy})
            opener = urllib.request.build_opener(handler)
        else:
            opener = urllib.request.build_opener()

        t0 = time.time()
        try:
            resp = opener.open(req, timeout=self.timeout)
            text = resp.read().decode("utf-8", "replace")
        except Exception as e:
            text = f"__HTTP_ERROR__: {e}"
        elapsed = time.time() - t0

        if self.delay > 0:
            time.sleep(self.delay)
        return text, elapsed


def set_query_param(url, key, value):
    """替换或追加 URL 查询参数，value 原样写入（调用方负责编码）"""
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    new_query = [(k, v) for k, v in query if k != key]
    new_query.append((key, value))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path,
         urllib.parse.urlencode(new_query), parsed.fragment))


def parse_post_data(raw):
    """'a=1&b=2' -> dict；无法解析则原样返回字符串"""
    try:
        return dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
    except Exception:
        return raw
