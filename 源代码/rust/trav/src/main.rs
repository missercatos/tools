//! trav - 通用值空间遍历工具 (CTF 解题 / 终端习惯)
//! 值空间来源: 内联列表(a&b&c) / 字典文件(@file) / 内置字典(--dict) / 生成器({1..10})
//! 判别规则: ==CODE | !=CODE | contains:字符串 | grep:正则
//! 命中处理: 打印 HIT; --recurse 时把命中值回填为下一轮 base 继续深入

use base64::Engine;
use clap::Parser;
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, Mode, Out};
use regex::Regex;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const GEN_DEFAULT_COUNT: usize = 2000;
const GEN_DEFAULT_BUDGET: f64 = 90.0;

const UA_POOL: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
];

const DICT_DIRS: &[&str] = &[
    "admin",
    "upload",
    "uploads",
    "config",
    "configs",
    "data",
    "database",
    "db",
    "backup",
    "backups",
    "temp",
    "tmp",
    "test",
    "tests",
    "api",
    "v1",
    "assets",
    "static",
    "css",
    "js",
    "img",
    "images",
    "fonts",
    "include",
    "includes",
    "lib",
    "libs",
    "vendor",
    "node_modules",
    "logs",
    "log",
    "cache",
    "session",
    "user",
    "users",
    "profile",
    "manage",
    "manager",
    "system",
    "adminer",
    "phpmyadmin",
    "pma",
    "web",
    "www",
    "download",
    "files",
    "file",
    "doc",
    "docs",
    "help",
    "faq",
    "search",
    "index",
    "home",
    "src",
    "source",
    "old",
    "new",
    "dev",
    "prod",
    "flag",
    "f1ag",
    "upfile",
    "upload_file",
    "uploadfiles",
    "flag_dir",
    "admin123",
];

const DICT_BACKUP: &[&str] = &[
    "www.zip",
    "web.zip",
    "site.zip",
    "backup.zip",
    "backup.tar.gz",
    "backup.tar",
    "back.zip",
    "data.zip",
    "db.zip",
    "database.zip",
    "sql.zip",
    "bak.zip",
    "wwwroot.zip",
    "web.rar",
    "site.rar",
    "1.zip",
    "2.zip",
    "a.zip",
    "index.zip",
    "flag.zip",
    "admin.zip",
    "source.zip",
    "src.zip",
    "code.zip",
    "www.tar.gz",
    "web.tar.gz",
    "backup.sql",
    "db.sql",
    "data.sql",
    "dump.sql",
    "mysql.sql",
    "www.tar",
    "web.tar",
    "site.tar.gz",
    "old.zip",
    "old.tar.gz",
    "uploads.zip",
    "files.zip",
];

const DICT_FLAG: &[&str] = &[
    "flag",
    "flag.txt",
    "flag.php",
    "flag.html",
    "f1ag.txt",
    "f1ag.php",
    "flag1",
    "flag2",
    "1.txt",
    "1.php",
    "getflag",
    "get_flag",
    "readflag",
    "fl4g",
    "FLAG",
    "flag_here",
    "flag_dir",
    "flag.zip",
    "flag.tar.gz",
    "index.php",
];

const DICT_ENDPOINTS: &[&str] = &[
    "robots.txt",
    "sitemap.xml",
    ".env",
    ".gitignore",
    ".DS_Store",
    "phpinfo.php",
    "info.php",
    "test.php",
    "readme.md",
    "readme.txt",
    "README.md",
    "license",
    "LICENSE",
    "composer.json",
    "package.json",
    "web.config",
    ".htaccess",
    "crossdomain.xml",
    "security.txt",
    "index.php.bak",
    "config.php.bak",
    "config.php~",
    "admin.php",
    "manage.php",
    "login.php",
    "index.php.swp",
    ".env.bak",
    "flag.txt.bak",
];

const DICT_USERS: &[&str] = &[
    "admin",
    "root",
    "administrator",
    "test",
    "guest",
    "user",
    "manager",
    "operator",
    "system",
    "support",
    "webmaster",
    "demo",
    "admin01",
    "admin2",
    "admin123",
    "root1",
    "root123",
    "service",
    "ctf",
    "user1",
    "operator1",
];

#[derive(Parser, Debug)]
#[command(
    name = "trav",
    version,
    about = "用一批候选值挨个探测 URL，命中的打出来",
    override_usage = "trav <URL前缀> \"<候选值>\" <判定条件> [选项]",
    long_about = "trav -- 用一批候选值挨个探测 URL，命中的打出来\n\n用法: trav <URL前缀> \"<候选值>\" <判定条件> [选项]\n\n候选值写法:\n  \"a&b&c\"        & 分隔\n  \"@字典文件\"    从文件读，每行一个\n  \"{1..100}\"     数字范围\n  --dict 名称    内置字典: dirs|backup|flag|endpoints|users\n\n--gen 生成器（替代候选值参数，用法: trav <URL> <判定> --gen 生成器名:条数）:\n  md5-0e:条数    现场搜索 md5 以 0e 开头的魔法哈希串（随机串+MD5+前缀判定）\n                 概率事件: 默认预算 90 秒（TRAV_GEN_TIME 可调），出多少算多少\n\n判定条件:\n  ==200         状态码正好是 200\n  !=404         状态码不是 404（文件存在）\n  contains:x    响应内容包含 x\n  grep:正则     匹配正则，并输出匹配的内容\n\n退出码: 0=命中 1=无结果 2=用法错误 3=运行错误",
    after_help = "示例:\n  trav http://x/ --dict dirs \"!=404\" --ext \".php&.html\"\n  trav http://x/ \"@pw.txt\" \"==200\" --user admin\n  trav http://x/ \"web&www&backup\" \"!=404\" --ext \".zip&.tar.gz\"\n  trav http://x/flag_in_here/ \"1&2&3\" \"==200\" --recurse\n  trav http://x/ --dict endpoints \"contains:password\" --header \"X-Real-IP: 127.0.0.1\""
)]
struct Args {
    /// 位置参数: <URL前缀> <候选值> <判定条件>（--dict/--gen 时省略候选值）
    #[arg(value_name = "参数", num_args = 1..)]
    pos: Vec<String>,

    /// 再加一组候选值，两两组合（文件名×后缀）
    #[arg(long, value_name = "值空间")]
    ext: Option<String>,

    /// 候选值当密码，用 user:密码 逐个试
    #[arg(long, value_name = "用户名")]
    user: Option<String>,

    /// 生成候选值（与位置参数候选值互斥）
    #[arg(long, value_name = "生成器[:条数]")]
    gen: Option<String>,

    /// 用内置字典当候选值
    #[arg(long, value_name = "名称", conflicts_with = "gen")]
    dict: Option<String>,

    /// 附加请求头（可多次）
    #[arg(long = "header", value_name = "K: V")]
    headers: Vec<String>,

    /// 随机浏览器 User-Agent（带值则自定义 UA）
    #[arg(long, value_name = "UA", num_args = 0..=1, default_missing_value = "")]
    ua: Option<String>,

    /// 命中后继续往下一层目录找
    #[arg(long)]
    recurse: bool,

    /// 递归最多深入几层
    #[arg(long, default_value_t = 5, value_name = "N")]
    maxdepth: u32,

    /// 每请求超时秒数
    #[arg(long, default_value_t = 5, value_name = "SECS")]
    timeout: u64,

    /// 并发数，提速用
    #[arg(long, default_value_t = 1, value_name = "N")]
    threads: usize,

    /// 每请求间隔毫秒（限速/防封）
    #[arg(long, default_value_t = 0, value_name = "MS")]
    delay: u64,

    /// 不跟随 3xx，打印 Location
    #[arg(long)]
    no_follow: bool,

    /// HTTP 代理
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// 跳过 TLS 证书校验
    #[arg(long)]
    insecure: bool,

    /// Cookie
    #[arg(long, value_name = "COOKIE")]
    cookie: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

enum Rule {
    StatusEq(String),
    StatusNe(String),
    Contains(String),
    Grep(Regex),
}

impl Rule {
    fn parse(s: &str) -> Result<Self, String> {
        if let Some(v) = s.strip_prefix("==") {
            Ok(Rule::StatusEq(v.to_string()))
        } else if let Some(v) = s.strip_prefix("!=") {
            Ok(Rule::StatusNe(v.to_string()))
        } else if let Some(v) = s.strip_prefix("contains:") {
            Ok(Rule::Contains(v.to_string()))
        } else if let Some(v) = s.strip_prefix("grep:") {
            Regex::new(v)
                .map(Rule::Grep)
                .map_err(|e| format!("无效正则: {e}"))
        } else {
            Err(format!("未知判别规则: {s}"))
        }
    }

    fn hit(&self, status: u16, body: &str, matches: &mut Vec<String>) -> bool {
        match self {
            Rule::StatusEq(s) => status.to_string() == *s,
            Rule::StatusNe(s) => status.to_string() != *s,
            Rule::Contains(x) => body.contains(x.as_str()),
            Rule::Grep(re) => {
                let mut found = false;
                for m in re.find_iter(body) {
                    matches.push(m.as_str().to_string());
                    found = true;
                }
                found
            }
        }
    }
}

#[derive(Serialize)]
struct Hit {
    value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    url: String,
    status: u16,
    depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    matches: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contains: Option<String>,
}

#[derive(Serialize)]
struct Report {
    base: String,
    rule: String,
    tested: usize,
    hits: usize,
    errors: usize,
    wildcard: bool,
    results: Vec<Hit>,
}

struct Scanner {
    client: HttpClient,
    headers: Vec<(String, String)>,
    user: Option<String>,
    rule: Rule,
    no_follow: bool,
    recurse: bool,
    maxdepth: u32,
    delay: u64,
    json: bool,
    wildcard_body: Option<String>,
    tested: AtomicUsize,
    hit_count: AtomicUsize,
    errors: AtomicUsize,
    results: Mutex<Vec<Hit>>,
}

impl Scanner {
    fn fetch(
        &self,
        url: &str,
        headers: &[(String, String)],
    ) -> Result<common::http::Response, String> {
        match self.client.request("GET", url, headers, None) {
            Ok(r) => Ok(r),
            Err(_) => self.client.request("GET", url, headers, None),
        }
    }

    fn probe(&self, url: &str, val: &str, depth: u32) -> bool {
        let mut headers = self.headers.clone();
        if let Some(u) = &self.user {
            headers.push(auth_header(u, val));
        }
        self.tested.fetch_add(1, Ordering::Relaxed);
        let resp = match self.fetch(url, &headers) {
            Ok(r) => r,
            Err(_) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        };
        let status = resp.status;
        let body = resp.text();
        if let Some(wb) = &self.wildcard_body {
            if &body == wb {
                return false;
            }
        }
        let mut matches = Vec::new();
        if !self.rule.hit(status, &body, &mut matches) {
            return false;
        }
        let location = if self.no_follow {
            resp.header("location")
                .map(|s| resolve_location(url, s.trim()))
        } else {
            None
        };
        let contains = match &self.rule {
            Rule::Contains(x) => Some(x.clone()),
            _ => None,
        };
        if !self.json {
            let prefix = match &self.user {
                Some(u) => format!("{u}:{val}"),
                None => val.to_string(),
            };
            println!("HIT: {prefix} => {url} -> {status}");
            if let Some(loc) = &location {
                if !loc.is_empty() {
                    println!("    Location: {loc}");
                }
            }
            for m in &matches {
                println!("    {m}");
            }
            if let Some(x) = &contains {
                println!("    ...{x}...");
            }
        }
        self.hit_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut r) = self.results.lock() {
            r.push(Hit {
                value: val.to_string(),
                user: self.user.clone(),
                url: url.to_string(),
                status,
                depth,
                location,
                matches,
                contains,
            });
        }
        true
    }

    fn run(&self, base: &str, depth: u32, cands: &[String], exts: &[String]) {
        for c in cands {
            for e in exts {
                let val = format!("{c}{e}");
                let url = join_url(base, &val, self.user.is_some());
                let hit = self.probe(&url, c, depth);
                if hit && !self.recurse {
                    return;
                }
                if hit && self.recurse && depth < self.maxdepth {
                    self.run(&url, depth + 1, cands, exts);
                }
            }
            if self.delay > 0 {
                std::thread::sleep(Duration::from_millis(self.delay));
            }
        }
    }

    fn run_parallel(&self, base: &str, cands: &[String], threads: usize) {
        let next = AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..threads {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= cands.len() {
                        break;
                    }
                    let c = &cands[i];
                    let url = join_url(base, c, self.user.is_some());
                    self.probe(&url, c, 1);
                });
            }
        });
    }
}

fn builtin(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "dirs" => Some(DICT_DIRS),
        "backup" => Some(DICT_BACKUP),
        "flag" => Some(DICT_FLAG),
        "endpoints" => Some(DICT_ENDPOINTS),
        "users" => Some(DICT_USERS),
        _ => None,
    }
}

fn dict_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(d) = std::env::var("TRAV_DICT_DIR") {
        dirs.push(PathBuf::from(d));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("../../ctf/wordlists"));
            dirs.push(dir.join("../../../ctf/wordlists"));
            dirs.push(dir.join("../../../../ctf/wordlists"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("ctf/wordlists"));
        dirs.push(cwd.join("../../ctf/wordlists"));
    }
    dirs
}

fn resolve_dict(name: &str) -> Result<String, String> {
    for d in dict_dirs() {
        let p = d.join(format!("{name}.txt"));
        if p.is_file() {
            return Ok(format!("@{}", p.display()));
        }
    }
    if builtin(name).is_some() {
        Ok(format!("--builtin:{name}"))
    } else {
        Err(format!("未知内置字典: {name}"))
    }
}

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

fn seed() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15);
    nanos ^ ((std::process::id() as u64) << 32) ^ nanos.rotate_left(17)
}

fn rand_hex(n: usize) -> String {
    let mut st = seed();
    let mut s = String::with_capacity(n);
    for _ in 0..n {
        let v = xorshift(&mut st) % 16;
        s.push(std::char::from_digit(v as u32, 16).unwrap_or('0'));
    }
    s
}

fn random_ua() -> String {
    let mut st = seed();
    let i = (xorshift(&mut st) % UA_POOL.len() as u64) as usize;
    UA_POOL[i].to_string()
}

fn auth_header(user: &str, pass: &str) -> (String, String) {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
    ("Authorization".to_string(), format!("Basic {token}"))
}

fn join_url(base: &str, val: &str, user_mode: bool) -> String {
    if user_mode && !base.contains("{}") {
        return base.to_string();
    }
    if base.contains("{}") {
        return base.replace("{}", val);
    }
    if base.ends_with('/') {
        format!("{base}{val}")
    } else {
        format!("{base}/{val}")
    }
}

fn resolve_location(url: &str, loc: &str) -> String {
    if loc.contains("://") {
        return loc.to_string();
    }
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s, r),
        None => return loc.to_string(),
    };
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if let Some(l) = loc.strip_prefix("//") {
        return format!("{scheme}://{l}");
    }
    if loc.starts_with('/') {
        return format!("{scheme}://{host}{loc}");
    }
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    format!("{scheme}://{host}{dir}{loc}")
}

fn fmt_num(v: i64, pad: bool, width: usize) -> String {
    if pad {
        if v < 0 {
            format!("-{:0width$}", v.unsigned_abs(), width = width)
        } else {
            format!("{v:0width$}")
        }
    } else {
        v.to_string()
    }
}

fn expand_range(inner: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = inner.split("..").collect();
    if !(2..=3).contains(&parts.len()) {
        return None;
    }
    if let (Ok(a), Ok(b)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
        let raw_step = if parts.len() == 3 {
            parts[2].parse::<i64>().ok()?
        } else {
            0
        };
        let step = if raw_step == 0 {
            if a <= b {
                1
            } else {
                -1
            }
        } else {
            raw_step
        };
        let pad = (parts[0].len() > 1 && parts[0].starts_with('0'))
            || (parts[1].len() > 1 && parts[1].starts_with('0'));
        let width = parts[0]
            .trim_start_matches('-')
            .len()
            .max(parts[1].trim_start_matches('-').len());
        let mut out = Vec::new();
        let mut i = a;
        if step > 0 {
            while i <= b {
                out.push(fmt_num(i, pad, width));
                i = match i.checked_add(step) {
                    Some(v) => v,
                    None => break,
                };
            }
        } else {
            while i >= b {
                out.push(fmt_num(i, pad, width));
                i = match i.checked_add(step) {
                    Some(v) => v,
                    None => break,
                };
            }
        }
        return Some(out);
    }
    let ca = parts[0].chars().next()?;
    let cb = parts[1].chars().next()?;
    if parts[0].chars().count() == 1
        && parts[1].chars().count() == 1
        && ca.is_ascii_alphabetic()
        && cb.is_ascii_alphabetic()
    {
        let raw_step = if parts.len() == 3 {
            parts[2].parse::<i64>().ok()?
        } else {
            0
        };
        let step = if raw_step == 0 {
            if ca <= cb {
                1
            } else {
                -1
            }
        } else {
            raw_step
        };
        let mut out = Vec::new();
        let mut i = ca as i64;
        let b = cb as i64;
        if step > 0 {
            while i <= b {
                out.push(char::from(i as u8).to_string());
                i = match i.checked_add(step) {
                    Some(v) => v,
                    None => break,
                };
            }
        } else {
            while i >= b {
                out.push(char::from(i as u8).to_string());
                i = match i.checked_add(step) {
                    Some(v) => v,
                    None => break,
                };
            }
        }
        return Some(out);
    }
    None
}

fn expand_braces(s: &str) -> Vec<String> {
    let re = Regex::new(r"\{([^{}]*)\}").expect("brace regex");
    for cap in re.captures_iter(s) {
        let m = cap.get(0).expect("full match");
        if let Some(items) = expand_range(&cap[1]) {
            let prefix = &s[..m.start()];
            let suffix = &s[m.end()..];
            let mut out = Vec::new();
            for it in items {
                let mid = format!("{prefix}{it}{suffix}");
                out.extend(expand_braces(&mid));
            }
            return out;
        }
    }
    vec![s.to_string()]
}

fn gen_md5_0e(want: usize, budget: f64) -> Vec<String> {
    use md5::{Digest, Md5};
    let deadline = Instant::now() + Duration::from_secs_f64(budget.max(0.1));
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .max(1);
    std::thread::scope(|s| {
        for t in 0..nthreads {
            let hits = Arc::clone(&hits);
            let stop = Arc::clone(&stop);
            s.spawn(move || {
                const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                let mut st = seed() ^ (t as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                let mut s6 = [0u8; 6];
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    let mut r = xorshift(&mut st);
                    for ch in s6.iter_mut() {
                        *ch = CHARS[(r % 62) as usize];
                        r /= 62;
                    }
                    let mut h = Md5::new();
                    h.update(s6);
                    let d = h.finalize();
                    if d[0] == 0x0e
                        && d[1..]
                            .iter()
                            .all(|&b| (b >> 4) <= 9 && (b & 0x0f) <= 9)
                    {
                        let val = String::from_utf8_lossy(&s6).to_string();
                        if let Ok(mut v) = hits.lock() {
                            v.push(val);
                            if v.len() >= want {
                                stop.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                }
            });
        }
    });
    let mut v = hits.lock().map(|g| g.clone()).unwrap_or_default();
    v.sort();
    v.dedup();
    v.truncate(want);
    v
}

fn gen_runner(spec: &str) -> Result<Vec<String>, String> {
    let (name, count) = match spec.split_once(':') {
        Some((n, c)) => (
            n,
            c.parse::<usize>()
                .map_err(|_| format!("无效生成器条数: {c}"))?,
        ),
        None => (spec, GEN_DEFAULT_COUNT),
    };
    match name {
        "md5-0e" => {
            let budget = std::env::var("TRAV_GEN_TIME")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(GEN_DEFAULT_BUDGET);
            Ok(gen_md5_0e(count, budget))
        }
        other => Err(format!("未知生成器: {other}（当前支持 md5-0e）")),
    }
}

fn expand_space(spec: &str) -> Result<Vec<String>, String> {
    if let Some(path) = spec.strip_prefix('@') {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("无法读取字典文件 {path}: {e}"))?;
        return Ok(data.lines().map(|l| l.to_string()).collect());
    }
    if let Some(gen) = spec.strip_prefix("--gen:") {
        return gen_runner(gen);
    }
    if let Some(name) = spec.strip_prefix("--builtin:") {
        return builtin(name)
            .map(|d| d.iter().map(|s| s.to_string()).collect())
            .ok_or_else(|| format!("未知内置字典: {name}"));
    }
    if spec.len() >= 2 && spec.starts_with('{') && spec.ends_with('}') {
        return Ok(expand_braces(spec));
    }
    Ok(spec.split('&').map(|s| s.to_string()).collect())
}

fn wildcard_check(
    client: &HttpClient,
    base: &str,
    headers: &[(String, String)],
    user: Option<&str>,
    rule: &Rule,
) -> Option<String> {
    let rnd = rand_hex(10);
    let url = join_url(base, &rnd, user.is_some());
    let mut hs = headers.to_vec();
    if let Some(u) = user {
        hs.push(auth_header(u, &format!("x{rnd}")));
    }
    let resp = match client.request("GET", &url, &hs, None) {
        Ok(r) => r,
        Err(_) => match client.request("GET", &url, &hs, None) {
            Ok(r) => r,
            Err(_) => return None,
        },
    };
    let body = resp.text();
    let mut matches = Vec::new();
    if rule.hit(resp.status, &body, &mut matches) {
        eprintln!(
            "警告: 随机值也命中判定({rnd} -> {})，疑似通配响应，将过滤相同响应的候选值",
            resp.status
        );
        Some(body)
    } else {
        None
    }
}

fn usage_error(msg: &str) -> ExitCode {
    eprintln!("{msg}");
    eprintln!("用法: trav <URL前缀> \"<候选值>\" <判定条件> [选项]");
    eprintln!("运行 trav --help 查看完整帮助");
    finish(exit::USAGE)
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let pos = &args.pos;
    let base: String;
    let space: String;
    let rule_text: String;
    if let Some(gen) = &args.gen {
        if pos.len() < 2 {
            return usage_error("错误: --gen 模式需要 <URL前缀> <判定条件>");
        }
        if pos.len() > 2 {
            return usage_error("错误: --gen 模式下无需候选值参数");
        }
        base = pos[0].clone();
        space = format!("--gen:{gen}");
        rule_text = pos[1].clone();
    } else if let Some(dict) = &args.dict {
        if pos.len() < 2 {
            return usage_error("错误: --dict 模式需要 <URL前缀> <判定条件>");
        }
        if pos.len() > 2 {
            return usage_error("错误: --dict 模式下无需候选值参数");
        }
        base = pos[0].clone();
        space = match resolve_dict(dict) {
            Ok(s) => s,
            Err(e) => return usage_error(&e),
        };
        rule_text = pos[1].clone();
    } else {
        if pos.len() != 3 {
            return usage_error("错误: 需要 <URL前缀> <候选值> <判定条件> 三个参数");
        }
        base = pos[0].clone();
        space = pos[1].clone();
        rule_text = pos[2].clone();
    }

    let rule = match Rule::parse(&rule_text) {
        Ok(r) => r,
        Err(e) => {
            out.error(&e);
            return finish(exit::USAGE);
        }
    };

    let mut threads = args.threads.max(1);
    let mut delay = args.delay;
    if args.recurse {
        threads = 1;
    }
    if threads > 1 && delay > 0 {
        eprintln!("警告: 并行模式下 --delay 无效");
        delay = 0;
    }

    let user_agent = match &args.ua {
        Some(s) if !s.is_empty() => s.clone(),
        Some(_) => random_ua(),
        None => HttpOpts::default().user_agent,
    };

    let opts = HttpOpts {
        timeout: args.timeout,
        proxy: args.proxy.clone(),
        insecure: args.insecure,
        user_agent,
        cookie: args.cookie.clone(),
        redirects: if args.no_follow { 0 } else { 10 },
    };
    let client = match HttpClient::new(&opts) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return finish(exit::ERROR);
        }
    };

    let mut headers = Vec::new();
    for h in &args.headers {
        match h.split_once(':') {
            Some((k, v)) => headers.push((k.trim().to_string(), v.trim_start().to_string())),
            None => eprintln!("警告: 忽略无效请求头: {h}"),
        }
    }

    let cands = match expand_space(&space) {
        Ok(c) => c,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    let exts = match &args.ext {
        Some(e) => match expand_space(e) {
            Ok(v) => v,
            Err(err) => {
                out.error(&err);
                return finish(exit::ERROR);
            }
        },
        None => vec![String::new()],
    };

    let wildcard_body = wildcard_check(&client, &base, &headers, args.user.as_deref(), &rule);
    let wildcard = wildcard_body.is_some();

    let scanner = Scanner {
        client,
        headers,
        user: args.user.clone(),
        rule,
        no_follow: args.no_follow,
        recurse: args.recurse,
        maxdepth: args.maxdepth,
        delay,
        json: out.json(),
        wildcard_body,
        tested: AtomicUsize::new(0),
        hit_count: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
        results: Mutex::new(Vec::new()),
    };

    if threads > 1 {
        if args.ext.is_some() {
            eprintln!("警告: --threads 并行模式不支持 --ext，已忽略");
        }
        scanner.run_parallel(&base, &cands, threads);
    } else {
        scanner.run(&base, 1, &cands, &exts);
    }

    let tested = scanner.tested.load(Ordering::Relaxed);
    let hits = scanner.hit_count.load(Ordering::Relaxed);
    let errors = scanner.errors.load(Ordering::Relaxed);
    let results = scanner.results.into_inner().unwrap_or_default();
    let report = Report {
        base: base.clone(),
        rule: rule_text.clone(),
        tested,
        hits,
        errors,
        wildcard,
        results,
    };

    if !out.json() {
        eprintln!("[*] 统计: 探测 {tested} | 命中 {hits} | 错误 {errors}");
    }
    out.emit(|| {}, &report);

    if hits > 0 {
        finish(exit::OK)
    } else {
        finish(exit::NO_RESULT)
    }
}
