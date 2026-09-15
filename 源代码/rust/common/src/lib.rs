//! hackingtools 共享库
//!
//! 统一约定:
//! - 退出码: 0=成功/命中, 1=无结果, 2=用法错误, 3=运行错误
//! - 输出: 默认人类可读, --json 时输出 JSON 到 stdout
//! - HTTP: 统一支持 --timeout/--proxy/--insecure/--ua/--cookie

use std::process::ExitCode;

pub mod exit {
    pub const OK: u8 = 0;
    pub const NO_RESULT: u8 = 1;
    pub const USAGE: u8 = 2;
    pub const ERROR: u8 = 3;
}

pub fn finish(code: u8) -> ExitCode {
    ExitCode::from(code)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Human,
    Json,
}

impl Mode {
    pub fn from_flag(json: bool) -> Self {
        if json {
            Mode::Json
        } else {
            Mode::Human
        }
    }
    pub fn is_json(&self) -> bool {
        *self == Mode::Json
    }
}

/// 输出封装: human 闭包负责人类可读输出; json 分支自动序列化
pub struct Out {
    pub mode: Mode,
}

impl Out {
    pub fn new(mode: Mode) -> Self {
        Out { mode }
    }
    pub fn json(&self) -> bool {
        self.mode.is_json()
    }
    /// 人类可读时执行 human; JSON 时序列化 value
    pub fn emit<T: serde::Serialize>(&self, human: impl FnOnce(), value: &T) {
        match self.mode {
            Mode::Human => human(),
            Mode::Json => match serde_json::to_string_pretty(value) {
                Ok(s) => println!("{s}"),
                Err(e) => eprintln!("{{\"error\":\"json serialize: {e}\"}}"),
            },
        }
    }
    /// 打印提示信息(JSON 模式下打到 stderr, 避免污染 stdout)
    pub fn info(&self, msg: &str) {
        match self.mode {
            Mode::Human => println!("{msg}"),
            Mode::Json => eprintln!("{msg}"),
        }
    }
    /// 打印错误(始终 stderr)
    pub fn error(&self, msg: &str) {
        eprintln!("[-] {msg}");
    }
}

/// flag 扫描: 常见 flag 格式
pub fn scan_flags(data: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(data);
    let re = regex::Regex::new(
        r"(?i)\b(flag|ctf|key|passwd|password)\{[^}\r\n]{1,200}\}",
    )
    .expect("flag regex");
    let mut out: Vec<String> = re.find_iter(&text).map(|m| m.as_str().to_string()).collect();
    out.sort();
    out.dedup();
    out
}

/// 解析 hex 字符串(允许 0x 前缀)
pub fn parse_hex(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t, 16).map_err(|e| format!("invalid hex '{s}': {e}"))
}

#[cfg(feature = "http")]
pub mod http {
    use std::time::Duration;

    #[derive(Clone, Debug)]
    pub struct HttpOpts {
        pub timeout: u64,
        pub proxy: Option<String>,
        pub insecure: bool,
        pub user_agent: String,
        pub cookie: Option<String>,
        pub redirects: u32,
    }

    impl Default for HttpOpts {
        fn default() -> Self {
            HttpOpts {
                timeout: 10,
                proxy: None,
                insecure: false,
                user_agent: "Mozilla/5.0 (X11; Linux x86_64) hackingtools/2.0".to_string(),
                cookie: None,
                redirects: 10,
            }
        }
    }

    pub struct Response {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Response {
        pub fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).to_string()
        }
        pub fn header(&self, name: &str) -> Option<&str> {
            let lname = name.to_ascii_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| k.to_ascii_lowercase() == lname)
                .map(|(_, v)| v.as_str())
        }
        pub fn is_success(&self) -> bool {
            (200..300).contains(&self.status)
        }
    }

    #[derive(Clone)]
    pub struct HttpClient {
        agent: ureq::Agent,
        cookie: Option<String>,
        user_agent: String,
    }

    impl HttpClient {
        pub fn new(opts: &HttpOpts) -> Result<Self, String> {
            let mut tls = ureq::tls::TlsConfig::builder();
            if opts.insecure {
                tls = tls.disable_verification(true);
            }
            let mut cfg = ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(opts.timeout.max(1))))
                .max_redirects(opts.redirects)
                .http_status_as_error(false)
                .tls_config(tls.build());
            if let Some(p) = &opts.proxy {
                let proxy = ureq::Proxy::new(p.as_str()).map_err(|e| format!("proxy: {e}"))?;
                cfg = cfg.proxy(Some(proxy));
            }
            let agent: ureq::Agent = cfg.build().into();
            Ok(HttpClient {
                agent,
                cookie: opts.cookie.clone(),
                user_agent: opts.user_agent.clone(),
            })
        }

        pub fn request(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
            body: Option<(&[u8], &str)>,
        ) -> Result<Response, String> {
            let m = method.to_ascii_uppercase();
            let mut rb = ureq::http::Request::builder()
                .method(m.as_str())
                .uri(url)
                .header("User-Agent", self.user_agent.as_str());
            if let Some(c) = &self.cookie {
                rb = rb.header("Cookie", c.as_str());
            }
            for (k, v) in headers {
                rb = rb.header(k.as_str(), v.as_str());
            }
            let req = match body {
                Some((data, ctype)) => rb
                    .header("Content-Type", ctype)
                    .body(data.to_vec())
                    .map_err(|e| format!("build request: {e}"))?,
                None => rb
                    .body(Vec::new())
                    .map_err(|e| format!("build request: {e}"))?,
            };
            let mut resp = self.agent.run(req).map_err(|e| format!("{e}"))?;
            let status = resp.status().as_u16();
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let body = resp
                .body_mut()
                .read_to_vec()
                .map_err(|e| format!("read body: {e}"))?;
            Ok(Response {
                status,
                headers,
                body,
            })
        }

        pub fn get(&self, url: &str) -> Result<Response, String> {
            self.request("GET", url, &[], None)
        }

        pub fn get_with(&self, url: &str, headers: &[(String, String)]) -> Result<Response, String> {
            self.request("GET", url, headers, None)
        }

        pub fn post(&self, url: &str, body: &str, ctype: &str) -> Result<Response, String> {
            self.request("POST", url, &[], Some((body.as_bytes(), ctype)))
        }

        pub fn post_form(&self, url: &str, body: &str) -> Result<Response, String> {
            self.post(url, body, "application/x-www-form-urlencoded")
        }
    }
}
