#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use reqwest::cookie::Jar;
use reqwest::header::{HeaderMap, SET_COOKIE};
use reqwest::Client;
use url::Url;

use crate::Args;

pub struct Session {
    /// 可变持有的 client（锁定/导入时整体换新）
    client: RwLock<Arc<Client>>,
    /// 自己记录的 cookie 快照（仅用于导出，domain -> name -> value）
    cookies: Mutex<BTreeMap<(String, String), String>>,
    ua: String,
    timeout: Duration,
    proxy: Option<String>,
    import_jar: Option<Arc<Jar>>,
    /// 站点原始 URL（用于 join）
    pub base: String,
}

impl Session {
    pub fn new(args: &Args) -> anyhow::Result<Self> {
        let import_jar = match &args.import_cookie {
            Some(p) => Some(Self::parse_netscape(p)?),
            None => None,
        };
        let s = Self {
            client: RwLock::new(Arc::new(Self::bake_client(
                &args.ua,
                args.timeout_ms,
                args.proxy.as_deref(),
                import_jar.as_ref().cloned(),
            )?)),
            cookies: Mutex::new(BTreeMap::new()),
            ua: args.ua.clone(),
            timeout: Duration::from_millis(args.timeout_ms),
            proxy: args.proxy.clone(),
            import_jar,
            base: args.url.clone(),
        };
        Ok(s)
    }

    fn bake_client(
        ua: &str,
        timeout_ms: u64,
        proxy: Option<&str>,
        jar: Option<Arc<Jar>>,
    ) -> anyhow::Result<Client> {
        let mut b = Client::builder()
            .user_agent(ua)
            .timeout(Duration::from_millis(timeout_ms));
        if let Some(p) = proxy {
            b = b.proxy(reqwest::Proxy::all(p)?);
        }
        b = match jar {
            Some(j) => b.cookie_provider(j),
            None => b.cookie_store(true),
        };
        Ok(b.build()?)
    }

    /// 锁定期: 换全新会话（丢弃所有 cookie）
    pub fn swap_fresh(&self) {
        if let Ok(c) = Self::bake_client(&self.ua, self.timeout.as_millis() as u64, self.proxy.as_deref(), None) {
            *self.client.write().unwrap() = Arc::new(c);
            self.cookies.lock().unwrap().clear();
        }
    }

    /// REPL: 导入新 cookie 文件并切换会话
    pub fn import_file(&self, path: &str) -> anyhow::Result<()> {
        let jar = Self::parse_netscape(path)?;
        let c = Arc::new(Self::bake_client(
            &self.ua,
            self.timeout.as_millis() as u64,
            self.proxy.as_deref(),
            Some(jar),
        )?);
        *self.client.write().unwrap() = c;
        Ok(())
    }

    pub async fn client(&self) -> Arc<Client> {
        self.client.read().unwrap().clone()
    }

    /// 从响应头收集 Set-Cookie（供导出）
    pub fn capture(&self, resp_url: &str, headers: &HeaderMap) {
        let host = Url::parse(resp_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
            .unwrap_or_default();
        if host.is_empty() {
            return;
        }
        let mut map = self.cookies.lock().unwrap();
        for h in headers.get_all(SET_COOKIE) {
            if let Ok(s) = h.to_str() {
                if let Some((n, v)) = s.split_once('=') {
                    let n = n.trim().to_string();
                    let v = v.split(';').next().unwrap_or("").trim().to_string();
                    map.insert((host.clone(), n), v);
                }
            }
        }
    }

    pub fn dump(&self) -> Vec<(String, String, String)> {
        self.cookies
            .lock()
            .unwrap()
            .iter()
            .map(|((d, n), v)| (d.clone(), n.clone(), v.clone()))
            .collect()
    }

    /// 解析 Netscape cookie 文件 → Jar
    fn parse_netscape(path: &str) -> anyhow::Result<Arc<Jar>> {
        let text = std::fs::read_to_string(path)?;
        let jar = Arc::new(Jar::default());
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 7 {
                continue;
            }
            let mut domain = cols[0].trim();
            if let Some(rest) = domain.strip_prefix("#HttpOnly_") {
                domain = rest;
            }
            let path_col = cols[2];
            let name = cols[5];
            let value = cols[6];
            let domain_clean = domain.trim_start_matches('.');
            let cookie_str = format!("{name}={value}; Path={path_col}; Domain={domain_clean}");
            // 依次尝试 https / http
            for scheme in ["https", "http"] {
                let url = format!("{scheme}://{domain_clean}{path_col}");
                if let Ok(u) = Url::parse(&url) {
                    jar.add_cookie_str(&cookie_str, &u);
                    break;
                }
            }
        }
        Ok(jar)
    }
}

/// 把相对路径解析成绝对 URL（gate/REPL 用）
pub fn resolve_url(base: &str, path: &str) -> String {
    if path.contains("://") {
        return path.to_string();
    }
    if path.starts_with('/') {
        if let Ok(u) = Url::parse(base) {
            if let Some(host) = u.host_str() {
                let scheme = u.scheme();
                let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
                return format!("{scheme}://{host}{port}{path}");
            }
        }
        return path.to_string();
    }
    match Url::parse(base).and_then(|u| u.join(path)) {
        Ok(u) => u.to_string(),
        Err(_) => path.to_string(),
    }
}