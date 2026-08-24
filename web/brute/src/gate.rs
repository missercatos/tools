#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, BufRead, Write};
use std::process::Command;
use std::sync::Arc;

use regex::Regex;
use tokio::sync::Mutex;

use crate::session::{resolve_url, Session};
use crate::Args;

/// 闸门：一次性值的 取 → 展示/提取 → 人工输入 → 注入 环形流程。
/// 会话 cookie 始终由 Engine/Session 持有，取码与提交同会话，杜绝失配。
pub struct Gate {
    kind: GateKind,
    state: Mutex<Option<Vec<(String, String)>>>,
}

enum GateKind {
    /// 图片验证码
    Image { url: String, fields: Vec<String> },
    /// 页面 token（CSRF/滑动值），正则取捕获组 1
    Token { method: String, url: String, re: Regex, fields: Vec<String> },
    /// 万能手动闸门
    Manual { note: String, field: String },
}

const CAP_FILE: &str = "/tmp/brute_cap.png";

impl Gate {
    pub fn new(a: &Args) -> anyhow::Result<Option<Arc<Self>>> {
        let kind = if let Some(s) = &a.gate_image {
            let (url, fields) = split_spec(s)?;
            anyhow::ensure!(!url.is_empty(), "--gate-image URL 为空");
            anyhow::ensure!(!fields.is_empty(), "--gate-image 至少需要一个字段");
            GateKind::Image { url, fields }
        } else if let Some(t) = &a.gate_token {
            let inject = a
                .gate_token_inject
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("--gate-token 需要配合 --gate-token-inject"))?;
            let (method, rest) = t
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("--gate-token 格式: GET 页面URL:正则"))?;
            let (url, re_str) = rest
                .rsplit_once(':')
                .ok_or_else(|| anyhow::anyhow!("--gate-token 正则缺失"))?;
            let re = Regex::new(re_str)?;
            let fields: Vec<String> = inject.split(',').map(|s| s.trim().to_string()).collect();
            GateKind::Token {
                method: method.trim().to_uppercase(),
                url: url.trim().to_string(),
                re,
                fields,
            }
        } else if let Some(m) = &a.gate_manual {
            let (note, field) = m
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("--gate-manual 格式: 提示语:注入字段"))?;
            GateKind::Manual {
                note: note.trim().to_string(),
                field: field.trim().to_string(),
            }
        } else {
            return Ok(None);
        };
        Ok(Some(Arc::new(Self {
            kind,
            state: Mutex::new(None),
        })))
    }

    /// 取当前闸门值；无则先取一次
    pub async fn get(&self, session: &Arc<Session>) -> Option<Vec<(String, String)>> {
        let mut st = self.state.lock().await;
        if st.is_none() {
            *st = self.fetch(session).await;
        }
        st.clone()
    }

    /// 强制重新取（闸门信号/锁定时调用）
    pub async fn reset(&self, session: &Arc<Session>) {
        let mut st = self.state.lock().await;
        *st = self.fetch(session).await;
    }

    async fn fetch(&self, session: &Arc<Session>) -> Option<Vec<(String, String)>> {
        match &self.kind {
            GateKind::Image { url, fields } => {
                let url = resolve_url(&session.base, url);
                let client = session.client().await;
                let bytes = client.get(&url).send().await.ok()?.bytes().await.ok()?;
                fs::write(CAP_FILE, &bytes).ok();
                display_captcha(CAP_FILE);
                let code = prompt("验证码");
                Some(pack_fields(fields, &code))
            }
            GateKind::Token {
                method,
                url,
                re,
                fields,
            } => {
                let url = resolve_url(&session.base, url);
                let client = session.client().await;
                let text = if method == "POST" {
                    client.post(&url).send().await.ok()?.text().await.ok()?
                } else {
                    client.get(&url).send().await.ok()?.text().await.ok()?
                };
                let Some(m) = re.captures(&text) else {
                    eprintln!("[gate] token 正则未匹配到任何内容（页面可能已变化）");
                    return None;
                };
                let val = m.get(1)?.as_str().to_string();
                eprintln!("[gate] token = {val}");
                Some(
                    fields
                        .iter()
                        .map(|f| (f.clone(), val.clone()))
                        .collect(),
                )
            }
            GateKind::Manual { note, field } => {
                let v = prompt(note);
                Some(vec![(field.clone(), v)])
            }
        }
    }
}

/// 字段打包：含 ctime/time 的字段自动填当前时间戳（eYou 场景）
fn pack_fields(fields: &[String], code: &str) -> Vec<(String, String)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_default();
    fields
        .iter()
        .map(|f| {
            if f.to_lowercase().contains("ctime") || f.to_lowercase().contains("time") {
                (f.clone(), now.clone())
            } else {
                (f.clone(), code.to_string())
            }
        })
        .collect()
}

fn split_spec(s: &str) -> anyhow::Result<(String, Vec<String>)> {
    let (url, fields) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("闸门格式: URL:字段1[,字段2...]"))?;
    let fields: Vec<String> = fields.split(',').map(|f| f.trim().to_string()).collect();
    Ok((url.trim().to_string(), fields))
}

/// 展示图片：优先 GUI 查看器，其次 chafa/img2txt ASCII，最后提示路径
fn display_captcha(path: &str) {
    for viewer in ["feh", "imv", "eog", "xdg-open"] {
        if Command::new(viewer)
            .arg(path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            eprintln!("[gate] 已用 {viewer} 打开验证码");
            return;
        }
    }
    for ascii in ["chafa", "img2txt"] {
        if let Ok(out) = Command::new(ascii).arg(path).output() {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if s.trim().len() > 10 {
                    print!("{s}");
                    eprintln!("[gate] (上面的 ASCII 画即验证码)");
                    return;
                }
            }
        }
    }
    eprintln!("[gate] 未找到图片查看器，请自行打开 {path}");
}

fn prompt(note: &str) -> String {
    eprint!("[gate] {note} → ");
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() || line.is_empty() {
        return String::new();
    }
    line.trim().to_string()
}