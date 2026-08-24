#![forbid(unsafe_code)]

use reqwest::header::CONTENT_TYPE;
use reqwest::{Client, RequestBuilder};

use crate::Args;

#[derive(Clone)]
pub enum Auth {
    Get { url: String, user: String },
    Form { url: String, pairs: Vec<(String, String)>, user: String },
    Json { url: String, raw: String, user: String },
    Basic { url: String, user: String },
}

const USER_TAG: &str = "{user}";
const PASS_TAG: &str = "{pass}";

impl Auth {
    pub fn new(a: &Args) -> anyhow::Result<Self> {
        if let Some(t) = &a.post {
            return Ok(Auth::Form {
                url: a.url.clone(),
                pairs: parse_kv(t)?,
                user: a.user.clone(),
            });
        }
        if let Some(j) = &a.json {
            return Ok(Auth::Json {
                url: a.url.clone(),
                raw: j.clone(),
                user: a.user.clone(),
            });
        }
        if let Some(u) = &a.basic_user {
            return Ok(Auth::Basic {
                url: a.url.clone(),
                user: u.clone(),
            });
        }
        Ok(Auth::Get {
            url: a.url.clone(),
            user: a.user.clone(),
        })
    }

    pub fn request(
        &self,
        c: &Client,
        pass: &str,
        extra: Option<&[(String, String)]>,
    ) -> anyhow::Result<RequestBuilder> {
        Ok(match self {
            Auth::Get { url, user } => {
                c.get(render(url, user, pass))
            }
            Auth::Form { url, pairs, user } => {
                let mut fields: Vec<(String, String)> = pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), render(v, user, pass)))
                    .collect();
                if let Some(extra) = extra {
                    fields.extend(extra.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
                c.post(url).form(&fields)
            }
            Auth::Json { url, raw, user } => c
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(render(raw, user, pass)),
            Auth::Basic { url, user } => {
                c.get(url).basic_auth(user, Some(pass))
            }
        })
    }
}

fn render(tpl: &str, user: &str, pass: &str) -> String {
    tpl.replace(USER_TAG, user).replace(PASS_TAG, pass)
}

fn parse_kv(t: &str) -> anyhow::Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for seg in t.split('&') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        let (k, v) = seg.split_once('=').unwrap_or((seg, ""));
        pairs.push((k.to_string(), v.to_string()));
    }
    anyhow::ensure!(!pairs.is_empty(), "--post 模板为空");
    // 模板必须带 {pass}（除非真的有固定密码业务的用法，这里强制检查）
    if !t.contains(PASS_TAG) {
        anyhow::bail!("--post 模板缺少 {{pass}} 占位符");
    }
    Ok(pairs)
}