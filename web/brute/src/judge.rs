#![forbid(unsafe_code)]

use regex::Regex;

use crate::Args;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    Success,
    Fail,
    Gate,
    Lockout,
    Neutral,
}

pub struct Judge {
    fail_contains: Option<String>,
    success_contains: Option<String>,
    code: Option<u16>,
    flag_re: Regex,
    gate_error: String,
    lockout: Option<String>,
}

impl Judge {
    pub fn new(a: &Args) -> anyhow::Result<Self> {
        Ok(Self {
            fail_contains: a.fail_contains.clone(),
            success_contains: a.success_contains.clone(),
            code: a.code,
            flag_re: Regex::new(&a.flag_regex)?,
            gate_error: a.gate_error.clone(),
            lockout: a.lockout.clone(),
        })
    }

    pub fn verdict(&self, status: u16, body: &str) -> Verdict {
        if !self.gate_error.is_empty() && body.to_lowercase().contains(&self.gate_error.to_lowercase())
        {
            return Verdict::Gate;
        }
        if let Some(l) = &self.lockout {
            if body.to_lowercase().contains(&l.to_lowercase()) {
                return Verdict::Lockout;
            }
        }
        if let Some(s) = &self.success_contains {
            if body.contains(s) {
                return Verdict::Success;
            }
        }
        if let Some(f) = &self.fail_contains {
            if body.contains(f) {
                return Verdict::Fail;
            }
        }
        if let Some(c) = self.code {
            if status == c {
                return Verdict::Success;
            }
        }
        // 没有显式成功/失败判据时：200 且无失败信号 → 保守视为未命中
        Verdict::Neutral
    }

    pub fn flags(&self, body: &str) -> Vec<String> {
        self.flag_re
            .captures_iter(body)
            .map(|m| m.get(0).map(|s| s.as_str().to_string()).unwrap_or_default())
            .filter(|s| !s.is_empty())
            .collect()
    }
}