#![forbid(unsafe_code)]

use std::fs;

use crate::Args;

const DIR: &str = "rules";

/// 把本次打法存档（规则 = 完整参数列表，每行一个）
pub fn save(name: &str, argv: &[String]) -> anyhow::Result<()> {
    fs::create_dir_all(DIR)?;
    fs::write(format!("{DIR}/{name}"), argv.join("\n"))?;
    Ok(())
}

pub fn load(name: &str) -> anyhow::Result<Vec<String>> {
    let text = fs::read_to_string(format!("{DIR}/{name}"))?;
    Ok(text
        .lines()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect())
}

/// 由当前 Args 重建命令行参数（用于存档）
pub fn argv_of(a: &Args) -> Vec<String> {
    let mut v = vec![a.url.clone()];
    fn add(v: &mut Vec<String>, flag: &str, val: &str) {
        v.push(flag.to_string());
        v.push(val.to_string());
    }
    if let Some(x) = &a.post {
        add(&mut v, "--post", x);
    }
    if let Some(x) = &a.json {
        add(&mut v, "--json", x);
    }
    if let Some(x) = &a.basic_user {
        add(&mut v, "--basic-user", x);
    }
    if a.user != "admin" {
        add(&mut v, "--user", &a.user);
    }
    if let Some(x) = &a.dict {
        add(&mut v, "--dict", x);
    }
    if let Some(x) = &a.defaults {
        add(&mut v, "--defaults", x);
    }
    if a.workers != 6 {
        add(&mut v, "--workers", &a.workers.to_string());
    }
    if let Some(x) = a.interval_ms {
        add(&mut v, "--interval-ms", &x.to_string());
    }
    if let Some(x) = &a.fail_contains {
        add(&mut v, "--fail-contains", x);
    }
    if let Some(x) = &a.success_contains {
        add(&mut v, "--success-contains", x);
    }
    if let Some(x) = a.code {
        add(&mut v, "--code", &x.to_string());
    }
    if a.flag_regex != r"ctfhub\{[^}]+\}" {
        add(&mut v, "--flag-regex", &a.flag_regex);
    }
    if a.resume {
        v.push("--resume".to_string());
    }
    if a.offset_file != ".brute.offset" {
        add(&mut v, "--offset-file", &a.offset_file);
    }
    if let Some(x) = &a.gate_image {
        add(&mut v, "--gate-image", x);
    }
    if a.gate_error != "captcha" {
        add(&mut v, "--gate-error", &a.gate_error);
    }
    if let Some(x) = &a.gate_token {
        add(&mut v, "--gate-token", x);
    }
    if let Some(x) = &a.gate_token_inject {
        add(&mut v, "--gate-token-inject", x);
    }
    if let Some(x) = &a.gate_manual {
        add(&mut v, "--gate-manual", x);
    }
    if let Some(x) = &a.lockout {
        add(&mut v, "--lockout", x);
    }
    if a.lockout_wait != 60 {
        add(&mut v, "--lockout-wait", &a.lockout_wait.to_string());
    }
    if a.timeout_ms != 10000 {
        add(&mut v, "--timeout-ms", &a.timeout_ms.to_string());
    }
    if a.ua != "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" {
        add(&mut v, "--ua", &a.ua);
    }
    if let Some(x) = &a.import_cookie {
        add(&mut v, "--import-cookie", x);
    }
    if let Some(x) = &a.proxy {
        add(&mut v, "--proxy", x);
    }
    if let Some(x) = &a.mangle {
        add(&mut v, "--mangle", x);
    }
    if let Some(x) = &a.enum_users {
        add(&mut v, "--enum-users", x);
    }
    if let Some(x) = &a.report {
        add(&mut v, "--report", x);
    }
    if a.retry != 2 {
        add(&mut v, "--retry", &a.retry.to_string());
    }
    if a.repl {
        v.push("--repl".to_string());
    }
    v
}