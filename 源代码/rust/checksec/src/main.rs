//! checksec - ELF 保护检测 (NX/PIE/RELRO/Canary/FORTIFY/RWX)
//! 纯 Rust 解析, 不再依赖 readelf/xxd/nm

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW};
use goblin::elf::program_header::{PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK};
use goblin::elf::Elf;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "checksec",
    version,
    about = "ELF 保护检测: NX/PIE/RELRO/Canary/FORTIFY/RWX",
    long_about = "纯 Rust 解析 ELF, 零外部依赖。\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标 ELF 文件
    #[arg(value_name = "BINARY")]
    binary: PathBuf,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Report {
    file: String,
    bits: u8,
    arch: String,
    elf_type: String,
    nx: Option<bool>,
    pie: Option<bool>,
    relro: String,
    canary: bool,
    fortify: usize,
    rwx: bool,
}

fn machine_name(m: u16) -> String {
    match m {
        goblin::elf::header::EM_386 => "x86".into(),
        goblin::elf::header::EM_X86_64 => "x86_64".into(),
        goblin::elf::header::EM_ARM => "ARM".into(),
        goblin::elf::header::EM_AARCH64 => "AArch64".into(),
        goblin::elf::header::EM_MIPS => "MIPS".into(),
        goblin::elf::header::EM_RISCV => "RISC-V".into(),
        goblin::elf::header::EM_PPC => "PowerPC".into(),
        goblin::elf::header::EM_PPC64 => "PowerPC64".into(),
        other => format!("machine_{other}"),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let data = match std::fs::read(&args.binary) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("cannot read {}: {e}", args.binary.display()));
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

    // NX: PT_GNU_STACK 权限不含 X
    let mut nx: Option<bool> = None;
    let mut rwx = false;
    for ph in &elf.program_headers {
        if ph.p_type == PT_GNU_STACK {
            nx = Some(ph.p_flags & PF_X == 0);
        }
        if ph.p_flags & PF_W != 0 && ph.p_flags & PF_X != 0 {
            rwx = true;
        }
    }

    // PIE
    let pie = match elf.header.e_type {
        goblin::elf::header::ET_DYN => Some(true),
        goblin::elf::header::ET_EXEC => Some(false),
        _ => None,
    };
    let elf_type = match elf.header.e_type {
        goblin::elf::header::ET_EXEC => "ET_EXEC",
        goblin::elf::header::ET_DYN => "ET_DYN",
        goblin::elf::header::ET_REL => "ET_REL",
        goblin::elf::header::ET_CORE => "ET_CORE",
        _ => "ET_NONE",
    }
    .to_string();

    // RELRO
    let has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let bind_now = elf.dynamic.as_ref().is_some_and(|d| {
        d.dyns.iter().any(|e| {
            (e.d_tag == goblin::elf::dynamic::DT_FLAGS
                && e.d_val & DF_BIND_NOW != 0)
                || (e.d_tag == goblin::elf::dynamic::DT_FLAGS_1
                    && e.d_val & DF_1_NOW != 0)
                || e.d_tag == goblin::elf::dynamic::DT_BIND_NOW
        })
    });
    let relro = if !has_relro {
        "none".to_string()
    } else if bind_now {
        "full".to_string()
    } else {
        "partial".to_string()
    };

    // Canary / FORTIFY: 动态符号
    let mut canary = false;
    let mut fortify = 0usize;
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name == "__stack_chk_fail" || name == "__stack_chk_fail_local" {
                canary = true;
            } else if name.starts_with("__") && name.ends_with("_chk") {
                fortify += 1;
            }
        }
    }

    let report = Report {
        file: args.binary.display().to_string(),
        bits: if elf.is_64 { 64 } else { 32 },
        arch: machine_name(elf.header.e_machine),
        elf_type,
        nx,
        pie,
        relro: relro.clone(),
        canary,
        fortify,
        rwx,
    };

    out.emit(
        || {
            println!("{} {}", "[*]".bold(), report.file.bold());
            println!("    Arch: {}-bit | {}", report.bits, report.arch);
            match report.nx {
                Some(true) => println!("{} {:<10} {}", "[+]".green(), "NX", "Enabled".green()),
                Some(false) => println!(
                    "{} {:<10} {}",
                    "[-]".red(),
                    "NX",
                    "Disabled (stack executable)".red()
                ),
                None => println!(
                    "{} {:<10} {}",
                    "[!]".yellow(),
                    "NX",
                    "No PT_GNU_STACK (legacy binary?)".yellow()
                ),
            }
            match report.pie {
                Some(true) => println!(
                    "{} {:<10} {}",
                    "[+]".green(),
                    "PIE",
                    format!("Enabled ({})", report.elf_type).green()
                ),
                Some(false) => println!(
                    "{} {:<10} {}",
                    "[-]".red(),
                    "PIE",
                    format!("Disabled ({})", report.elf_type).red()
                ),
                None => println!(
                    "{} {:<10} {}",
                    "[!]".yellow(),
                    "PIE",
                    format!("Unknown type ({})", report.elf_type).yellow()
                ),
            }
            match report.relro.as_str() {
                "full" => println!("{} {:<10} {}", "[+]".green(), "RELRO", "Full RELRO".green()),
                "partial" => println!(
                    "{} {:<10} {}",
                    "[!]".yellow(),
                    "RELRO",
                    "Partial RELRO".yellow()
                ),
                _ => println!("{} {:<10} {}", "[-]".red(), "RELRO", "No RELRO".red()),
            }
            if report.canary {
                println!("{} {:<10} {}", "[+]".green(), "Canary", "Enabled".green());
            } else {
                println!("{} {:<10} {}", "[-]".red(), "Canary", "Disabled".red());
            }
            if report.fortify > 0 {
                println!(
                    "{} {:<10} {}",
                    "[+]".green(),
                    "FORTIFY",
                    format!("Enabled ({} functions)", report.fortify).green()
                );
            } else {
                println!("{} {:<10} {}", "[-]".red(), "FORTIFY", "Disabled".red());
            }
            if report.rwx {
                println!(
                    "{} {:<10} {}",
                    "[!]".yellow(),
                    "RWX",
                    "Found writable+executable segments".yellow()
                );
            } else {
                println!("{} {:<10} {}", "[+]".green(), "RWX", "No RWX segments".green());
            }
        },
        &report,
    );

    finish(exit::OK)
}
