//! libc-sym - libc 符号偏移查询
//! 纯 Rust 解析动态符号表, 不再依赖 nm/readelf

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use goblin::elf::Elf;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "libc-sym",
    version,
    about = "libc 符号偏移查询",
    long_about = "用法示例:\n  libc-sym libc.so.6 system execve __libc_start_main\n  libc-sym libc.so.6 --all\n  libc-sym libc.so.6 --search printf\n\n退出码: 0=找到 1=未找到 2=用法错误 3=运行错误",
    after_help = "退出码: 0=找到 1=未找到 2=用法错误 3=运行错误"
)]
struct Args {
    /// libc / ELF 文件
    #[arg(value_name = "LIBC")]
    libc: PathBuf,

    /// 要查询的符号名(可多个)
    #[arg(value_name = "SYMBOL")]
    symbols: Vec<String>,

    /// 列出所有导出函数
    #[arg(long, short = 'a')]
    all: bool,

    /// 模糊搜索导出函数
    #[arg(long, short = 's', value_name = "KEY")]
    search: Option<String>,

    /// 搜索所有符号(含 .symtab)
    #[arg(long = "search-all", short = 'S', value_name = "KEY")]
    search_all: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize, Clone)]
struct SymEntry {
    name: String,
    addr: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
}

#[derive(Serialize, Clone)]
struct Report {
    file: String,
    elf_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbols: Option<Vec<SymEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    missing: Option<Vec<String>>,
}

fn clean_name(n: &str) -> String {
    match n.find('@') {
        Some(i) => n[..i].to_string(),
        None => n.to_string(),
    }
}

fn elf_type_str(elf: &Elf) -> String {
    match elf.header.e_type {
        goblin::elf::header::ET_DYN => {
            let has_soname = elf.dynamic.as_ref().is_some_and(|d| {
                d.dyns
                    .iter()
                    .any(|e| e.d_tag == goblin::elf::dynamic::DT_SONAME)
            });
            if has_soname {
                "DYN (Shared object file)".to_string()
            } else if elf
                .program_headers
                .iter()
                .any(|p| p.p_type == goblin::elf::program_header::PT_INTERP)
            {
                "DYN (Position-Independent Executable file)".to_string()
            } else {
                "DYN (Shared object file)".to_string()
            }
        }
        goblin::elf::header::ET_EXEC => "EXEC (Executable file)".to_string(),
        goblin::elf::header::ET_REL => "REL (Relocatable file)".to_string(),
        goblin::elf::header::ET_CORE => "CORE (Core file)".to_string(),
        _ => "NONE".to_string(),
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let data = match std::fs::read(&args.libc) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("cannot read {}: {e}", args.libc.display()));
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

    // 导出函数: 动态符号, 已定义, FUNC/WEAK
    let mut exported: Vec<SymEntry> = Vec::new();
    for sym in elf.dynsyms.iter() {
        if sym.st_shndx == 0 {
            continue; // undefined
        }
        if !(sym.is_function() || sym.st_type() == goblin::elf::sym::STT_GNU_IFUNC) {
            continue;
        }
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.is_empty() {
                continue;
            }
            exported.push(SymEntry {
                name: clean_name(name),
                addr: sym.st_value,
                kind: None,
            });
        }
    }
    exported.sort_by(|a, b| a.addr.cmp(&b.addr));

    // 全符号 (.symtab)
    let mut all_syms: Vec<SymEntry> = Vec::new();
    for sym in elf.syms.iter() {
        if sym.st_shndx == 0 {
            continue;
        }
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name.is_empty() {
                continue;
            }
            let kind = match sym.st_type() {
                goblin::elf::sym::STT_FUNC => "FUNC",
                goblin::elf::sym::STT_OBJECT => "OBJECT",
                goblin::elf::sym::STT_GNU_IFUNC => "IFUNC",
                _ => "NOTYPE",
            };
            all_syms.push(SymEntry {
                name: clean_name(name),
                addr: sym.st_value,
                kind: Some(kind.to_string()),
            });
        }
    }
    all_syms.sort_by(|a, b| a.addr.cmp(&b.addr));

    // --search-all: 全符号搜索
    if let Some(key) = &args.search_all {
        let lk = key.to_lowercase();
        let hits: Vec<&SymEntry> = all_syms
            .iter()
            .filter(|s| s.name.to_lowercase().contains(&lk))
            .collect();
        let report = Report {
            file: args.libc.display().to_string(),
            elf_type: elf_type_str(&elf),
            symbols: Some(
                hits.iter()
                    .map(|s| SymEntry {
                        name: s.name.clone(),
                        addr: s.addr,
                        kind: s.kind.clone(),
                    })
                    .collect(),
            ),
            missing: None,
        };
        out.emit(
            || {
                println!("{} {}", "[*]".bold(), report.file.bold());
                println!("    Type: {}", report.elf_type);
                println!("\n{}", format!("搜索 (所有符号): {key}").cyan());
                for s in report.symbols.as_ref().unwrap() {
                    println!(
                        "  0x{:<12x} {:<8} {}",
                        s.addr,
                        s.kind.as_deref().unwrap_or(""),
                        s.name
                    );
                }
            },
            &report,
        );
        return finish(if hits.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        });
    }

    // --all / --search: 导出函数
    if args.all || args.search.is_some() {
        let hits: Vec<&SymEntry> = match &args.search {
            Some(key) => {
                let lk = key.to_lowercase();
                exported
                    .iter()
                    .filter(|s| s.name.to_lowercase().contains(&lk))
                    .collect()
            }
            None => exported.iter().collect(),
        };
        let report = Report {
            file: args.libc.display().to_string(),
            elf_type: elf_type_str(&elf),
            symbols: Some(
                hits.iter()
                    .map(|s| SymEntry {
                        name: s.name.clone(),
                        addr: s.addr,
                        kind: None,
                    })
                    .collect(),
            ),
            missing: None,
        };
        out.emit(
            || {
                println!("{} {}", "[*]".bold(), report.file.bold());
                println!("    Type: {}", report.elf_type);
                match &args.search {
                    Some(k) => println!("\n{}", format!("搜索: {k}").cyan()),
                    None => println!("\n{}", "导出函数:".cyan()),
                }
                for s in report.symbols.as_ref().unwrap() {
                    println!("  0x{:<12x} {}", s.addr, s.name);
                }
            },
            &report,
        );
        return finish(if hits.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        });
    }

    // 逐个查询
    if args.symbols.is_empty() {
        out.error("需要符号名, 或 --all / --search <关键词>");
        return finish(exit::USAGE);
    }

    let mut found: Vec<SymEntry> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for want in &args.symbols {
        match exported.iter().find(|s| s.name == *want) {
            Some(s) => found.push(SymEntry {
                name: s.name.clone(),
                addr: s.addr,
                kind: None,
            }),
            None => missing.push(want.clone()),
        }
    }

    let report = Report {
        file: args.libc.display().to_string(),
        elf_type: elf_type_str(&elf),
        symbols: Some(found.clone()),
        missing: if missing.is_empty() {
            None
        } else {
            Some(missing.clone())
        },
    };

    out.emit(
        || {
            println!("{} {}", "[*]".bold(), report.file.bold());
            println!("    Type: {}", report.elf_type);
            println!("\n{}", "符号偏移:".cyan());
            for s in &found {
                println!("  0x{:<10x} {}", s.addr, s.name);
            }
            for m in &missing {
                println!("  {} {:<12} {} {}", "???".red(), "", m, "(not found)".red());
            }
        },
        &report,
    );

    finish(if missing.is_empty() {
        exit::OK
    } else {
        exit::NO_RESULT
    })
}
