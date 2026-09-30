use clap::Parser;
use colored::*;
use common::{exit, finish, Mode, Out};
use goblin::elf::Elf;
use goblin::Object;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "pwn-elf", about = "ELF解析 + 保护检测")]
struct Args {
    /// ELF文件路径
    file: PathBuf,

    /// 仅显示保护信息
    #[arg(long)]
    protections: bool,

    /// 仅显示段信息
    #[arg(long)]
    segments: bool,

    /// 仅显示节信息
    #[arg(long)]
    sections: bool,

    /// 显示GOT表
    #[arg(long)]
    got: bool,

    /// 显示PLT表
    #[arg(long)]
    plt: bool,

    /// 显示动态符号
    #[arg(long)]
    dynsyms: bool,

    /// JSON输出
    #[arg(long)]
    json: bool,

    /// 搜索gadget (需要objdump)
    #[arg(long)]
    gadgets: bool,

    /// 搜索指定gadget字符串
    #[arg(long)]
    search: Option<String>,
}

#[derive(Serialize)]
struct Protection {
    name: String,
    status: String,
    #[serde(skip_serializing)]
    color: &'static str,
}

#[derive(Serialize)]
struct SegmentInfo {
    #[serde(rename = "type")]
    ptype: String,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    flags: String,
}

#[derive(Serialize)]
struct SectionInfo {
    name: String,
    addr: u64,
    offset: u64,
    size: u64,
    flags: String,
}

#[derive(Serialize)]
struct GotEntry {
    address: u64,
    value: u64,
    size: u64,
    name: String,
}

#[derive(Serialize)]
struct PltEntry {
    address: u64,
    name: String,
}

#[derive(Serialize)]
struct DynSymEntry {
    value: u64,
    size: u64,
    #[serde(rename = "type")]
    sym_type: String,
    bind: String,
    name: String,
}

#[derive(Serialize)]
struct GadgetsReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    search: Option<String>,
    count: usize,
    items: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct Report {
    file: String,
    arch: String,
    bits: u8,
    elf_type: String,
    entry: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    protections: Option<Vec<Protection>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    segments: Option<Vec<SegmentInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sections: Option<Vec<SectionInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    got: Option<Vec<GotEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plt: Option<Vec<PltEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dynsyms: Option<Vec<DynSymEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gadgets: Option<GadgetsReport>,
}

fn collect_protections(elf: &Elf) -> Vec<Protection> {
    let mut protections = Vec::new();

    // PIE
    match elf.header.e_type {
        goblin::elf::header::ET_DYN => {
            protections.push(Protection { name: "PIE".into(), status: "Enabled".into(), color: "green" });
        }
        goblin::elf::header::ET_EXEC => {
            protections.push(Protection { name: "PIE".into(), status: "Disabled".into(), color: "red" });
        }
        _ => {
            protections.push(Protection { name: "PIE".into(), status: "Unknown".into(), color: "yellow" });
        }
    }

    // NX: 检查PT_GNU_STACK
    let has_gnu_stack = elf.program_headers.iter().any(|ph| {
        ph.p_type == goblin::elf::program_header::PT_GNU_STACK
    });
    let gnu_stack_exec = elf.program_headers.iter().any(|ph| {
        ph.p_type == goblin::elf::program_header::PT_GNU_STACK
            && (ph.p_flags & goblin::elf::program_header::PF_X) != 0
    });
    if gnu_stack_exec {
        protections.push(Protection { name: "NX".into(), status: "Disabled (stack executable)".into(), color: "red" });
    } else if has_gnu_stack {
        protections.push(Protection { name: "NX".into(), status: "Enabled".into(), color: "green" });
    } else {
        protections.push(Protection { name: "NX".into(), status: "Unknown (no PT_GNU_STACK)".into(), color: "yellow" });
    }

    // RELRO
    let has_relro = elf.program_headers.iter().any(|ph| {
        ph.p_type == goblin::elf::program_header::PT_GNU_RELRO
    });
    let has_bind_now = elf.dynamic.as_ref().map_or(false, |d| {
        d.dyns.iter().any(|dyn_entry| {
            dyn_entry.d_tag == goblin::elf::dynamic::DT_BIND_NOW
                || (dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS
                    && (dyn_entry.d_val & goblin::elf::dynamic::DF_BIND_NOW) != 0)
                || (dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS_1
                    && (dyn_entry.d_val & goblin::elf::dynamic::DF_1_NOW) != 0)
        })
    });
    if has_relro && has_bind_now {
        protections.push(Protection { name: "RELRO".into(), status: "Full RELRO".into(), color: "green" });
    } else if has_relro {
        protections.push(Protection { name: "RELRO".into(), status: "Partial RELRO".into(), color: "yellow" });
    } else {
        protections.push(Protection { name: "RELRO".into(), status: "No RELRO".into(), color: "red" });
    }

    // Stack Canary
    let has_canary = elf.dynsyms.iter().any(|sym| {
        elf.strtab.get_at(sym.st_name).map_or(false, |name| {
            name.contains("__stack_chk_fail")
        })
    });
    if has_canary {
        protections.push(Protection { name: "Canary".into(), status: "Enabled".into(), color: "green" });
    } else {
        protections.push(Protection { name: "Canary".into(), status: "Disabled".into(), color: "red" });
    }

    // FORTIFY
    let fortify_count = elf.dynsyms.iter().filter(|sym| {
        elf.strtab.get_at(sym.st_name).map_or(false, |name| {
            name.ends_with("_chk") && name.starts_with("__")
        })
    }).count();
    if fortify_count > 0 {
        protections.push(Protection { name: "FORTIFY".into(), status: format!("Enabled ({} functions)", fortify_count), color: "green" });
    } else {
        protections.push(Protection { name: "FORTIFY".into(), status: "Disabled".into(), color: "red" });
    }

    // RWX segments
    let has_rwx = elf.program_headers.iter().any(|ph| {
        let rwx = goblin::elf::program_header::PF_R
            | goblin::elf::program_header::PF_W
            | goblin::elf::program_header::PF_X;
        (ph.p_flags & rwx) == rwx
    });
    if has_rwx {
        protections.push(Protection { name: "RWX".into(), status: "Found writable+executable segments".into(), color: "red" });
    } else {
        protections.push(Protection { name: "RWX".into(), status: "No RWX segments".into(), color: "green" });
    }

    protections
}

fn print_protections(protections: &[Protection]) {
    println!("\n{}", "=== Protections ===".bold());
    for p in protections {
        match p.color {
            "green" => println!("  {} {}", p.name.green().bold(), p.status),
            "red" => println!("  {} {}", p.name.red().bold(), p.status),
            "yellow" => println!("  {} {}", p.name.yellow().bold(), p.status),
            _ => println!("  {} {}", p.name, p.status),
        }
    }
}

fn collect_segments(elf: &Elf) -> Vec<SegmentInfo> {
    elf.program_headers.iter().map(|ph| {
        let type_str = match ph.p_type {
            goblin::elf::program_header::PT_NULL => "NULL",
            goblin::elf::program_header::PT_LOAD => "LOAD",
            goblin::elf::program_header::PT_DYNAMIC => "DYNAMIC",
            goblin::elf::program_header::PT_INTERP => "INTERP",
            goblin::elf::program_header::PT_NOTE => "NOTE",
            goblin::elf::program_header::PT_PHDR => "PHDR",
            goblin::elf::program_header::PT_GNU_STACK => "GNU_STACK",
            goblin::elf::program_header::PT_GNU_RELRO => "GNU_RELRO",
            goblin::elf::program_header::PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            _ => "OTHER",
        };
        let mut flags = String::new();
        if ph.p_flags & goblin::elf::program_header::PF_R != 0 { flags.push('R'); }
        if ph.p_flags & goblin::elf::program_header::PF_W != 0 { flags.push('W'); }
        if ph.p_flags & goblin::elf::program_header::PF_X != 0 { flags.push('X'); }

        SegmentInfo {
            ptype: type_str.to_string(),
            offset: ph.p_offset,
            vaddr: ph.p_vaddr,
            paddr: ph.p_paddr,
            filesz: ph.p_filesz,
            flags,
        }
    }).collect()
}

fn print_segments(segments: &[SegmentInfo]) {
    println!("\n{}", "=== Program Headers ===".bold());
    println!("  {:<8} {:<16} {:<16} {:<16} {:<10} {:<6}",
        "Type", "Offset", "VirtAddr", "PhysAddr", "FileSize", "Flags");
    for ph in segments {
        println!("  {:<8} 0x{:<15x} 0x{:<15x} 0x{:<15x} 0x{:<9x} {:<6}",
            ph.ptype, ph.offset, ph.vaddr, ph.paddr, ph.filesz, ph.flags);
    }
}

fn collect_sections(elf: &Elf) -> Vec<SectionInfo> {
    let mut out = Vec::new();
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name.is_empty() { continue; }
            let mut flags = String::new();
            if section.sh_flags & goblin::elf::section_header::SHF_WRITE as u64 != 0 { flags.push('W'); }
            if section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 { flags.push('A'); }
            if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 { flags.push('X'); }

            out.push(SectionInfo {
                name: name.to_string(),
                addr: section.sh_addr,
                offset: section.sh_offset,
                size: section.sh_size,
                flags,
            });
        }
    }
    out
}

fn print_sections(sections: &[SectionInfo]) {
    println!("\n{}", "=== Sections ===".bold());
    println!("  {:<20} {:<16} {:<16} {:<10} {:<6}",
        "Name", "Addr", "Offset", "Size", "Flags");
    for section in sections {
        println!("  {:<20} 0x{:<15x} 0x{:<15x} 0x{:<9x} {:<6}",
            section.name, section.addr, section.offset, section.size, section.flags);
    }
}

fn collect_got(elf: &Elf) -> Vec<GotEntry> {
    let mut out = Vec::new();
    for sym in &elf.dynsyms {
        if sym.st_value != 0 && sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    out.push(GotEntry {
                        address: sym.st_value,
                        value: sym.st_value,
                        size: sym.st_size,
                        name: name.to_string(),
                    });
                }
            }
        }
    }
    out
}

fn print_got(entries: &[GotEntry]) {
    println!("\n{}", "=== GOT (Global Offset Table) ===".bold());
    println!("  {:<16} {:<20} {:<8} {:<20}",
        "Address", "Value", "Size", "Name");
    for e in entries {
        println!("  0x{:<15x} 0x{:<19x} {:<8} {}",
            e.address, e.value, e.size, e.name);
    }
}

fn collect_plt(elf: &Elf) -> Vec<PltEntry> {
    let mut out = Vec::new();
    for sym in &elf.dynsyms {
        if sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() && !name.starts_with("_") {
                    out.push(PltEntry {
                        address: sym.st_value,
                        name: name.to_string(),
                    });
                }
            }
        }
    }
    out
}

fn print_plt(entries: &[PltEntry]) {
    println!("\n{}", "=== PLT (Procedure Linkage Table) ===".bold());
    for e in entries {
        println!("  0x{:<15x} {}", e.address, e.name);
    }
}

fn collect_dynsyms(elf: &Elf) -> Vec<DynSymEntry> {
    let mut out = Vec::new();
    for sym in &elf.dynsyms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name.is_empty() { continue; }
            let type_str = match sym.st_type() {
                goblin::elf::sym::STT_NOTYPE => "NOTYPE",
                goblin::elf::sym::STT_OBJECT => "OBJECT",
                goblin::elf::sym::STT_FUNC => "FUNC",
                goblin::elf::sym::STT_SECTION => "SECTION",
                goblin::elf::sym::STT_FILE => "FILE",
                goblin::elf::sym::STT_COMMON => "COMMON",
                goblin::elf::sym::STT_TLS => "TLS",
                _ => "OTHER",
            };
            let bind_str = match sym.st_bind() {
                goblin::elf::sym::STB_LOCAL => "LOCAL",
                goblin::elf::sym::STB_GLOBAL => "GLOBAL",
                goblin::elf::sym::STB_WEAK => "WEAK",
                _ => "OTHER",
            };
            out.push(DynSymEntry {
                value: sym.st_value,
                size: sym.st_size,
                sym_type: type_str.to_string(),
                bind: bind_str.to_string(),
                name: name.to_string(),
            });
        }
    }
    out
}

fn print_dynsyms(entries: &[DynSymEntry]) {
    println!("\n{}", "=== Dynamic Symbols ===".bold());
    println!("  {:<16} {:<16} {:<8} {:<8} {:<20}",
        "Value", "Size", "Type", "Bind", "Name");
    for e in entries {
        println!("  0x{:<15x} {:<16} {:<8} {:<8} {}",
            e.value, e.size, e.sym_type, e.bind, e.name);
    }
}

fn collect_gadgets(binary_path: &str, search: &Option<String>) -> Result<Vec<String>, String> {
    use std::process::Command;

    let output = Command::new("objdump")
        .args(["-d", binary_path])
        .output()
        .map_err(|e| e.to_string())?;

    let disasm = String::from_utf8_lossy(&output.stdout);
    let mut gadgets = Vec::new();

    for line in disasm.lines() {
        let line = line.trim();
        if let Some(ref s) = search {
            if line.contains(s.as_str()) {
                gadgets.push(line.to_string());
            }
        } else {
            // 查找常见gadget: pop rdi; ret, pop rsi; ret 等
            if line.contains("pop") && line.contains("ret") {
                gadgets.push(line.to_string());
            }
            if line.contains("syscall") || line.contains("int 0x80") {
                gadgets.push(line.to_string());
            }
            if line.contains("leave") && line.contains("ret") {
                gadgets.push(line.to_string());
            }
        }
    }

    Ok(gadgets)
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("Failed to read {}: {}", args.file.display(), e));
            return finish(exit::ERROR);
        }
    };

    let elf = match Object::parse(&data) {
        Ok(Object::Elf(elf)) => elf,
        Ok(_) => {
            out.error(&format!("Not an ELF file: {}", args.file.display()));
            return finish(exit::ERROR);
        }
        Err(e) => {
            out.error(&format!("Not an ELF file: {} ({})", args.file.display(), e));
            return finish(exit::ERROR);
        }
    };

    let arch_str = match elf.header.e_machine {
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_ARM => "ARM",
        goblin::elf::header::EM_AARCH64 => "AArch64",
        _ => "Unknown",
    };
    let type_str = match elf.header.e_type {
        goblin::elf::header::ET_EXEC => "ET_EXEC",
        goblin::elf::header::ET_DYN => "ET_DYN (PIE)",
        goblin::elf::header::ET_REL => "ET_REL",
        goblin::elf::header::ET_CORE => "ET_CORE",
        _ => "Unknown",
    };

    let no_flags = !args.protections && !args.segments && !args.sections
        && !args.got && !args.plt && !args.dynsyms;
    let show_protections = args.protections || no_flags;

    let protections = show_protections.then(|| collect_protections(&elf));
    let segments = args.segments.then(|| collect_segments(&elf));
    let sections = args.sections.then(|| collect_sections(&elf));
    let got = args.got.then(|| collect_got(&elf));
    let plt = args.plt.then(|| collect_plt(&elf));
    let dynsyms = args.dynsyms.then(|| collect_dynsyms(&elf));
    let gadgets = args.gadgets.then(|| {
        let path = args.file.to_string_lossy().to_string();
        match collect_gadgets(&path, &args.search) {
            Ok(items) => GadgetsReport {
                search: args.search.clone(),
                count: items.len(),
                items,
                error: None,
            },
            Err(e) => GadgetsReport {
                search: args.search.clone(),
                count: 0,
                items: Vec::new(),
                error: Some(e),
            },
        }
    });

    let report = Report {
        file: args.file.display().to_string(),
        arch: arch_str.to_string(),
        bits: if elf.is_64 { 64 } else { 32 },
        elf_type: type_str.to_string(),
        entry: elf.entry,
        protections,
        segments,
        sections,
        got,
        plt,
        dynsyms,
        gadgets,
    };

    out.emit(
        || {
            println!("{}", format!("=== {} ===", report.file).bold());
            println!("  Arch:   {} ({})", report.arch,
                if report.bits == 64 { "64-bit" } else { "32-bit" });
            println!("  Type:   {}", report.elf_type);
            println!("  Entry:  0x{:x}", report.entry);

            if let Some(protections) = &report.protections {
                print_protections(protections);
            }
            if let Some(segments) = &report.segments {
                print_segments(segments);
            }
            if let Some(sections) = &report.sections {
                print_sections(sections);
            }
            if let Some(got) = &report.got {
                print_got(got);
            }
            if let Some(plt) = &report.plt {
                print_plt(plt);
            }
            if let Some(dynsyms) = &report.dynsyms {
                print_dynsyms(dynsyms);
            }
            if let Some(gadgets) = &report.gadgets {
                println!("\n{}", "=== Gadgets ===".bold());
                if let Some(e) = &gadgets.error {
                    println!("  Error running objdump: {}", e);
                } else if gadgets.items.is_empty() {
                    println!("  No gadgets found.");
                } else {
                    for g in &gadgets.items {
                        println!("  {}", g);
                    }
                    println!("\n  Found {} gadgets", gadgets.items.len());
                }
            }
        },
        &report,
    );

    if let Some(gadgets) = &report.gadgets {
        if gadgets.error.is_some() {
            return finish(exit::ERROR);
        }
        if gadgets.items.is_empty() {
            return finish(exit::NO_RESULT);
        }
    }

    finish(exit::OK)
}
