use clap::Parser;
use colored::*;
use goblin::elf::Elf;
use goblin::Object;
use std::fs;
use std::path::PathBuf;

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

struct Protection {
    name: &'static str,
    status: String,
    color: &'static str,
}

fn check_protections(elf: &Elf) -> Vec<Protection> {
    let mut protections = Vec::new();

    // PIE
    match elf.header.e_type {
        goblin::elf::header::ET_DYN => {
            protections.push(Protection { name: "PIE", status: "Enabled".into(), color: "green" });
        }
        goblin::elf::header::ET_EXEC => {
            protections.push(Protection { name: "PIE", status: "Disabled".into(), color: "red" });
        }
        _ => {
            protections.push(Protection { name: "PIE", status: "Unknown".into(), color: "yellow" });
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
        protections.push(Protection { name: "NX", status: "Disabled (stack executable)".into(), color: "red" });
    } else if has_gnu_stack {
        protections.push(Protection { name: "NX", status: "Enabled".into(), color: "green" });
    } else {
        protections.push(Protection { name: "NX", status: "Unknown (no PT_GNU_STACK)".into(), color: "yellow" });
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
        protections.push(Protection { name: "RELRO", status: "Full RELRO".into(), color: "green" });
    } else if has_relro {
        protections.push(Protection { name: "RELRO", status: "Partial RELRO".into(), color: "yellow" });
    } else {
        protections.push(Protection { name: "RELRO", status: "No RELRO".into(), color: "red" });
    }

    // Stack Canary
    let has_canary = elf.dynsyms.iter().any(|sym| {
        elf.strtab.get_at(sym.st_name).map_or(false, |name| {
            name.contains("__stack_chk_fail")
        })
    });
    if has_canary {
        protections.push(Protection { name: "Canary", status: "Enabled".into(), color: "green" });
    } else {
        protections.push(Protection { name: "Canary", status: "Disabled".into(), color: "red" });
    }

    // FORTIFY
    let fortify_count = elf.dynsyms.iter().filter(|sym| {
        elf.strtab.get_at(sym.st_name).map_or(false, |name| {
            name.ends_with("_chk") && name.starts_with("__")
        })
    }).count();
    if fortify_count > 0 {
        protections.push(Protection { name: "FORTIFY", status: format!("Enabled ({} functions)", fortify_count), color: "green" });
    } else {
        protections.push(Protection { name: "FORTIFY", status: "Disabled".into(), color: "red" });
    }

    // RWX segments
    let has_rwx = elf.program_headers.iter().any(|ph| {
        let rwx = goblin::elf::program_header::PF_R
            | goblin::elf::program_header::PF_W
            | goblin::elf::program_header::PF_X;
        (ph.p_flags & rwx) == rwx
    });
    if has_rwx {
        protections.push(Protection { name: "RWX", status: "Found writable+executable segments".into(), color: "red" });
    } else {
        protections.push(Protection { name: "RWX", status: "No RWX segments".into(), color: "green" });
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

fn print_segments(elf: &Elf) {
    println!("\n{}", "=== Program Headers ===".bold());
    println!("  {:<8} {:<16} {:<16} {:<16} {:<10} {:<6}",
        "Type", "Offset", "VirtAddr", "PhysAddr", "FileSize", "Flags");
    for ph in &elf.program_headers {
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
        
        println!("  {:<8} 0x{:<15x} 0x{:<15x} 0x{:<15x} 0x{:<9x} {:<6}",
            type_str, ph.p_offset, ph.p_vaddr, ph.p_paddr, ph.p_filesz, flags);
    }
}

fn print_sections(elf: &Elf) {
    println!("\n{}", "=== Sections ===".bold());
    println!("  {:<20} {:<16} {:<16} {:<10} {:<6}",
        "Name", "Addr", "Offset", "Size", "Flags");
    for section in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
            if name.is_empty() { continue; }
            let mut flags = String::new();
            if section.sh_flags & goblin::elf::section_header::SHF_WRITE as u64 != 0 { flags.push('W'); }
            if section.sh_flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0 { flags.push('A'); }
            if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 { flags.push('X'); }
            
            println!("  {:<20} 0x{:<15x} 0x{:<15x} 0x{:<9x} {:<6}",
                name, section.sh_addr, section.sh_offset, section.sh_size, flags);
        }
    }
}

fn print_got(elf: &Elf) {
    println!("\n{}", "=== GOT (Global Offset Table) ===".bold());
    println!("  {:<16} {:<20} {:<8} {:<20}",
        "Address", "Value", "Size", "Name");
    for sym in &elf.dynsyms {
        if sym.st_value != 0 && sym.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    println!("  0x{:<15x} 0x{:<19x} {:<8} {}",
                        sym.st_value, sym.st_value, sym.st_size, name);
                }
            }
        }
    }
}

fn print_plt(elf: &Elf) {
    println!("\n{}", "=== PLT (Procedure Linkage Table) ===".bold());
    for sym in &elf.dynsyms {
        if sym.st_value != 0 {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() && !name.starts_with("_") {
                    println!("  0x{:<15x} {}", sym.st_value, name);
                }
            }
        }
    }
}

fn print_dynsyms(elf: &Elf) {
    println!("\n{}", "=== Dynamic Symbols ===".bold());
    println!("  {:<16} {:<16} {:<8} {:<8} {:<20}",
        "Value", "Size", "Type", "Bind", "Name");
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
            println!("  0x{:<15x} {:<16} {:<8} {:<8} {}",
                sym.st_value, sym.st_size, type_str, bind_str, name);
        }
    }
}

fn find_gadgets(binary_path: &str, search: &Option<String>) {
    println!("\n{}", "=== Gadgets ===".bold());
    use std::process::Command;
    
    let output = Command::new("objdump")
        .args(["-d", binary_path])
        .output();
    
    match output {
        Ok(out) => {
            let disasm = String::from_utf8_lossy(&out.stdout);
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
            
            if gadgets.is_empty() {
                println!("  No gadgets found.");
            } else {
                for g in &gadgets {
                    println!("  {}", g);
                }
                println!("\n  Found {} gadgets", gadgets.len());
            }
        }
        Err(e) => {
            println!("  Error running objdump: {}", e);
        }
    }
}

fn main() {
    let args = Args::parse();
    
    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{} Failed to read {}: {}", "error:".red().bold(), args.file.display(), e);
            std::process::exit(1);
        }
    };
    
    let elf = match Object::parse(&data).unwrap() {
        Object::Elf(elf) => elf,
        _ => {
            eprintln!("{} Not an ELF file: {}", "error:".red().bold(), args.file.display());
            std::process::exit(1);
        }
    };
    
    // 基本信息
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
    
    println!("{}", format!("=== {} ===", args.file.display()).bold());
    println!("  Arch:   {} ({})", arch_str,
        if elf.is_64 { "64-bit" } else { "32-bit" });
    println!("  Type:   {}", type_str);
    println!("  Entry:  0x{:x}", elf.entry);
    
    // 默认显示保护信息
    if !args.protections && !args.segments && !args.sections
        && !args.got && !args.plt && !args.dynsyms {
        let protections = check_protections(&elf);
        print_protections(&protections);
    }
    
    if args.protections {
        let protections = check_protections(&elf);
        print_protections(&protections);
    }
    if args.segments { print_segments(&elf); }
    if args.sections { print_sections(&elf); }
    if args.got { print_got(&elf); }
    if args.plt { print_plt(&elf); }
    if args.dynsyms { print_dynsyms(&elf); }
    if args.gadgets {
        find_gadgets(&args.file.to_str().unwrap_or(""), &args.search);
    }
}
