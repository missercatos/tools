use clap::Parser;
use colored::*;
use goblin::elf::Elf;
use goblin::Object;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pwn-one", about = "one_gadget查找 (在libc/ELF中搜索execve /bin/sh gadget)")]
struct Args {
    /// ELF/libc文件路径
    file: PathBuf,

    /// 最大搜索深度 (默认: 在所有代码段搜索)
    #[arg(short = 'n', long, default_value = "100")]
    max_results: usize,

    /// 搜索"/bin/sh"字符串偏移
    #[arg(long)]
    binsh: bool,

    /// 搜索execve syscall (0x3b on x86_64, 0xb on x86)
    #[arg(long)]
    syscall: bool,

    /// 搜索所有可疑gadget
    #[arg(long)]
    all: bool,

    /// 显示详细信息
    #[arg(short, long)]
    verbose: bool,

    /// JSON输出
    #[arg(long)]
    json: bool,
}

/// 搜索gadget的结果
struct Gadget {
    addr: u64,
    description: String,
    constraints: Vec<String>,
    confidence: u8,  // 0-100
}

fn find_binsh_string(elf: &Elf, data: &[u8]) -> Vec<u64> {
    let mut addrs = Vec::new();
    let binsh = b"/bin/sh";
    let binsh2 = b"/bin/sh\0";
    
    // 在只读数据段搜索
    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            if name == ".rodata" || name == ".data" || name == ".data.rel.ro" {
                let start = sh.sh_offset as usize;
                let end = start + sh.sh_size as usize;
                if end <= data.len() {
                    let section = &data[start..end];
                    for i in 0..section.len().saturating_sub(8) {
                        if &section[i..i+7] == binsh || &section[i..i+8] == binsh2 {
                            addrs.push(sh.sh_addr + i as u64);
                        }
                    }
                }
            }
        }
    }
    
    // 如果在section中没找到,搜索整个文件
    if addrs.is_empty() {
        for i in 0..data.len().saturating_sub(8) {
            if &data[i..i+7] == binsh || &data[i..i+8] == binsh2 {
                // 粗略转换 file offset -> virtual addr
                for ph in &elf.program_headers {
                    if ph.p_type == goblin::elf::program_header::PT_LOAD {
                        if (i as u64) >= ph.p_offset && (i as u64) < ph.p_offset + ph.p_filesz {
                            let vaddr = ph.p_vaddr + (i as u64 - ph.p_offset);
                            addrs.push(vaddr);
                            break;
                        }
                    }
                }
            }
        }
    }
    
    addrs
}

fn search_gadgets(elf: &Elf, data: &[u8], max_results: usize, _verbose: bool) -> Vec<Gadget> {
    let mut gadgets = Vec::new();
    
    // 获取 /bin/sh 地址
    let binsh_addrs = find_binsh_string(elf, data);
    
    // 搜索代码段中的模式
    for ph in &elf.program_headers {
        if ph.p_type != goblin::elf::program_header::PT_LOAD { continue; }
        if ph.p_flags & goblin::elf::program_header::PF_X == 0 { continue; }
        
        let start = ph.p_offset as usize;
        let end = start + ph.p_filesz as usize;
        if end > data.len() { continue; }
        
        let code = &data[start..end];
        let vbase = ph.p_vaddr;
        
        // 搜索 x86_64 指令模式
        for i in 0..code.len().saturating_sub(15) {
            if gadgets.len() >= max_results { break; }
            
            let bytes = &code[i..std::cmp::min(i + 15, code.len())];
            let vaddr = vbase + i as u64;
            
            // 模式1: lea rdi, [rip+OFFSET] (48 8d 3d XX XX XX XX)
            // 这是加载字符串地址的常见方式
            if bytes.len() >= 7 && bytes[0] == 0x48 && bytes[1] == 0x8d && bytes[2] == 0x3d {
                let offset = i32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]) as i64;
                let target = (vaddr as i64 + 7 + offset) as u64;
                
                // 检查是否指向 /bin/sh
                if binsh_addrs.contains(&target) {
                    // 检查后续是否有 syscall 或 call
                    let rest = &code[i+7..std::cmp::min(i+30, code.len())];
                    let has_syscall = rest.windows(2).any(|w| w == [0x0f, 0x05]);
                    let has_int80 = rest.windows(2).any(|w| w == [0xcd, 0x80]);
                    let has_call = rest.iter().any(|&b| b == 0xe8 || b == 0xff);
                    
                    let mut constraints = Vec::new();
                    if has_call {
                        constraints.push("需要控制调用目标 (call rax等)".to_string());
                    }
                    if !has_syscall && !has_int80 {
                        constraints.push("无直接syscall, 需要间接调用".to_string());
                    }
                    
                    gadgets.push(Gadget {
                        addr: vaddr,
                        description: format!("lea rdi, [rip+0x{:x}] ; -> \"{}\"",
                            offset, "/bin/sh"),
                        constraints,
                        confidence: if has_syscall || has_int80 { 90 } else { 60 },
                    });
                }
            }
            
            // 模式2: 直接 syscall (0f 05) 前有 execve 号
            if bytes.len() >= 2 && bytes[0] == 0x0f && bytes[1] == 0x05 {
                // 检查前面的指令: mov eax, 0x3b (b8 3b 00 00 00)
                if i >= 5 && code[i-5] == 0xb8 && code[i-4] == 0x3b {
                    let mut constraints = Vec::new();
                    constraints.push("需要: rdi=/bin/sh, rsi=NULL, rdx=NULL".to_string());
                    gadgets.push(Gadget {
                        addr: vaddr - 5,
                        description: "mov eax, 0x3b ; syscall (execve)".to_string(),
                        constraints,
                        confidence: 70,
                    });
                }
            }
            
            // 模式3: call rax (ff d0) - 常见的一跳
            if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xd0 {
                gadgets.push(Gadget {
                    addr: vaddr,
                    description: "call rax".to_string(),
                    constraints: vec!["需要rax指向有效gadget/函数".to_string()],
                    confidence: 40,
                });
            }
            
            // 模式4: ret (c3) - 仅在特殊上下文
            // 跳过,太多误报
        }
    }
    
    // 按置信度排序
    gadgets.sort_by(|a, b| b.confidence.cmp(&a.confidence));
    gadgets
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
    
    println!("{}", format!("=== one_gadget search: {} ===", args.file.display()).bold());
    
    if args.binsh || args.all {
        let binsh_addrs = find_binsh_string(&elf, &data);
        if binsh_addrs.is_empty() {
            println!("\n  {} \"/bin/sh\" string not found", "warning:".yellow());
        } else {
            println!("\n{}", "=== \"/bin/sh\" addresses ===".bold());
            for addr in &binsh_addrs {
                println!("  0x{:x}", addr);
            }
        }
    }
    
    if args.syscall || args.all {
        println!("\n{}", "=== execve syscalls ===".bold());
        for ph in &elf.program_headers {
            if ph.p_type != goblin::elf::program_header::PT_LOAD { continue; }
            if ph.p_flags & goblin::elf::program_header::PF_X == 0 { continue; }
            
            let start = ph.p_offset as usize;
            let end = start + ph.p_filesz as usize;
            if end > data.len() { continue; }
            let code = &data[start..end];
            
            for i in 0..code.len().saturating_sub(2) {
                if code[i] == 0x0f && code[i+1] == 0x05 {
                    // 检查前面的 mov eax, 0x3b (execve)
                    if i >= 5 && code[i-5] == 0xb8 && code[i-4] == 0x3b {
                        println!("  0x{:x}: syscall (execve)", ph.p_vaddr + i as u64);
                    }
                }
            }
        }
    }
    
    if !args.binsh && !args.syscall || args.all {
        let gadgets = search_gadgets(&elf, &data, args.max_results, args.verbose);
        
        if gadgets.is_empty() {
            println!("\n  {} No one_gadget found.", "warning:".yellow());
            println!("  Tip: 使用 one_gadget (gem install one_gadget) 获取更精确的结果");
        } else {
            println!("\n{}", "=== one_gadget candidates ===".bold());
            for (i, g) in gadgets.iter().enumerate() {
                let _conf_color = if g.confidence >= 80 { "green" }
                    else if g.confidence >= 50 { "yellow" }
                    else { "red" };
                
                println!("\n  {} 0x{:x} [{}% confidence]",
                    format!("gadget_{}:", i).bold(),
                    g.addr,
                    g.confidence);
                println!("    {}", g.description);
                if !g.constraints.is_empty() {
                    for c in &g.constraints {
                        println!("    {} {}", "constraint:".yellow(), c);
                    }
                }
                if args.verbose {
                    // 显示上下文
                    let offset = g.addr as usize;
                    // 粗略计算文件偏移
                    for ph in &elf.program_headers {
                        if ph.p_type == goblin::elf::program_header::PT_LOAD
                            && offset >= ph.p_vaddr as usize
                            && offset < (ph.p_vaddr + ph.p_filesz) as usize
                        {
                            let file_off = ph.p_offset as usize + (offset - ph.p_vaddr as usize);
                            let end = std::cmp::min(file_off + 16, data.len());
                            if end > file_off {
                                println!("    hex: {}", data[file_off..end].iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<Vec<_>>().join(" "));
                            }
                            break;
                        }
                    }
                }
            }
            println!("\n  Found {} candidate(s)", gadgets.len());
        }
    }
    
    println!("\n{}", "Tip: 安装 one_gadget (gem install one_gadget) 获取更精确的结果".dimmed());
}
