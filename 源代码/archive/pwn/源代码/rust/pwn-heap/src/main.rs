use clap::Parser;
use colored::*;
use goblin::Object;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pwn-heap", about = "堆元数据解析 (分析堆块/ bin / tcache)")]
struct Args {
    /// 内存dump文件(core dump或dd导出的堆)
    file: PathBuf,

    /// 堆起始地址 (十六进制)
    #[arg(short = 'b', long)]
    base: Option<String>,

    /// 分析堆块数量
    #[arg(short = 'n', long, default_value = "20")]
    count: usize,

    /// 显示所有chunk (包括free)
    #[arg(long)]
    all: bool,

    /// 显示bin信息
    #[arg(long)]
    bins: bool,

    /// 显示tcache信息
    #[arg(long)]
    tcache: bool,

    /// 解析lib ELF的malloc定义 (获取chunk layout)
    #[arg(long)]
    libc: Option<PathBuf>,

    /// 从地址开始解析 (十六进制)
    #[arg(short, long)]
    addr: Option<String>,

    /// JSON输出
    #[arg(long)]
    json: bool,
}

const CHUNK_HDR_SIZE: usize = 0x10;  // 64-bit: prev_size(8) + size(8)
const SIZE_MASK: u64 = 0xfffffffffffffff8;
const PREV_INUSE: u64 = 1;
const IS_MMAPPED: u64 = 2;
const NON_MAIN_ARENA: u64 = 4;

#[derive(Debug, Clone)]
struct ChunkHeader {
    prev_size: u64,
    size: u64,
    prev_inuse: bool,
    is_mmapped: bool,
    non_main_arena: bool,
    real_size: u64,
}

impl ChunkHeader {
    fn parse(data: &[u8], offset: usize) -> Option<Self> {
        if offset + CHUNK_HDR_SIZE > data.len() {
            return None;
        }
        let prev_size = u64::from_le_bytes(data[offset..offset+8].try_into().ok()?);
        let size = u64::from_le_bytes(data[offset+8..offset+16].try_into().ok()?);
        
        let real_size = size & SIZE_MASK;
        let prev_inuse = (size & PREV_INUSE) != 0;
        let is_mmapped = (size & IS_MMAPPED) != 0;
        let non_main_arena = (size & NON_MAIN_ARENA) != 0;
        
        Some(ChunkHeader {
            prev_size,
            size,
            prev_inuse,
            is_mmapped,
            non_main_arena,
            real_size,
        })
    }
    
    fn fd_offset(&self) -> usize {
        CHUNK_HDR_SIZE  // fd 在 chunk data 起始处
    }
    
    fn bk_offset(&self) -> usize {
        CHUNK_HDR_SIZE + 8  // bk 在 fd 之后
    }
}

fn parse_chunks(data: &[u8], base_addr: u64, count: usize, show_all: bool) -> Vec<(u64, ChunkHeader, Vec<u64>)> {
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    let mut addr = base_addr;
    
    while chunks.len() < count && offset + CHUNK_HDR_SIZE <= data.len() {
        let header = match ChunkHeader::parse(data, offset) {
            Some(h) => h,
            None => break,
        };
        
        // 读取fd/bk指针 (如果是free chunk)
        let mut ptrs = Vec::new();
        if !header.prev_inuse && header.real_size >= 0x20 {
            let data_start = offset + CHUNK_HDR_SIZE;
            if data_start + 16 <= data.len() {
                let fd = u64::from_le_bytes(data[data_start..data_start+8].try_into().unwrap_or([0;8]));
                let bk = u64::from_le_bytes(data[data_start+8..data_start+16].try_into().unwrap_or([0;8]));
                ptrs.push(fd);
                ptrs.push(bk);
            }
        }
        
        let next_size = header.real_size;
        if show_all || !header.prev_inuse {
            chunks.push((addr, header, ptrs));
        }
        
        let next_offset = CHUNK_HDR_SIZE + next_size as usize;
        if next_offset == 0 || offset + next_offset > data.len() {
            break;
        }
        offset += next_offset;
        addr += next_offset as u64;
    }
    
    chunks
}

fn format_flags(chunk: &ChunkHeader) -> String {
    let mut flags = String::new();
    if chunk.prev_inuse { flags.push_str("P"); } else { flags.push('-'); }
    if chunk.is_mmapped { flags.push_str("M"); } else { flags.push('-'); }
    if chunk.non_main_arena { flags.push_str("A"); } else { flags.push('-'); }
    flags
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
    
    let base_addr = args.base.as_ref()
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
        .unwrap_or(0);
    
    println!("{}", format!("=== Heap analysis: {} ===", args.file.display()).bold());
    println!("  File size: {} bytes", data.len());
    if base_addr > 0 {
        println!("  Base addr: 0x{:x}", base_addr);
    }
    
    // 检查是否为ELF (尝试获取段信息)
    if let Ok(Object::Elf(elf)) = Object::parse(&data) {
        println!("\n{}", "=== ELF info ===".bold());
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                let rw = if ph.p_flags & goblin::elf::program_header::PF_W != 0 { "RW" } else { "R" };
                println!("  LOAD 0x{:016x} - 0x{:016x} ({})",
                    ph.p_vaddr, ph.p_vaddr + ph.p_filesz, rw);
            }
        }
    }
    
    if args.addr.is_some() || base_addr > 0 || args.file.extension().map_or(false, |e| e == "bin" || e == "dump") {
        // 解析堆块
        let actual_base = args.addr.as_ref()
            .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(base_addr))
            .unwrap_or(base_addr);
        
        let chunks = parse_chunks(&data, actual_base, args.count, args.all);
        
        println!("\n{}", format!("=== Heap Chunks ({} found) ===", chunks.len()).bold());
        println!("  {:<18} {:<18} {:<8} {:<8} {:<5} {:<8} {:<10}",
            "Addr", "Prev", "Size", "Real", "Flag", "Status", "FD/BK");
        println!("  {}", "-".repeat(80));
        
        for (addr, header, ptrs) in &chunks {
            let status = if header.prev_inuse {
                "inuse".normal()
            } else if header.is_mmapped {
                "mmap".yellow()
            } else {
                "free".red()
            };
            
            let ptrs_str = if ptrs.len() >= 2 {
                format!("fd=0x{:x} bk=0x{:x}", ptrs[0], ptrs[1])
            } else if header.prev_inuse {
                format!("data[0..{}]", header.real_size.saturating_sub(CHUNK_HDR_SIZE as u64))
            } else {
                String::new()
            };
            
            println!("  0x{:016x} 0x{:016x} {:<8} {:<8} {:<5} {:<8} {}",
                addr, header.prev_size, header.size, header.real_size,
                format_flags(header), status, ptrs_str);
        }
        
        // 显示统计
        let total_size: u64 = chunks.iter().map(|(_, h, _)| h.real_size).sum();
        let inuse_count = chunks.iter().filter(|(_, h, _)| h.prev_inuse).count();
        let free_count = chunks.len() - inuse_count;
        
        println!("\n{}", "=== Statistics ===".bold());
        println!("  Total chunks: {}", chunks.len());
        println!("  In-use:       {} ({:.1}%)", inuse_count,
            if chunks.is_empty() { 0.0 } else { inuse_count as f64 / chunks.len() as f64 * 100.0 });
        println!("  Free:         {} ({:.1}%)", free_count,
            if chunks.is_empty() { 0.0 } else { free_count as f64 / chunks.len() as f64 * 100.0 });
        println!("  Total size:   0x{:x} ({} bytes)", total_size, total_size);
    }
    
    if args.tcache {
        println!("\n{}", "=== Tcache ===".bold());
        println!("  (需要gdb/pwndbg: tcache 或 heap tcache)");
        println!("  tcache 每个 bin 最多 7 个 chunk, 大小范围 0x20 - 0x410");
    }
    
    if args.bins {
        println!("\n{}", "=== Bins ===".bold());
        println!("  (需要gdb/pwndbg: bins 或 heap bins)");
        println!("  fastbin:  0x20 - 0x80 (LIFO)");
        println!("  unsorted: 所有大小 (FIFO)");
        println!("  smallbin: 0x20 - 0x400 (FIFO)");
        println!("  largebin: 0x400+ (FIFO, 按大小排序)");
    }
    
    println!("\n{}", "Tip: 使用 gdb + pwndbg 进行动态堆分析".dimmed());
    println!("  pwndbg> heap");
    println!("  pwndbg> heap bins");
    println!("  pwndbg> tcache");
    println!("  pwndbg> vis_heap_chunks");
}
