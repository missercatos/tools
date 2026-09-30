use clap::Parser;
use colored::*;
use common::{exit, finish, parse_hex, Mode, Out};
use goblin::Object;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

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
}

#[derive(Serialize)]
struct ChunkEntry {
    addr: u64,
    prev_size: u64,
    size: u64,
    real_size: u64,
    flags: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fd: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bk: Option<u64>,
}

#[derive(Serialize)]
struct Statistics {
    total_chunks: usize,
    inuse: usize,
    free: usize,
    total_size: u64,
}

#[derive(Serialize)]
struct ElfLoad {
    start: u64,
    end: u64,
    flags: String,
}

#[derive(Serialize)]
struct Report {
    file: String,
    file_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    base: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elf: Option<Vec<ElfLoad>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunks: Option<Vec<ChunkEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    statistics: Option<Statistics>,
    tcache: bool,
    bins: bool,
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

fn to_entry(addr: u64, header: &ChunkHeader, ptrs: &[u64]) -> ChunkEntry {
    let status = if header.prev_inuse {
        "inuse"
    } else if header.is_mmapped {
        "mmap"
    } else {
        "free"
    };
    ChunkEntry {
        addr,
        prev_size: header.prev_size,
        size: header.size,
        real_size: header.real_size,
        flags: format_flags(header),
        status: status.to_string(),
        fd: ptrs.first().copied(),
        bk: ptrs.get(1).copied(),
    }
}

fn collect_elf_loads(data: &[u8]) -> Option<Vec<ElfLoad>> {
    if let Ok(Object::Elf(elf)) = Object::parse(data) {
        Some(elf.program_headers.iter()
            .filter(|ph| ph.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|ph| {
                let rw = if ph.p_flags & goblin::elf::program_header::PF_W != 0 { "RW" } else { "R" };
                ElfLoad {
                    start: ph.p_vaddr,
                    end: ph.p_vaddr + ph.p_filesz,
                    flags: rw.to_string(),
                }
            })
            .collect())
    } else {
        None
    }
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

    let base_addr = match &args.base {
        Some(s) => match parse_hex(s) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        },
        None => 0,
    };

    let actual_base = match &args.addr {
        Some(s) => match parse_hex(s) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        },
        None => base_addr,
    };

    let elf_loads = collect_elf_loads(&data);

    let analyze = args.addr.is_some() || base_addr > 0
        || args.file.extension().map_or(false, |e| e == "bin" || e == "dump");

    let chunks = if analyze {
        let raw = parse_chunks(&data, actual_base, args.count, args.all);
        Some(raw.iter().map(|(addr, header, ptrs)| to_entry(*addr, header, ptrs)).collect::<Vec<_>>())
    } else {
        None
    };

    let statistics = chunks.as_ref().map(|chunks| {
        let inuse = chunks.iter().filter(|c| c.status == "inuse").count();
        Statistics {
            total_chunks: chunks.len(),
            inuse,
            free: chunks.len() - inuse,
            total_size: chunks.iter().map(|c| c.real_size).sum(),
        }
    });

    let report = Report {
        file: args.file.display().to_string(),
        file_size: data.len(),
        base: (base_addr > 0).then_some(base_addr),
        elf: elf_loads,
        chunks,
        statistics,
        tcache: args.tcache,
        bins: args.bins,
    };

    out.emit(
        || {
            println!("{}", format!("=== Heap analysis: {} ===", report.file).bold());
            println!("  File size: {} bytes", report.file_size);
            if let Some(base_addr) = report.base {
                println!("  Base addr: 0x{:x}", base_addr);
            }

            if let Some(loads) = &report.elf {
                println!("\n{}", "=== ELF info ===".bold());
                for l in loads {
                    println!("  LOAD 0x{:016x} - 0x{:016x} ({})", l.start, l.end, l.flags);
                }
            }

            if let Some(chunks) = &report.chunks {
                println!("\n{}", format!("=== Heap Chunks ({} found) ===", chunks.len()).bold());
                println!("  {:<18} {:<18} {:<8} {:<8} {:<5} {:<8} {:<10}",
                    "Addr", "Prev", "Size", "Real", "Flag", "Status", "FD/BK");
                println!("  {}", "-".repeat(80));

                for c in chunks {
                    let status = match c.status.as_str() {
                        "inuse" => "inuse".normal(),
                        "mmap" => "mmap".yellow(),
                        _ => "free".red(),
                    };

                    let ptrs_str = if let (Some(fd), Some(bk)) = (c.fd, c.bk) {
                        format!("fd=0x{:x} bk=0x{:x}", fd, bk)
                    } else if c.status == "inuse" {
                        format!("data[0..{}]", c.real_size.saturating_sub(CHUNK_HDR_SIZE as u64))
                    } else {
                        String::new()
                    };

                    println!("  0x{:016x} 0x{:016x} {:<8} {:<8} {:<5} {:<8} {}",
                        c.addr, c.prev_size, c.size, c.real_size,
                        c.flags, status, ptrs_str);
                }

                if let Some(stats) = &report.statistics {
                    let pct = |n: usize| {
                        if stats.total_chunks == 0 {
                            0.0
                        } else {
                            n as f64 / stats.total_chunks as f64 * 100.0
                        }
                    };
                    println!("\n{}", "=== Statistics ===".bold());
                    println!("  Total chunks: {}", stats.total_chunks);
                    println!("  In-use:       {} ({:.1}%)", stats.inuse, pct(stats.inuse));
                    println!("  Free:         {} ({:.1}%)", stats.free, pct(stats.free));
                    println!("  Total size:   0x{:x} ({} bytes)", stats.total_size, stats.total_size);
                }
            }

            if report.tcache {
                println!("\n{}", "=== Tcache ===".bold());
                println!("  (需要gdb/pwndbg: tcache 或 heap tcache)");
                println!("  tcache 每个 bin 最多 7 个 chunk, 大小范围 0x20 - 0x410");
            }

            if report.bins {
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
        },
        &report,
    );

    if out.json() {
        if report.tcache {
            out.info("=== Tcache ===\n  (需要gdb/pwndbg: tcache 或 heap tcache)\n  tcache 每个 bin 最多 7 个 chunk, 大小范围 0x20 - 0x410");
        }
        if report.bins {
            out.info("=== Bins ===\n  (需要gdb/pwndbg: bins 或 heap bins)\n  fastbin:  0x20 - 0x80 (LIFO)\n  unsorted: 所有大小 (FIFO)\n  smallbin: 0x20 - 0x400 (FIFO)\n  largebin: 0x400+ (FIFO, 按大小排序)");
        }
        out.info("Tip: 使用 gdb + pwndbg 进行动态堆分析\n  pwndbg> heap\n  pwndbg> heap bins\n  pwndbg> tcache\n  pwndbg> vis_heap_chunks");
    }

    if let Some(chunks) = &report.chunks {
        if chunks.is_empty() {
            return finish(exit::NO_RESULT);
        }
    }

    finish(exit::OK)
}
