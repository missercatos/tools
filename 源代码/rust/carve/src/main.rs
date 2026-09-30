//! carve - 文件雕刻: 从二进制转储中恢复内嵌文件

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "carve",
    version,
    about = "文件雕刻: 从二进制转储中恢复内嵌文件",
    long_about = "扫描常见文件签名(PNG/JPEG/ZIP/PDF/ELF...)并雕刻输出。\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标文件
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// 输出目录 (默认 <文件名>_carved)
    #[arg(short, long)]
    output_dir: Option<PathBuf>,

    /// 同时搜索 ZIP (兼容保留)
    #[arg(long)]
    zip: bool,

    /// 搜索全部已知签名 (兼容保留)
    #[arg(long)]
    all: bool,

    /// 仅列出, 不提取
    #[arg(long)]
    list: bool,

    /// 最小文件大小
    #[arg(long, default_value = "16")]
    min_size: usize,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct CarvedFile {
    offset: usize,
    kind: String,
    size: usize,
    preview: String,
    path: Option<String>,
}

#[derive(Serialize)]
struct Report {
    file: String,
    size: usize,
    count: usize,
    output_dir: Option<String>,
    files: Vec<CarvedFile>,
}

struct Signature {
    name: &'static str,
    magic: &'static [u8],
    end: Option<&'static [u8]>,
    max_size: usize,
}

fn get_signatures() -> Vec<Signature> {
    vec![
        Signature { name: "PNG", magic: b"\x89PNG\r\n\x1a\n", end: Some(b"IEND"), max_size: 100_000_000 },
        Signature { name: "JPEG", magic: b"\xff\xd8\xff", end: Some(b"\xff\xd9"), max_size: 50_000_000 },
        Signature { name: "GIF", magic: b"GIF8", end: Some(b"\x00\x3b"), max_size: 50_000_000 },
        Signature { name: "ZIP", magic: b"PK\x03\x04", end: None, max_size: 100_000_000 },
        Signature { name: "PDF", magic: b"%PDF", end: Some(b"%%EOF"), max_size: 100_000_000 },
        Signature { name: "ELF", magic: b"\x7fELF", end: None, max_size: 50_000_000 },
        Signature { name: "PE", magic: b"MZ", end: None, max_size: 50_000_000 },
        Signature { name: "GZIP", magic: b"\x1f\x8b", end: None, max_size: 100_000_000 },
        Signature { name: "BZIP2", magic: b"BZh", end: None, max_size: 100_000_000 },
        Signature { name: "7Z", magic: b"7z\xbc\xaf\x27\x1c", end: None, max_size: 100_000_000 },
        Signature { name: "RAR", magic: b"Rar!\x1a\x07", end: None, max_size: 100_000_000 },
        Signature { name: "SQLite", magic: b"SQLite format 3", end: None, max_size: 1_000_000_000 },
        Signature { name: "PCAP", magic: b"\xd4\xc3\xb2\xa1", end: None, max_size: 500_000_000 },
        Signature { name: "TIFF", magic: b"II\x2a\x00", end: None, max_size: 100_000_000 },
        Signature { name: "FLAC", magic: b"fLaC", end: None, max_size: 100_000_000 },
        Signature { name: "OGG", magic: b"OggS", end: None, max_size: 100_000_000 },
    ]
}

fn carve_file(data: &[u8], sig: &Signature, start: usize) -> Option<Vec<u8>> {
    if let Some(end_magic) = sig.end {
        let search_start = start + sig.magic.len();
        if search_start >= data.len() {
            return None;
        }

        for i in search_start..data.len().saturating_sub(end_magic.len()) {
            if &data[i..i + end_magic.len()] == end_magic {
                let end = i + end_magic.len();
                if end - start >= sig.max_size {
                    return None;
                }
                return Some(data[start..end].to_vec());
            }
        }

        let max_search = (start + sig.max_size).min(data.len());
        if max_search > start {
            return Some(data[start..max_search].to_vec());
        }
    } else {
        let end = (start + sig.max_size).min(data.len());
        return Some(data[start..end].to_vec());
    }
    None
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));
    let _ = (args.zip, args.all);

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("cannot read {}: {e}", args.file.display()));
            return finish(exit::ERROR);
        }
    };

    let sigs = get_signatures();
    let mut found: Vec<(usize, &'static str, Vec<u8>)> = Vec::new();

    for sig in &sigs {
        let mut i = 0;
        while i + sig.magic.len() <= data.len() {
            if &data[i..i + sig.magic.len()] == sig.magic {
                if let Some(carved) = carve_file(&data, sig, i) {
                    if carved.len() >= args.min_size {
                        found.push((i, sig.name, carved));
                    }
                }
                i += sig.magic.len();
            } else {
                i += 1;
            }
        }
    }

    let outdir = args.output_dir.clone().unwrap_or_else(|| {
        let stem = args.file.file_stem().unwrap_or_default().to_string_lossy();
        PathBuf::from(format!("{}_carved", stem))
    });

    let write_files = !args.list && !found.is_empty();
    if write_files {
        fs::create_dir_all(&outdir).ok();
    }

    let mut files: Vec<CarvedFile> = Vec::with_capacity(found.len());
    for (offset, name, carved) in &found {
        let preview: String = carved
            .iter()
            .take(32)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        let path = if write_files {
            let filename = format!("{}/{:08x}_{}.bin", outdir.display(), offset, name);
            fs::write(&filename, carved).ok();
            Some(filename)
        } else {
            None
        };
        files.push(CarvedFile {
            offset: *offset,
            kind: name.to_string(),
            size: carved.len(),
            preview,
            path,
        });
    }

    let report = Report {
        file: args.file.display().to_string(),
        size: data.len(),
        count: files.len(),
        output_dir: if write_files {
            Some(outdir.display().to_string())
        } else {
            None
        },
        files,
    };

    out.emit(
        || {
            println!("{}", format!("=== {} ===", report.file).bold());
            println!("  Size: {} bytes", report.size);

            if report.files.is_empty() {
                println!("\n  {} No files found", "warning:".yellow());
                return;
            }

            println!(
                "\n{}",
                format!("=== Found {} file(s) ===", report.files.len()).bold()
            );

            for f in &report.files {
                println!(
                    "  {} 0x{:08x} ({:>8} bytes)  {}",
                    f.kind.green().bold(),
                    f.offset,
                    f.size,
                    f.preview
                );
                if let Some(path) = &f.path {
                    println!("    -> {}", path);
                }
            }

            if let Some(dir) = &report.output_dir {
                println!("\n  Output: {}", dir);
            }
        },
        &report,
    );

    if report.files.is_empty() {
        finish(exit::NO_RESULT)
    } else {
        finish(exit::OK)
    }
}
