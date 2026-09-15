//! filetype - 快速文件类型检测(magic number)
//! 纯 Rust 读取文件头, 不再依赖 xxd/stat/bc

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "filetype",
    version,
    about = "快速文件类型检测(magic number)",
    long_about = "用法: filetype <file>...\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 要检测的文件(可多个)
    #[arg(value_name = "FILE", required = true)]
    files: Vec<PathBuf>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

const MAGIC_TABLE: &[(&[u8], &str)] = &[
    (&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a], "PNG image"),
    (&[0xff, 0xd8, 0xff], "JPEG image"),
    (&[b'G', b'I', b'F', b'8'], "GIF image"),
    (&[b'B', b'M'], "BMP image"),
    (&[b'P', b'K', 0x03, 0x04], "ZIP archive / Office doc"),
    (&[b'P', b'K', 0x05, 0x06], "ZIP archive (empty)"),
    (&[0x1f, 0x8b], "GZIP compressed"),
    (&[b'B', b'Z', b'h'], "BZIP2 compressed"),
    (&[0xfd, b'7', b'z', b'X', b'Z', 0x00], "XZ compressed"),
    (&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], "7-Zip archive"),
    (&[b'R', b'a', b'r', b'!', 0x1a, 0x07], "RAR archive"),
    (&[b'%', b'P', b'D', b'F'], "PDF document"),
    (&[0xd0, 0xcf, 0x11, 0xe0], "OLE2 (Office 97-2003)"),
    (
        &[b'S', b'Q', b'L', b'i', b't', b'e', b' ', b'f'],
        "SQLite database",
    ),
    (
        &[0x00, 0x00, 0x00, 0x1c, b'f', b't', b'y', b'p'],
        "MP4/MOV video",
    ),
    (
        &[0x00, 0x00, 0x00, 0x18, b'f', b't', b'y', b'p'],
        "MP4/MOV video",
    ),
    (&[b'R', b'I', b'F', b'F'], "RIFF (WAV/AVI)"),
    (&[b'I', b'I', 0x2a, 0x00], "TIFF image (LE)"),
    (&[b'M', b'M', 0x00, 0x2a], "TIFF image (BE)"),
    (&[0x7f, b'E', b'L', b'F'], "ELF executable"),
    (&[b'M', b'Z'], "PE/COFF (Windows)"),
    (&[0xca, 0xfe, 0xba, 0xbe], "Java class / Mach-O fat"),
    (&[0xca, 0xfe, 0xfa, 0xbe], "Java class / Mach-O fat"),
    (&[b'f', b'L', b'a', b'C'], "FLAC audio"),
    (&[b'O', b'g', b'g', b'S'], "OGG container"),
    (&[0x28, 0xb5, 0x2f, 0xfd], "Zstandard compressed"),
    (&[b'L', b'Z', b'I', b'P'], "LZIP compressed"),
];

#[derive(Serialize)]
struct FileInfo {
    file: String,
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_human: Option<String>,
}

#[derive(Serialize)]
struct Report {
    files: Vec<FileInfo>,
}

fn trunc1(v: f64) -> f64 {
    (v * 10.0).floor() / 10.0
}

fn human_size(size: u64) -> String {
    if size > 1_048_576 {
        format!("{:.1} MB", trunc1(size as f64 / 1_048_576.0))
    } else if size > 1024 {
        format!("{:.1} KB", trunc1(size as f64 / 1024.0))
    } else {
        format!("{size} B")
    }
}

fn detect(magic: &[u8]) -> Option<&'static str> {
    MAGIC_TABLE
        .iter()
        .find(|(m, _)| magic.starts_with(m))
        .map(|(_, d)| *d)
}

fn is_text(sample: &[u8]) -> bool {
    if sample.is_empty() {
        return false;
    }
    let printable = sample
        .iter()
        .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b))
        .count();
    printable > sample.len() * 90 / 100
}

fn analyze(path: &Path) -> FileInfo {
    let file = path.display().to_string();
    let meta = match std::fs::metadata(path) {
        Ok(m) if m.is_file() => m,
        _ => {
            return FileInfo {
                file,
                exists: false,
                file_type: None,
                size: None,
                size_human: None,
            }
        }
    };
    let size = meta.len();
    let mut sample = Vec::new();
    let _ = File::open(path).and_then(|f| f.take(512).read_to_end(&mut sample));
    let magic = &sample[..sample.len().min(16)];
    let file_type = detect(magic)
        .map(|s| s.to_string())
        .or_else(|| is_text(&sample).then(|| "Text file".to_string()))
        .unwrap_or_else(|| "Unknown".to_string());
    FileInfo {
        file,
        exists: true,
        file_type: Some(file_type),
        size: Some(size),
        size_human: Some(human_size(size)),
    }
}

fn pad(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - s.len()))
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let files: Vec<FileInfo> = args.files.iter().map(|p| analyze(p)).collect();
    let found = files.iter().filter(|f| f.exists).count();
    let report = Report { files };

    out.emit(
        || {
            println!("{}", "=== File Type Detection ===".bold());
            for f in &report.files {
                if f.exists {
                    println!(
                        "  {} {} ({})",
                        pad(&f.file, 30).green(),
                        pad(f.file_type.as_deref().unwrap_or(""), 25).cyan(),
                        f.size_human.as_deref().unwrap_or("?")
                    );
                } else {
                    println!("  {}: {}", f.file, "not found".red());
                }
            }
        },
        &report,
    );

    finish(if found == 0 {
        exit::NO_RESULT
    } else {
        exit::OK
    })
}
