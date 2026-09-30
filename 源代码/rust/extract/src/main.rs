//! extract - 嵌套压缩包自动解压
//! zip/tar/gz/bz2/xz 纯 Rust 处理; 7z/rar 回退调用系统 7z/7za/unrar

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const MAX_DEPTH: u32 = 50;

#[derive(Parser, Debug)]
#[command(
    name = "extract",
    version,
    about = "嵌套压缩包自动解压",
    long_about = "支持: zip, tar, gz, bz2, xz, 7z, rar (含嵌套)\n\n用法: extract <archive> [outdir]\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 压缩包文件
    #[arg(value_name = "ARCHIVE")]
    archive: PathBuf,

    /// 输出目录 (默认 <文件名>_extracted)
    #[arg(value_name = "OUTDIR")]
    outdir: Option<PathBuf>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct ExtractItem {
    archive: String,
    outdir: String,
    depth: u32,
}

#[derive(Serialize)]
struct FailItem {
    archive: String,
    depth: u32,
    error: String,
}

#[derive(Serialize)]
struct Report {
    file: String,
    outdir: String,
    depth: u32,
    extracted: Vec<ExtractItem>,
    failed: Vec<FailItem>,
    files: Vec<String>,
    total_files: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Zip,
    Tar,
    Gzip,
    Bzip2,
    Xz,
    SevenZ,
    Rar,
}

fn default_outdir(file: &Path) -> PathBuf {
    let name = file
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("archive");
    let stem = match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    };
    PathBuf::from(format!("{stem}_extracted"))
}

fn is_archive_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar.gz", ".tar.bz2",
        ".tar.xz",
    ]
    .iter()
    .any(|e| n.ends_with(e))
}

fn kind_from_name(name: &str) -> Option<Kind> {
    let n = name.to_ascii_lowercase();
    if n.ends_with(".zip") {
        Some(Kind::Zip)
    } else if n.ends_with(".tar") {
        Some(Kind::Tar)
    } else if n.ends_with(".gz") || n.ends_with(".tgz") {
        Some(Kind::Gzip)
    } else if n.ends_with(".bz2") || n.ends_with(".tbz2") {
        Some(Kind::Bzip2)
    } else if n.ends_with(".xz") || n.ends_with(".txz") {
        Some(Kind::Xz)
    } else if n.ends_with(".7z") {
        Some(Kind::SevenZ)
    } else if n.ends_with(".rar") {
        Some(Kind::Rar)
    } else {
        None
    }
}

fn detect(path: &Path) -> Option<Kind> {
    let mut buf = [0u8; 512];
    let n = File::open(path)
        .and_then(|mut f| f.read(&mut buf))
        .unwrap_or(0);
    let b = &buf[..n];
    if b.len() >= 4
        && (&b[..4] == b"PK\x03\x04" || &b[..4] == b"PK\x05\x06" || &b[..4] == b"PK\x07\x08")
    {
        return Some(Kind::Zip);
    }
    if b.len() >= 2 && b[0] == 0x1f && b[1] == 0x8b {
        return Some(Kind::Gzip);
    }
    if b.len() >= 3 && &b[..3] == b"BZh" {
        return Some(Kind::Bzip2);
    }
    if b.len() >= 6 && &b[..6] == b"\xfd7zXZ\x00" {
        return Some(Kind::Xz);
    }
    if b.len() >= 6 && &b[..6] == b"7z\xbc\xaf\x27\x1c" {
        return Some(Kind::SevenZ);
    }
    if b.len() >= 6 && &b[..6] == b"Rar!\x1a\x07" {
        return Some(Kind::Rar);
    }
    if b.len() >= 262 && &b[257..262] == b"ustar" {
        return Some(Kind::Tar);
    }
    path.file_name()
        .and_then(|s| s.to_str())
        .and_then(kind_from_name)
}

fn extract_zip(path: &Path, out: &Path) -> Result<(), String> {
    let f = File::open(path).map_err(|e| format!("打开失败: {e}"))?;
    let mut archive = zip::ZipArchive::new(f).map_err(|e| format!("zip 解析失败: {e}"))?;
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index_decrypt(i, b"")
            .map_err(|e| format!("读取条目失败: {e}"))?;
        let name = match entry.enclosed_name() {
            Some(p) => p.to_path_buf(),
            None => return Err(format!("非法路径: {}", entry.name())),
        };
        let target = out.join(&name);
        if entry.is_dir() {
            fs::create_dir_all(&target).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut w = File::create(&target).map_err(|e| e.to_string())?;
        io::copy(&mut entry, &mut w).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Some(mode) = entry.unix_mode() {
                let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

fn strip_compress_suffix(name: &str, kind: Kind) -> String {
    let suffix = match kind {
        Kind::Gzip => ".gz",
        Kind::Bzip2 => ".bz2",
        Kind::Xz => ".xz",
        _ => return name.to_string(),
    };
    match name.strip_suffix(suffix) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => name.to_string(),
    }
}

fn extract_compressed(path: &Path, out: &Path, kind: Kind) -> Result<(), String> {
    let tmp = out.join(format!(".extract.tmp.{}", std::process::id()));
    let f = File::open(path).map_err(|e| format!("打开失败: {e}"))?;
    let mut reader: Box<dyn Read> = match kind {
        Kind::Gzip => Box::new(flate2::read::GzDecoder::new(f)),
        Kind::Bzip2 => Box::new(bzip2::read::BzDecoder::new(f)),
        Kind::Xz => Box::new(xz2::read::XzDecoder::new(f)),
        _ => Box::new(f),
    };
    let mut tmpf = File::create(&tmp).map_err(|e| format!("写入临时文件失败: {e}"))?;
    io::copy(&mut reader, &mut tmpf).map_err(|e| format!("解压失败: {e}"))?;
    drop(tmpf);
    let tf = File::open(&tmp).map_err(|e| e.to_string())?;
    if tar::Archive::new(tf).unpack(out).is_ok() {
        let _ = fs::remove_file(&tmp);
        return Ok(());
    }
    let base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let target = out.join(strip_compress_suffix(base, kind));
    fs::rename(&tmp, &target).map_err(|e| format!("写入失败: {e}"))?;
    Ok(())
}

fn extract_tar(path: &Path, out: &Path) -> Result<(), String> {
    let f = File::open(path).map_err(|e| format!("打开失败: {e}"))?;
    tar::Archive::new(f)
        .unpack(out)
        .map_err(|e| format!("tar 解压失败: {e}"))
}

fn run_tool(cmd: &str, args: &[String]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn extract_7z(path: &Path, out: &Path) -> Result<(), String> {
    let args = vec![
        "x".to_string(),
        path.display().to_string(),
        format!("-o{}", out.display()),
        "-y".to_string(),
    ];
    for cmd in ["7z", "7za"] {
        if run_tool(cmd, &args) {
            return Ok(());
        }
    }
    Err("7z/7za 不可用或解压失败".to_string())
}

fn extract_rar(path: &Path, out: &Path) -> Result<(), String> {
    let unrar_args = vec![
        "x".to_string(),
        path.display().to_string(),
        format!("{}/", out.display()),
        "-y".to_string(),
    ];
    if run_tool("unrar", &unrar_args) {
        return Ok(());
    }
    extract_7z(path, out)
}

fn extract_file(path: &Path, out: &Path) -> Result<(), String> {
    let kind = detect(path).ok_or_else(|| "未知压缩格式".to_string())?;
    match kind {
        Kind::Zip => extract_zip(path, out),
        Kind::Tar => extract_tar(path, out),
        Kind::Gzip | Kind::Bzip2 | Kind::Xz => extract_compressed(path, out, kind),
        Kind::SevenZ => extract_7z(path, out),
        Kind::Rar => extract_rar(path, out),
    }
}

fn find_archives(root: &Path) -> Vec<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    let mut found = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                    if is_archive_name(name) {
                        found.push(p);
                    }
                }
            }
        }
    }
    found.sort();
    found
}

fn list_files(root: &Path) -> Vec<String> {
    let mut stack = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let p = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() => stack.push(p),
                Ok(t) if t.is_file() => files.push(p.display().to_string()),
                _ => {}
            }
        }
    }
    files.sort();
    files
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let file = args.archive.clone();
    if !file.is_file() {
        out.error(&format!("文件不存在: {}", file.display()));
        return finish(exit::ERROR);
    }
    let outdir = args.outdir.clone().unwrap_or_else(|| default_outdir(&file));
    if let Err(e) = fs::create_dir_all(&outdir) {
        out.error(&format!("无法创建输出目录 {}: {e}", outdir.display()));
        return finish(exit::ERROR);
    }

    out.info(&format!(
        "{}",
        format!("[*] Extracting: {}", file.display()).bold()
    ));
    out.info(&format!("    Output: {}", outdir.display()));

    if let Some(name) = file.file_name() {
        let _ = fs::copy(&file, outdir.join(name));
    }

    let mut extracted: Vec<ExtractItem> = Vec::new();
    let mut failed: Vec<FailItem> = Vec::new();
    let mut failed_paths: HashSet<PathBuf> = HashSet::new();
    let mut depth = 0u32;

    while depth < MAX_DEPTH {
        let archives = find_archives(&outdir);
        let mut found = false;
        for archive in archives {
            if failed_paths.contains(&archive) {
                continue;
            }
            let extract_dir = PathBuf::from(format!("{}_extracted", archive.display()));
            let _ = fs::create_dir_all(&extract_dir);
            match extract_file(&archive, &extract_dir) {
                Ok(()) => {
                    out.info(&format!(
                        "  {} Depth {}: {} -> {}",
                        "[+]".green(),
                        depth,
                        archive
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        extract_dir.display()
                    ));
                    let _ = fs::remove_file(&archive);
                    extracted.push(ExtractItem {
                        archive: archive.display().to_string(),
                        outdir: extract_dir.display().to_string(),
                        depth,
                    });
                    found = true;
                }
                Err(e) => {
                    out.info(&format!(
                        "  {} Depth {}: Failed to extract: {}",
                        "[!]".yellow(),
                        depth,
                        archive
                            .file_name()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default()
                    ));
                    let _ = fs::remove_dir(&extract_dir);
                    failed_paths.insert(archive.clone());
                    failed.push(FailItem {
                        archive: archive.display().to_string(),
                        depth,
                        error: e,
                    });
                }
            }
        }
        if !found {
            break;
        }
        depth += 1;
    }

    let files = list_files(&outdir);
    let total_files = files.len();
    let report = Report {
        file: file.display().to_string(),
        outdir: outdir.display().to_string(),
        depth,
        extracted,
        failed,
        files,
        total_files,
    };

    out.emit(
        || {
            println!("\n{} Extracted to: {}", "[*] Done.".bold(), report.outdir);
            println!("    Depth: {}", report.depth);
            println!("    Files:");
            for f in report.files.iter().take(20) {
                println!("      {f}");
            }
            if report.total_files > 20 {
                println!("      ... and {} more", report.total_files - 20);
            }
        },
        &report,
    );

    if report.extracted.is_empty() {
        finish(exit::NO_RESULT)
    } else {
        finish(exit::OK)
    }
}
