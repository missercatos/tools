//! spectro - 音频频谱图生成
//! 优先 sox, 回退 ffmpeg (均通过外部命令调用)

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

#[derive(Parser, Debug)]
#[command(
    name = "spectro",
    version,
    about = "音频频谱图生成 (sox/ffmpeg)",
    long_about = "用法: spectro <audio> [output.png]\n\n依赖: sox (或 ffmpeg)\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 输入音频文件
    #[arg(value_name = "AUDIO")]
    audio: PathBuf,

    /// 输出 PNG (默认 <文件名>_spectro.png)
    #[arg(value_name = "OUTPUT")]
    output: Option<PathBuf>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Report {
    audio: String,
    output: String,
    tool: Option<String>,
    success: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sox_info: Vec<String>,
}

fn default_output(audio: &Path) -> PathBuf {
    let name = audio
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("audio");
    let stem = match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    };
    PathBuf::from(format!("{stem}_spectro.png"))
}

fn have(cmd: &str) -> bool {
    Command::new(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn run(cmd: &str, args: &[&std::ffi::OsStr]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sox_info(audio: &Path) -> Vec<String> {
    let output = match Command::new("sox").arg("--i").arg(audio).output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .take(10)
        .map(|s| s.to_string())
        .collect()
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let audio = args.audio.clone();
    let output = args
        .output
        .clone()
        .unwrap_or_else(|| default_output(&audio));

    if !audio.is_file() {
        out.error(&format!("File not found: {}", audio.display()));
        return finish(exit::ERROR);
    }

    out.info(&format!(
        "{}",
        format!("[*] Generating spectrogram: {}", audio.display()).bold()
    ));

    let mut tool: Option<&str> = None;
    let mut attempted = false;

    if have("sox") {
        out.info("  Using sox...");
        attempted = true;
        let a = audio.as_os_str();
        let o = output.as_os_str();
        if run(
            "sox",
            &[
                a,
                std::ffi::OsStr::new("-n"),
                std::ffi::OsStr::new("spectrogram"),
                std::ffi::OsStr::new("-o"),
                o,
            ],
        ) {
            tool = Some("sox");
        }
    }

    if tool.is_none() && have("ffmpeg") {
        out.info("  Using ffmpeg...");
        attempted = true;
        let a = audio.as_os_str();
        let o = output.as_os_str();
        if run(
            "ffmpeg",
            &[
                std::ffi::OsStr::new("-i"),
                a,
                std::ffi::OsStr::new("-lavfi"),
                std::ffi::OsStr::new("showspectrumpic=s=1024x512"),
                std::ffi::OsStr::new("-y"),
                o,
            ],
        ) {
            tool = Some("ffmpeg");
        }
    }

    let success = tool.is_some();
    let info = if !success && have("sox") {
        sox_info(&audio)
    } else {
        Vec::new()
    };

    let report = Report {
        audio: audio.display().to_string(),
        output: output.display().to_string(),
        tool: tool.map(|s| s.to_string()),
        success,
        sox_info: info,
    };

    out.emit(
        || {
            if report.success {
                println!("  {} Written to: {}", "[+]".green(), report.output);
                return;
            }
            println!(
                "  {} sox/ffmpeg not found, using ASCII fallback",
                "[-]".red()
            );
            println!("\n  Install sox: pacman -S sox");
            println!("  Install ffmpeg: pacman -S ffmpeg");
            if !report.sox_info.is_empty() {
                println!("\n  {}", "Audio Info:".bold());
                for line in &report.sox_info {
                    println!("{line}");
                }
            }
        },
        &report,
    );

    if report.success {
        finish(exit::OK)
    } else if attempted {
        finish(exit::ERROR)
    } else {
        finish(exit::NO_RESULT)
    }
}
