//! visual - 二进制数据可视化: 字节值渲染为 PNG 图像 / ASCII 图

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "visual",
    version,
    about = "二进制数据可视化: 字节值渲染为 PNG 图像 / ASCII 图",
    long_about = "把文件字节按网格渲染成图像(灰度/RGB/ASCII)。\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标文件
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// 输出 PNG 路径 (默认 <文件名>_visual.png)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// 图像宽度 (默认 sqrt(文件大小))
    #[arg(long)]
    width: Option<usize>,

    /// 图像高度
    #[arg(long)]
    height: Option<usize>,

    /// 灰度 (每像素 1 字节)
    #[arg(long)]
    grayscale: bool,

    /// RGB 映射: R=byte, G=offset%256, B=0
    #[arg(long)]
    rgb_mode: bool,

    /// ASCII 艺术模式
    #[arg(long)]
    ascii: bool,

    /// JSON 输出 (输出元数据而非二进制)
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Report {
    file: String,
    size: usize,
    width: usize,
    height: usize,
    mode: String,
    grayscale: bool,
    rgb_mode: bool,
    output: Option<String>,
}

fn write_png(
    filepath: &PathBuf,
    width: usize,
    height: usize,
    pixels: &[u8],
    grayscale: bool,
) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = fs::File::create(filepath)?;
    file.write_all(b"\x89PNG\r\n\x1a\n")?;

    let color_type = if grayscale { 0 } else { 2 };
    let bpp = if grayscale { 1 } else { 3 };

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.push(8);
    ihdr.push(color_type);
    ihdr.extend_from_slice(&[0, 0, 0]);
    write_chunk(&mut file, b"IHDR", &ihdr)?;

    let mut raw = Vec::new();
    for y in 0..height {
        raw.push(0);
        for x in 0..width {
            let idx = (y * width + x) * bpp;
            for c in 0..bpp {
                if idx + c < pixels.len() {
                    raw.push(pixels[idx + c]);
                } else {
                    raw.push(0);
                }
            }
        }
    }

    let compressed = deflate(&raw);
    write_chunk(&mut file, b"IDAT", &compressed)?;
    write_chunk(&mut file, b"IEND", &[])?;
    Ok(())
}

fn write_chunk(file: &mut fs::File, chunk_type: &[u8], data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut c = 0xFFFFFFFFu32;
    for &b in chunk_type {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB88320
            } else {
                c >> 1
            };
        }
    }
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB88320
            } else {
                c >> 1
            };
        }
    }
    c ^= 0xFFFFFFFF;

    file.write_all(&(data.len() as u32).to_be_bytes())?;
    file.write_all(chunk_type)?;
    file.write_all(data)?;
    file.write_all(&c.to_be_bytes())?;
    Ok(())
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x78, 0x01]);

    let chunks: Vec<&[u8]> = data.chunks(0xFFFF).collect();
    if chunks.is_empty() {
        out.push(0x01);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        let total = chunks.len();
        for (i, chunk) in chunks.into_iter().enumerate() {
            out.push(if i + 1 == total { 0x01 } else { 0x00 });
            let len = chunk.len() as u16;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }

    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &d in data {
        a = (a + d as u32) % 65521;
        b = (b + a) % 65521;
    }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("cannot read {}: {e}", args.file.display()));
            return finish(exit::ERROR);
        }
    };

    let width = args
        .width
        .unwrap_or((data.len() as f64).sqrt() as usize)
        .max(1);
    let height = args.height.unwrap_or((data.len() + width - 1) / width);

    let mut output = None;

    if !args.ascii {
        let mut pixels = Vec::new();
        if args.grayscale {
            for y in 0..height {
                for x in 0..width {
                    let idx = y * width + x;
                    pixels.push(if idx < data.len() { data[idx] } else { 0 });
                }
            }
        } else {
            for y in 0..height {
                for x in 0..width {
                    let idx = y * width + x;
                    if idx < data.len() {
                        if args.rgb_mode {
                            pixels.push(data[idx]);
                            pixels.push((idx % 256) as u8);
                            pixels.push(0);
                        } else {
                            let b = data[idx];
                            pixels.push(b);
                            pixels.push(b);
                            pixels.push(b);
                        }
                    } else {
                        pixels.extend_from_slice(&[0, 0, 0]);
                    }
                }
            }
        }

        let outpath = args.output.clone().unwrap_or_else(|| {
            PathBuf::from(format!(
                "{}_visual.png",
                args.file.file_stem().unwrap_or_default().to_string_lossy()
            ))
        });

        if let Err(e) = write_png(&outpath, width, height, &pixels, args.grayscale) {
            out.error(&format!("cannot write {}: {e}", outpath.display()));
            return finish(exit::ERROR);
        }
        output = Some(outpath.display().to_string());
        if out.json() {
            out.info(&format!("written to {}", outpath.display()));
        }
    }

    let report = Report {
        file: args.file.display().to_string(),
        size: data.len(),
        width,
        height,
        mode: if args.ascii { "ascii" } else { "png" }.to_string(),
        grayscale: args.grayscale,
        rgb_mode: args.rgb_mode,
        output,
    };

    out.emit(
        || {
            println!("{}", format!("=== {} ===", report.file).bold());
            println!("  Size: {} bytes", report.size);
            println!("  Grid: {}x{}", report.width, report.height);

            if report.mode == "ascii" {
                let chars = " .:-=+*#%@";
                println!("\n{}", "Binary Visualization:".bold());
                for y in 0..report.height {
                    print!("  ");
                    for x in 0..report.width {
                        let idx = y * report.width + x;
                        if idx < data.len() {
                            let c = (data[idx] as usize * (chars.len() - 1)) / 255;
                            print!("{}", chars.chars().nth(c).unwrap_or(' '));
                        }
                    }
                    println!();
                }
            } else {
                println!("  Written to {}", report.output.as_deref().unwrap_or(""));
            }
        },
        &report,
    );

    if data.is_empty() {
        finish(exit::NO_RESULT)
    } else {
        finish(exit::OK)
    }
}
