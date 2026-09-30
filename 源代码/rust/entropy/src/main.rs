//! entropy - 熵可视化: 生成 PNG 热力图 / ASCII 图 / 统计信息

use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "entropy",
    version,
    about = "熵可视化: 生成 PNG 热力图 / ASCII 图 / 统计信息",
    long_about = "按块计算文件熵并可视化(默认 PNG 热力图, --ascii 为字符图, --info 仅统计)。\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标文件
    #[arg(value_name = "FILE")]
    file: PathBuf,

    /// 输出 PNG 路径 (默认 <文件名>_entropy.png)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// 块大小 (字节)
    #[arg(long, default_value = "256")]
    block_size: usize,

    /// 图像宽度 (默认 sqrt(块数))
    #[arg(long)]
    width: Option<usize>,

    /// 图像高度
    #[arg(long)]
    height: Option<usize>,

    /// 仅显示统计信息
    #[arg(long)]
    info: bool,

    /// ASCII 艺术模式 (无需 PNG)
    #[arg(long)]
    ascii: bool,

    /// JSON 输出 (输出元数据而非二进制)
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Anomaly {
    block: usize,
    offset: usize,
    entropy: f64,
    sigma: f64,
}

#[derive(Serialize)]
struct Report {
    file: String,
    size: usize,
    block_size: usize,
    blocks: usize,
    mode: String,
    width: Option<usize>,
    height: Option<usize>,
    overall_entropy: f64,
    block_min: Option<f64>,
    block_max: Option<f64>,
    output: Option<String>,
    anomalies: Vec<Anomaly>,
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| {
            let p = f as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn write_png(filepath: &PathBuf, width: usize, height: usize, pixels: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = fs::File::create(filepath)?;

    file.write_all(b"\x89PNG\r\n\x1a\n")?;

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.push(8);
    ihdr.push(2);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    write_chunk(&mut file, b"IHDR", &ihdr)?;

    let mut raw = Vec::with_capacity(height * (1 + width * 3));
    for y in 0..height {
        raw.push(0);
        for x in 0..width {
            let idx = (y * width + x) * 3;
            if idx + 2 < pixels.len() {
                raw.push(pixels[idx]);
                raw.push(pixels[idx + 1]);
                raw.push(pixels[idx + 2]);
            } else {
                raw.push(0);
                raw.push(0);
                raw.push(0);
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
    for &b in chunk_type.iter().chain(data.iter()) {
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
    out.push(0x78);
    out.push(0x01);

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

    let adler = adler32(data);
    out.extend_from_slice(&adler.to_be_bytes());

    out
}

fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &d in data {
        a = (a + d as u32) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

fn entropy_to_color(e: f64) -> (u8, u8, u8) {
    let t = (e / 8.0).clamp(0.0, 1.0);
    if t < 0.25 {
        let s = t / 0.25;
        (0, (s * 255.0) as u8, 255)
    } else if t < 0.5 {
        let s = (t - 0.25) / 0.25;
        (0, 255, (255.0 * (1.0 - s)) as u8)
    } else if t < 0.75 {
        let s = (t - 0.5) / 0.25;
        ((s * 255.0) as u8, 255, 0)
    } else {
        let s = (t - 0.75) / 0.25;
        (255, (255.0 * (1.0 - s)) as u8, 0)
    }
}

fn entropy_char(e: f64) -> char {
    if e < 1.0 {
        ' '
    } else if e < 2.0 {
        '.'
    } else if e < 3.0 {
        ':'
    } else if e < 4.0 {
        '-'
    } else if e < 5.0 {
        '='
    } else if e < 6.0 {
        '+'
    } else if e < 7.0 {
        '#'
    } else {
        '@'
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    if args.block_size == 0 {
        out.error("block size must be > 0");
        return finish(exit::USAGE);
    }

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => {
            out.error(&format!("cannot read {}: {e}", args.file.display()));
            return finish(exit::ERROR);
        }
    };

    let blocks: Vec<f64> = data
        .chunks(args.block_size)
        .map(|chunk| calculate_entropy(chunk))
        .collect();
    let overall = calculate_entropy(&data);
    let (block_min, block_max) = blocks
        .iter()
        .fold((None::<f64>, None::<f64>), |(mn, mx), &e| {
            (
                Some(match mn {
                    None => e,
                    Some(v) => v.min(e),
                }),
                Some(match mx {
                    None => e,
                    Some(v) => v.max(e),
                }),
            )
        });

    let info_mode = args.info || blocks.is_empty();
    let mode = if info_mode {
        "info"
    } else if args.ascii {
        "ascii"
    } else {
        "png"
    };

    let mut width = None;
    let mut height = None;
    let mut output = None;

    if !info_mode {
        let w = args.width.unwrap_or_else(|| {
            let w = (blocks.len() as f64).sqrt() as usize;
            w.max(1)
        });
        let h = args.height.unwrap_or_else(|| (blocks.len() + w - 1) / w);
        width = Some(w);
        height = Some(h);

        if mode == "png" {
            let mut pixels = Vec::with_capacity(w * h * 3);
            for y in 0..h {
                for x in 0..w {
                    let idx = y * w + x;
                    let e = if idx < blocks.len() { blocks[idx] } else { 0.0 };
                    let (r, g, b) = entropy_to_color(e);
                    pixels.push(r);
                    pixels.push(g);
                    pixels.push(b);
                }
            }

            let outpath = args.output.clone().unwrap_or_else(|| {
                let stem = args.file.file_stem().unwrap_or_default().to_string_lossy();
                PathBuf::from(format!("{}_entropy.png", stem))
            });

            if let Err(e) = write_png(&outpath, w, h, &pixels) {
                out.error(&format!("cannot write {}: {e}", outpath.display()));
                return finish(exit::ERROR);
            }
            output = Some(outpath.display().to_string());
            if out.json() {
                out.info(&format!("written to {}", outpath.display()));
            }
        }
    }

    let mut anomalies = Vec::new();
    if !info_mode {
        let mean: f64 = blocks.iter().sum::<f64>() / blocks.len() as f64;
        let std_dev: f64 =
            (blocks.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / blocks.len() as f64).sqrt();
        for (i, &e) in blocks.iter().enumerate() {
            if (e - mean).abs() > std_dev * 2.0 {
                anomalies.push(Anomaly {
                    block: i,
                    offset: i * args.block_size,
                    entropy: e,
                    sigma: ((e - mean) / std_dev).abs(),
                });
            }
        }
    }

    let report = Report {
        file: args.file.display().to_string(),
        size: data.len(),
        block_size: args.block_size,
        blocks: blocks.len(),
        mode: mode.to_string(),
        width,
        height,
        overall_entropy: overall,
        block_min,
        block_max,
        output,
        anomalies,
    };

    out.emit(
        || {
            println!("{}", format!("=== {} ===", report.file).bold());
            println!("  Size: {} bytes", report.size);

            if report.mode == "info" {
                println!("  Overall entropy: {:.4} / 8.0", report.overall_entropy);
                if let (Some(mn), Some(mx)) = (report.block_min, report.block_max) {
                    println!("  Block entropy range: {:.4} - {:.4}", mn, mx);
                }
                return;
            }

            println!("  Blocks: {} (size={})", report.blocks, report.block_size);
            println!(
                "  Grid: {}x{}",
                report.width.unwrap_or(0),
                report.height.unwrap_or(0)
            );

            if report.mode == "ascii" {
                println!("\n{}", "Entropy Map:".bold());
                let w = report.width.unwrap_or(0);
                let h = report.height.unwrap_or(0);
                for y in 0..h {
                    print!("  ");
                    for x in 0..w {
                        let idx = y * w + x;
                        if idx < blocks.len() {
                            print!("{}", entropy_char(blocks[idx]));
                        } else {
                            print!(" ");
                        }
                    }
                    println!();
                }
                println!("\n  Legend: ' '=0  '.'=1-2  ':'=2-3  '-'=3-4  '='=4-5  '+'=5-6  '#'=6-7  '@'=7-8");
            } else {
                println!("  Written to {}", report.output.as_deref().unwrap_or(""));
            }

            if !report.anomalies.is_empty() {
                println!(
                    "\n{} ({} blocks)",
                    "=== Anomaly Regions ===".bold(),
                    report.anomalies.len()
                );
                for a in report.anomalies.iter().take(20) {
                    println!(
                        "  0x{:08x} entropy={:.4} ({}σ from mean)",
                        a.offset, a.entropy, a.sigma as i32
                    );
                }
            }
        },
        &report,
    );

    if blocks.is_empty() {
        finish(exit::NO_RESULT)
    } else {
        finish(exit::OK)
    }
}
