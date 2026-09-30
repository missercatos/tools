use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "stego",
    version,
    about = "Image steganography detection",
    long_about = "图像隐写检测\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    file: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Extract LSB data from specified channel (0=R,1=G,2=B)
    #[arg(long)]
    lsb_extract: Option<u8>,
    /// Extract bits from LSB (default: 1)
    #[arg(long, default_value = "1")]
    bits: u8,
    /// Show channel statistics
    #[arg(long)]
    channels: bool,
    /// Check for appended data after image end
    #[arg(long)]
    appended: bool,
    /// Extract data after image end marker
    #[arg(long)]
    extract_appended: bool,
    /// Analyze all modes
    #[arg(long)]
    all: bool,
    /// Minimum entropy threshold for anomaly
    #[arg(long, default_value = "7.0")]
    entropy_threshold: f64,
    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct ImageInfo {
    width: usize,
    height: usize,
}

#[derive(Serialize)]
struct ChannelStat {
    channel: String,
    entropy: f64,
    min: u8,
    max: u8,
    mean: f64,
}

#[derive(Serialize)]
struct LsbResult {
    channel: u8,
    bits: u8,
    entropy: f64,
    text: String,
    hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

#[derive(Serialize)]
struct AppendedData {
    offset: usize,
    size: usize,
    entropy: f64,
    preview: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

#[derive(Serialize)]
struct ChunkInfo {
    chunk_type: String,
    size: usize,
    entropy: f64,
    suspicious: bool,
}

#[derive(Serialize)]
struct Report {
    file: String,
    size: usize,
    is_png: bool,
    is_bmp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<ImageInfo>,
    channels: Vec<ChannelStat>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lsb: Option<LsbResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    appended: Option<AppendedData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    riff_trailing: Option<usize>,
    chunks: Vec<ChunkInfo>,
}

fn read_png_pixels(data: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    if data.len() < 8 || &data[0..8] != b"\x89PNG\r\n\x1a\n" {
        return None;
    }

    let mut width = 0usize;
    let mut height = 0usize;
    let mut offset = 8;
    let mut idat_data = Vec::new();

    while offset + 8 <= data.len() {
        let chunk_len = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        let chunk_type = &data[offset + 4..offset + 8];
        offset += 12;

        if chunk_type == b"IHDR" && chunk_len >= 13 {
            width = u32::from_be_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
            height = u32::from_be_bytes(data[offset + 4..offset + 8].try_into().ok()?) as usize;
        } else if chunk_type == b"IDAT" {
            idat_data.extend_from_slice(&data[offset..offset + chunk_len]);
        } else if chunk_type == b"IEND" {
            break;
        }
        offset += chunk_len;
    }

    if width == 0 || height == 0 || idat_data.is_empty() {
        return None;
    }

    let decompressed = inflate_stored(&idat_data).ok()?;
    if decompressed.len() < height * (1 + width * 3) {
        return None;
    }

    let mut pixels = Vec::new();
    for y in 0..height {
        let row_start = y * (1 + width * 3);
        if row_start + 1 + width * 3 <= decompressed.len() {
            pixels.extend_from_slice(&decompressed[row_start + 1..row_start + 1 + width * 3]);
        }
    }

    Some((width, height, pixels))
}

fn inflate_stored(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if i + 2 > data.len() {
            break;
        }
        let block_type = data[i];
        i += 1;

        let is_last = block_type & 1 != 0;
        let block_len = u16::from_le_bytes(data[i..i + 2].try_into().map_err(|_| ())?) as usize;
        i += 2;

        if i + block_len > data.len() {
            break;
        }
        output.extend_from_slice(&data[i..i + block_len]);
        i += block_len;

        if is_last {
            break;
        }
    }

    Ok(output)
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

fn analyze_lsb(pixels: &[u8], channel: u8, bits: u8) -> Vec<u8> {
    let mask = (1u8 << bits) - 1;
    let shift = 8 - bits;
    let mut bits_collected = Vec::new();

    for i in (0..pixels.len()).step_by(3) {
        if i + (channel as usize) < pixels.len() {
            let val = pixels[i + channel as usize];
            bits_collected.push((val & mask) << shift);
        }
    }

    let mut result = Vec::new();
    for chunk in bits_collected.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            byte |= (bit >> (7 - i)) & (0x80 >> i);
        }
        result.push(byte);
    }
    result
}

fn channel_stats(pixels: &[u8]) -> Vec<ChannelStat> {
    let mut r = Vec::new();
    let mut g = Vec::new();
    let mut b = Vec::new();

    for i in (0..pixels.len()).step_by(3) {
        r.push(pixels[i]);
        if i + 1 < pixels.len() {
            g.push(pixels[i + 1]);
        }
        if i + 2 < pixels.len() {
            b.push(pixels[i + 2]);
        }
    }

    [("R", &r), ("G", &g), ("B", &b)]
        .iter()
        .map(|(name, ch)| {
            let entropy = calculate_entropy(ch);
            let min = ch.iter().cloned().fold(u8::MAX, u8::min);
            let max = ch.iter().cloned().fold(u8::MIN, u8::max);
            let mean = ch.iter().map(|&x| x as f64).sum::<f64>() / ch.len() as f64;
            ChannelStat {
                channel: name.to_string(),
                entropy,
                min,
                max,
                mean,
            }
        })
        .collect()
}

fn preview(data: &[u8], limit: usize) -> String {
    data.iter()
        .take(limit)
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
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

    let is_png = data.len() >= 8 && &data[0..8] == b"\x89PNG\r\n\x1a\n";
    let is_bmp = data.len() > 2 && data[0] == b'B' && data[1] == b'M';

    let mut report = Report {
        file: args.file.display().to_string(),
        size: data.len(),
        is_png,
        is_bmp,
        image: None,
        channels: Vec::new(),
        lsb: None,
        appended: None,
        riff_trailing: None,
        chunks: Vec::new(),
    };

    if args.channels || args.all {
        if let Some((w, h, pixels)) = read_png_pixels(&data) {
            report.image = Some(ImageInfo {
                width: w,
                height: h,
            });
            report.channels = channel_stats(&pixels);
        }
    }

    if let Some(channel) = args.lsb_extract {
        if let Some((_w, _h, pixels)) = read_png_pixels(&data) {
            let extracted = analyze_lsb(&pixels, channel, args.bits);
            let entropy = calculate_entropy(&extracted);
            let text = preview(&extracted, 200);
            let hex = extracted
                .iter()
                .take(64)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");

            let mut output = None;
            if let Some(out_path) = &args.output {
                fs::write(out_path, &extracted).ok();
                output = Some(out_path.display().to_string());
            }

            report.lsb = Some(LsbResult {
                channel,
                bits: args.bits,
                entropy,
                text,
                hex,
                output,
            });
        }
    }

    if args.appended || args.all || args.extract_appended {
        if is_png {
            if let Some(iend_pos) = data.windows(4).position(|w| w == b"IEND") {
                let after = iend_pos + 8;
                if after < data.len() {
                    let extra = &data[after..];
                    let entropy = calculate_entropy(extra);
                    let text = preview(extra, 200);

                    let mut output = None;
                    if args.extract_appended {
                        let default_path = PathBuf::from("appended_data.bin");
                        let outpath = args.output.as_ref().unwrap_or(&default_path);
                        fs::write(outpath, extra).ok();
                        output = Some(outpath.display().to_string());
                    }

                    report.appended = Some(AppendedData {
                        offset: after,
                        size: extra.len(),
                        entropy,
                        preview: text,
                        output,
                    });
                }
            }
        }

        if is_bmp || (!is_png && data.len() > 2) {
            if data.len() > 12 && &data[0..4] == b"RIFF" {
                let riff_size =
                    u32::from_le_bytes(data[4..8].try_into().unwrap_or([0; 4])) as usize;
                if riff_size + 8 < data.len() {
                    report.riff_trailing = Some(data.len() - riff_size - 8);
                }
            }
        }
    }

    if is_png && (args.all || (!args.channels && args.lsb_extract.is_none() && !args.appended)) {
        let mut offset = 8;
        while offset + 8 <= data.len() {
            let chunk_len =
                u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
            if offset + 8 + chunk_len > data.len() {
                break;
            }
            let chunk_type = String::from_utf8_lossy(&data[offset + 4..offset + 8]).to_string();
            let chunk_data = &data[offset + 8..offset + 8 + chunk_len];

            let entropy = calculate_entropy(chunk_data);
            let suspicious = if chunk_type == "IDAT" {
                false
            } else if chunk_type == "IHDR" || chunk_type == "IEND" {
                false
            } else {
                entropy > args.entropy_threshold || chunk_len > 10000
            };

            report.chunks.push(ChunkInfo {
                chunk_type,
                size: chunk_len,
                entropy,
                suspicious,
            });

            offset += 12 + chunk_len;
        }
    }

    out.emit(
        || {
            println!("{}", format!("=== {} ===", report.file).bold());
            println!("  Size: {} bytes", report.size);

            if !report.is_png && !report.is_bmp {
                println!("  {} Not a PNG/BMP image", "warning:".yellow());
            }

            if let Some(img) = &report.image {
                println!("  Image: {}x{}", img.width, img.height);
                println!("\n{}", "=== Channel Statistics ===".bold());
                for c in &report.channels {
                    println!(
                        "  {}: entropy={:.4} min={} max={} mean={:.1}",
                        c.channel, c.entropy, c.min, c.max, c.mean
                    );
                }
            }

            if let Some(lsb) = &report.lsb {
                println!(
                    "\n{}",
                    format!("=== LSB Extract (ch={}, bits={}) ===", lsb.channel, lsb.bits).bold()
                );
                println!("  Entropy: {:.4}", lsb.entropy);
                println!("  Text: {}", lsb.text);
                println!("  Hex:  {}", lsb.hex);
                if let Some(o) = &lsb.output {
                    println!("  Written to {}", o);
                }
            }

            if args.appended || args.all || args.extract_appended {
                if report.is_png {
                    if let Some(app) = &report.appended {
                        println!("\n{}", "=== Appended Data After IEND ===".bold());
                        println!("  {} bytes at 0x{:x}", app.size, app.offset);
                        println!("  Entropy: {:.4}", app.entropy);
                        println!("  Preview: {}", app.preview);
                        if let Some(o) = &app.output {
                            println!("  Written to {}", o);
                        }
                    } else {
                        println!("\n  No data after IEND");
                    }
                }

                if let Some(n) = report.riff_trailing {
                    println!("\n{} bytes after RIFF chunk", n);
                }
            }

            if report.is_png
                && (args.all || (!args.channels && args.lsb_extract.is_none() && !args.appended))
            {
                println!("\n{}", "=== PNG Chunk Analysis ===".bold());
                for c in &report.chunks {
                    if c.suspicious {
                        println!(
                            "  {} {} bytes entropy={:.4} SUSPICIOUS",
                            c.chunk_type.yellow().bold(),
                            c.size,
                            c.entropy
                        );
                    } else {
                        println!(
                            "  {} {} bytes entropy={:.4}",
                            c.chunk_type, c.size, c.entropy
                        );
                    }
                }
            }
        },
        &report,
    );

    finish(if report.is_png {
        exit::OK
    } else {
        exit::NO_RESULT
    })
}
