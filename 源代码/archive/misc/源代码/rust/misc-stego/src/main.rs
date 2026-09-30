use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-stego", about = "Image steganography detection")]
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
}

fn read_png_pixels(data: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    // Simple PNG parser for IHDR + IDAT
    if &data[0..8] != b"\x89PNG\r\n\x1a\n" { return None; }

    let mut width = 0usize;
    let mut height = 0usize;
    let mut offset = 8;
    let mut idat_data = Vec::new();

    while offset + 8 <= data.len() {
        let chunk_len = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?) as usize;
        let chunk_type = &data[offset+4..offset+8];
        offset += 12;

        if chunk_type == b"IHDR" && chunk_len >= 13 {
            width = u32::from_be_bytes(data[offset..offset+4].try_into().ok()?) as usize;
            height = u32::from_be_bytes(data[offset+4..offset+8].try_into().ok()?) as usize;
        } else if chunk_type == b"IDAT" {
            idat_data.extend_from_slice(&data[offset..offset+chunk_len]);
        } else if chunk_type == b"IEND" {
            break;
        }
        offset += chunk_len;
    }

    if width == 0 || height == 0 || idat_data.is_empty() { return None; }

    // Simple inflate (stored blocks only - works for most simple PNGs)
    let decompressed = inflate_stored(&idat_data).ok()?;
    if decompressed.len() < height * (1 + width * 3) { return None; }

    let mut pixels = Vec::new();
    for y in 0..height {
        let row_start = y * (1 + width * 3);
        if row_start + 1 + width * 3 <= decompressed.len() {
            pixels.extend_from_slice(&decompressed[row_start+1..row_start+1+width*3]);
        }
    }

    Some((width, height, pixels))
}

fn inflate_stored(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if i + 2 > data.len() { break; }
        let block_type = data[i];
        i += 1;

        let is_last = block_type & 1 != 0;
        let block_len = u16::from_le_bytes(data[i..i+2].try_into().map_err(|_| ())?) as usize;
        i += 2;

        if i + block_len > data.len() { break; }
        output.extend_from_slice(&data[i..i+block_len]);
        i += block_len;

        if is_last { break; }
    }

    Ok(output)
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter().filter(|&&f| f > 0).map(|&f| { let p = f as f64 / len; -p * p.log2() }).sum()
}

fn analyze_lsb(pixels: &[u8], width: usize, height: usize, channel: u8, bits: u8) -> Vec<u8> {
    let mask = (1u8 << bits) - 1;
    let shift = 8 - bits;
    let mut bits_collected = Vec::new();

    for i in (0..pixels.len()).step_by(3) {
        if i + (channel as usize) < pixels.len() {
            let val = pixels[i + channel as usize];
            bits_collected.push((val & mask) << shift);
        }
    }

    // Convert bits to bytes
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

fn channel_stats(pixels: &[u8], width: usize, height: usize) {
    let mut r = Vec::new();
    let mut g = Vec::new();
    let mut b = Vec::new();

    for i in (0..pixels.len()).step_by(3) {
        r.push(pixels[i]);
        if i + 1 < pixels.len() { g.push(pixels[i + 1]); }
        if i + 2 < pixels.len() { b.push(pixels[i + 2]); }
    }

    println!("\n{}", "=== Channel Statistics ===".bold());
    for (name, ch) in &[("R", &r), ("G", &g), ("B", &b)] {
        let entropy = calculate_entropy(ch);
        let min = ch.iter().cloned().fold(u8::MAX, u8::min);
        let max = ch.iter().cloned().fold(u8::MIN, u8::max);
        let mean = ch.iter().map(|&x| x as f64).sum::<f64>() / ch.len() as f64;
        println!("  {}: entropy={:.4} min={} max={} mean={:.1}", name, entropy, min, max, mean);
    }
}

fn main() {
    let args = Args::parse();

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => { eprintln!("{} {}", "error:".red().bold(), e); std::process::exit(1); }
    };

    println!("{}", format!("=== {} ===", args.file.display()).bold());
    println!("  Size: {} bytes", data.len());

    let is_png = &data[0..8] == b"\x89PNG\r\n\x1a\n";
    let is_bmp = data.len() > 2 && data[0] == b'B' && data[1] == b'M';

    if !is_png && !is_bmp {
        println!("  {} Not a PNG/BMP image", "warning:".yellow());
    }

    // Channel stats
    if args.channels || args.all {
        if let Some((w, h, pixels)) = read_png_pixels(&data) {
            println!("  Image: {}x{}", w, h);
            channel_stats(&pixels, w, h);
        }
    }

    // LSB extraction
    if let Some(channel) = args.lsb_extract {
        if let Some((w, h, pixels)) = read_png_pixels(&data) {
            let extracted = analyze_lsb(&pixels, w, h, channel, args.bits);
            let entropy = calculate_entropy(&extracted);
            println!("\n{}", format!("=== LSB Extract (ch={}, bits={}) ===", channel, args.bits).bold());
            println!("  Entropy: {:.4}", entropy);

            let preview: String = extracted.iter().take(200)
                .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                .collect();
            println!("  Text: {}", preview);

            let hex: String = extracted.iter().take(64).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            println!("  Hex:  {}", hex);

            if let Some(ref out) = args.output {
                fs::write(out, &extracted).ok();
                println!("  Written to {}", out.display());
            }
        }
    }

    // Appended data
    if args.appended || args.all || args.extract_appended {
        // Find PNG IEND
        if is_png {
            if let Some(iend_pos) = data.windows(4).position(|w| w == b"IEND") {
                let after = iend_pos + 8; // IEND + 4 bytes CRC
                if after < data.len() {
                    let extra = &data[after..];
                    println!("\n{}", "=== Appended Data After IEND ===".bold());
                    println!("  {} bytes at 0x{:x}", extra.len(), after);
                    let entropy = calculate_entropy(extra);
                    println!("  Entropy: {:.4}", entropy);
                    let preview: String = extra.iter().take(200)
                        .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                        .collect();
                    println!("  Preview: {}", preview);

                    if args.extract_appended {
                        let default_path = PathBuf::from("appended_data.bin");
                        let outpath = args.output.as_ref().unwrap_or(&default_path);
                        fs::write(outpath, extra).ok();
                        println!("  Written to {}", outpath.display());
                    }
                } else {
                    println!("\n  No data after IEND");
                }
            }
        }

        // Check for JPEG end marker
        if is_bmp || (!is_png && data.len() > 2) {
            // Check for RIFF end
            if data.len() > 12 && &data[0..4] == b"RIFF" {
                let riff_size = u32::from_le_bytes(data[4..8].try_into().unwrap_or([0;4])) as usize;
                if riff_size + 8 < data.len() {
                    println!("\n{} bytes after RIFF chunk", data.len() - riff_size - 8);
                }
            }
        }
    }

    // Try all PNG chunks
    if is_png && (args.all || (!args.channels && args.lsb_extract.is_none() && !args.appended)) {
        println!("\n{}", "=== PNG Chunk Analysis ===".bold());
        let mut offset = 8;
        while offset + 8 <= data.len() {
            let chunk_len = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap_or([0;4])) as usize;
            let chunk_type = String::from_utf8_lossy(&data[offset+4..offset+8]);
            let chunk_data = &data[offset+8..offset+8+chunk_len];

            let entropy = calculate_entropy(chunk_data);
            let suspicious = if chunk_type == "IDAT" { false }
                else if chunk_type == "IHDR" || chunk_type == "IEND" { false }
                else { entropy > args.entropy_threshold || chunk_len > 10000 };

            if suspicious {
                println!("  {} {} bytes entropy={:.4} SUSPICIOUS",
                    chunk_type.yellow().bold(), chunk_len, entropy);
            } else {
                println!("  {} {} bytes entropy={:.4}", chunk_type, chunk_len, entropy);
            }

            offset += 12 + chunk_len;
        }
    }
}
