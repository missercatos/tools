use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-entropy", about = "Entropy visualization - generate PNG heatmap")]
struct Args {
    file: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    #[arg(long, default_value = "256")]
    block_size: usize,
    #[arg(long)]
    width: Option<usize>,
    #[arg(long)]
    height: Option<usize>,
    #[arg(long)]
    info: bool,
    /// ASCII art mode (no PNG needed)
    #[arg(long)]
    ascii: bool,
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[b as usize] += 1; }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&f| f > 0)
        .map(|&f| { let p = f as f64 / len; -p * p.log2() })
        .sum()
}

fn write_png(filepath: &PathBuf, width: usize, height: usize, pixels: &[u8]) {
    use std::io::Write;

    let mut file = fs::File::create(filepath).unwrap();

    // PNG signature
    file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();

    // IHDR
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(2); // color type: RGB
    ihdr.push(0); // compression
    ihdr.push(0); // filter
    ihdr.push(0); // interlace
    write_chunk(&mut file, b"IHDR", &ihdr);

    // IDAT
    let mut raw = Vec::with_capacity(height * (1 + width * 3));
    for y in 0..height {
        raw.push(0); // filter: none
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

    // Deflate
    let compressed = deflate(&raw);
    write_chunk(&mut file, b"IDAT", &compressed);

    // IEND
    write_chunk(&mut file, b"IEND", &[]);
}

fn write_chunk(file: &mut fs::File, chunk_type: &[u8], data: &[u8]) {
    use std::io::Write;
    let mut crc = crc32(chunk_type);
    crc = crc32_update(crc, data);

    file.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
    file.write_all(chunk_type).unwrap();
    file.write_all(data).unwrap();
    file.write_all(&crc.to_be_bytes()).unwrap();
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 { crc = (crc >> 1) ^ 0xEDB88320; }
            else { crc >>= 1; }
        }
    }
    crc ^ 0xFFFFFFFF
}

fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = crc;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            if c & 1 != 0 { c = (c >> 1) ^ 0xEDB88320; }
            else { c >>= 1; }
        }
    }
    c
}

fn deflate(data: &[u8]) -> Vec<u8> {
    // Simple stored (no compression) deflate wrapper
    let mut out = Vec::new();
    let len = data.len();
    let nlen = (!len) & 0xFFFF;

    // zlib header
    out.push(0x78);
    out.push(0x01);

    // Last block
    out.push(0x01);
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out.extend_from_slice(&nlen.to_be_bytes());
    out.extend_from_slice(data);

    // Adler32
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
    // 0 = blue (low), 4 = green, 8 = red (high)
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
    if e < 1.0 { ' ' }
    else if e < 2.0 { '.' }
    else if e < 3.0 { ':' }
    else if e < 4.0 { '-' }
    else if e < 5.0 { '=' }
    else if e < 6.0 { '+' }
    else if e < 7.0 { '#' }
    else { '@' }
}

fn main() {
    let args = Args::parse();

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            std::process::exit(1);
        }
    };

    println!("{}", format!("=== {} ===", args.file.display()).bold());
    println!("  Size: {} bytes", data.len());

    // Calculate block entropies
    let blocks: Vec<f64> = data.chunks(args.block_size)
        .map(|chunk| calculate_entropy(chunk))
        .collect();

    if args.info || blocks.is_empty() {
        let overall = calculate_entropy(&data);
        println!("  Overall entropy: {:.4} / 8.0", overall);
        if let Some((min_e, max_e)) = blocks.iter()
            .fold(None, |acc: Option<(f64, f64)>, &e| {
                Some(match acc {
                    None => (e, e),
                    Some((mn, mx)) => (mn.min(e), mx.max(e)),
                })
            })
        {
            println!("  Block entropy range: {:.4} - {:.4}", min_e, max_e);
        }
        return;
    }

    let width = args.width.unwrap_or_else(|| {
        let w = (blocks.len() as f64).sqrt() as usize;
        w.max(1)
    });
    let height = args.height.unwrap_or_else(|| {
        (blocks.len() + width - 1) / width
    });

    println!("  Blocks: {} (size={})", blocks.len(), args.block_size);
    println!("  Grid: {}x{}", width, height);

    if args.ascii {
        // ASCII art mode
        println!("\n{}", "Entropy Map:".bold());
        for y in 0..height {
            print!("  ");
            for x in 0..width {
                let idx = y * width + x;
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
        // PNG mode
        let mut pixels = Vec::with_capacity(width * height * 3);
        for y in 0..height {
            for x in 0..width {
                let idx = y * width + x;
                let e = if idx < blocks.len() { blocks[idx] } else { 0.0 };
                let (r, g, b) = entropy_to_color(e);
                pixels.push(r);
                pixels.push(g);
                pixels.push(b);
            }
        }

        let outpath = args.output.unwrap_or_else(|| {
            let stem = args.file.file_stem().unwrap_or_default().to_string_lossy();
            PathBuf::from(format!("{}_entropy.png", stem))
        });

        write_png(&outpath, width, height, &pixels);
        println!("  Written to {}", outpath.display());
    }

    // Show anomaly regions
    let mean: f64 = blocks.iter().sum::<f64>() / blocks.len() as f64;
    let std_dev: f64 = (blocks.iter().map(|e| (e - mean).powi(2)).sum::<f64>() / blocks.len() as f64).sqrt();

    let mut anomalies = Vec::new();
    for (i, &e) in blocks.iter().enumerate() {
        if (e - mean).abs() > std_dev * 2.0 {
            anomalies.push((i, e));
        }
    }

    if !anomalies.is_empty() {
        println!("\n{} ({} blocks)", "=== Anomaly Regions ===".bold(), anomalies.len());
        for (idx, e) in anomalies.iter().take(20) {
            let byte_offset = idx * args.block_size;
            println!("  0x{:08x} entropy={:.4} ({}σ from mean)", byte_offset, e,
                ((e - mean) / std_dev).abs() as i32);
        }
    }
}
