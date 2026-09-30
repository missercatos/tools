use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-visual", about = "Binary data visualization")]
struct Args {
    file: PathBuf,
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Width in pixels (default: sqrt of file size)
    #[arg(long)]
    width: Option<usize>,
    /// Height in pixels
    #[arg(long)]
    height: Option<usize>,
    /// Grayscale (1 byte per pixel)
    #[arg(long)]
    grayscale: bool,
    /// Map bytes to RGB: R=byte, G=offset%256, B=0
    #[arg(long)]
    rgb_mode: bool,
    /// ASCII art mode
    #[arg(long)]
    ascii: bool,
}

fn write_png(filepath: &PathBuf, width: usize, height: usize, pixels: &[u8], grayscale: bool) {
    use std::io::Write;
    let mut file = fs::File::create(filepath).unwrap();
    file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();

    let color_type = if grayscale { 0 } else { 2 };
    let bpp = if grayscale { 1 } else { 3 };

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(width as u32).to_be_bytes());
    ihdr.extend_from_slice(&(height as u32).to_be_bytes());
    ihdr.push(8);
    ihdr.push(color_type);
    ihdr.extend_from_slice(&[0, 0, 0]);
    write_chunk(&mut file, b"IHDR", &ihdr);

    let mut raw = Vec::new();
    for y in 0..height {
        raw.push(0);
        for x in 0..width {
            let idx = (y * width + x) * bpp;
            for c in 0..bpp {
                if idx + c < pixels.len() { raw.push(pixels[idx + c]); }
                else { raw.push(0); }
            }
        }
    }

    let compressed = deflate(&raw);
    write_chunk(&mut file, b"IDAT", &compressed);
    write_chunk(&mut file, b"IEND", &[]);
}

fn write_chunk(file: &mut fs::File, chunk_type: &[u8], data: &[u8]) {
    use std::io::Write;
    let mut c = 0xFFFFFFFFu32;
    for &b in chunk_type { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 }; }}
    for &b in data { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 }; }}
    c ^= 0xFFFFFFFF;

    file.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
    file.write_all(chunk_type).unwrap();
    file.write_all(data).unwrap();
    file.write_all(&c.to_be_bytes()).unwrap();
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x78, 0x01, 0x01]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&((!data.len() & 0xFFFF) as u16).to_be_bytes());
    out.extend_from_slice(data);
    let mut a: u32 = 1; let mut b: u32 = 0;
    for &d in data { a = (a + d as u32) % 65521; b = (b + a) % 65521; }
    out.extend_from_slice(&((b << 16) | a).to_be_bytes());
    out
}

fn main() {
    let args = Args::parse();

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => { eprintln!("{} {}", "error:".red().bold(), e); std::process::exit(1); }
    };

    println!("{}", format!("=== {} ===", args.file.display()).bold());
    println!("  Size: {} bytes", data.len());

    let width = args.width.unwrap_or((data.len() as f64).sqrt() as usize).max(1);
    let height = args.height.unwrap_or((data.len() + width - 1) / width);

    println!("  Grid: {}x{}", width, height);

    if args.ascii {
        let chars = " .:-=+*#%@";
        println!("\n{}", "Binary Visualization:".bold());
        for y in 0..height {
            print!("  ");
            for x in 0..width {
                let idx = y * width + x;
                if idx < data.len() {
                    let c = (data[idx] as usize * (chars.len() - 1)) / 255;
                    print!("{}", chars.chars().nth(c).unwrap_or(' '));
                }
            }
            println!();
        }
    } else {
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

        let outpath = args.output.unwrap_or_else(|| {
            PathBuf::from(format!("{}_visual.png", args.file.file_stem().unwrap_or_default().to_string_lossy()))
        });

        write_png(&outpath, width, height, &pixels, args.grayscale);
        println!("  Written to {}", outpath.display());
    }
}
