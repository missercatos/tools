use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-qr", about = "QR code read/generate")]
struct Args {
    /// Text to encode (or file to read with --read)
    text: Option<String>,
    /// Read QR code from image
    #[arg(long)]
    read: bool,
    /// Generate PNG output
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Module size in pixels
    #[arg(long, default_value = "10")]
    module_size: usize,
    /// ASCII art mode (no PNG needed)
    #[arg(long)]
    ascii: bool,
}

// Simple QR-like encoding visualization (actual QR generation needs qrcode crate)
// This creates a DataMatrix/QR-style pattern for CTF
fn generate_qr_pattern(text: &[u8], size: usize) -> Vec<Vec<bool>> {
    // Create a simple grid with finder-like patterns
    let mut grid = vec![vec![false; size]; size];

    // Draw finder patterns (top-left, top-right, bottom-left)
    let draw_finder = |grid: &mut Vec<Vec<bool>>, ox: usize, oy: usize| {
        for y in 0..7 {
            for x in 0..7 {
                if x == 0 || x == 6 || y == 0 || y == 6
                    || (x >= 2 && x <= 4 && y >= 2 && y <= 4)
                {
                    grid[oy + y][ox + x] = true;
                }
            }
        }
    };

    draw_finder(&mut grid, 0, 0);
    draw_finder(&mut grid, size - 7, 0);
    draw_finder(&mut grid, 0, size - 7);

    // Data encoding (simple bit-stuffing of text)
    let mut bit_pos = 0;
    let bits: Vec<bool> = text.iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect();

    for y in 8..size-8 {
        for x in 8..size-8 {
            if bit_pos < bits.len() {
                grid[y][x] = bits[bit_pos];
                bit_pos += 1;
            }
        }
    }
    // Fill remaining with alternating pattern
    for y in 8..size-8 {
        for x in 8..size-8 {
            if !grid[y][x] && bit_pos >= bits.len() {
                grid[y][x] = (x + y) % 2 == 0;
            }
        }
    }

    grid
}

fn print_ascii_qr(grid: &[Vec<bool>]) {
    println!("\n{}", "QR Code (ASCII):".bold());
    // Top quiet zone
    println!("  {}", "  ".repeat(grid.len() + 4));
    for row in grid {
        print!("    ");
        for &cell in row {
            if cell { print!("██"); } else { print!("  "); }
        }
        println!();
    }
    println!("  {}", "  ".repeat(grid.len() + 4));
}

fn write_qr_png(filepath: &PathBuf, grid: &[Vec<bool>], module_size: usize) {
    use std::io::Write;
    let height = grid.len();
    let width = if !grid.is_empty() { grid[0].len() } else { 0 };
    let img_w = width * module_size;
    let img_h = height * module_size;

    let mut file = fs::File::create(filepath).unwrap();
    file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(img_w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(img_h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    write_chunk(&mut file, b"IHDR", &ihdr);

    let mut raw = Vec::new();
    for y in 0..img_h {
        raw.push(0);
        for x in 0..img_w {
            let gy = y / module_size;
            let gx = x / module_size;
            if gy < height && gx < width && grid[gy][gx] {
                raw.push(0); raw.push(0); raw.push(0);
            } else {
                raw.push(255); raw.push(255); raw.push(255);
            }
        }
    }

    let compressed = deflate(&raw);
    write_chunk(&mut file, b"IDAT", &compressed);
    write_chunk(&mut file, b"IEND", &[]);
}

fn write_chunk(file: &mut fs::File, ct: &[u8], data: &[u8]) {
    use std::io::Write;
    let mut c = 0xFFFFFFFFu32;
    for &b in ct { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 }; }}
    for &b in data { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 }; }}
    c ^= 0xFFFFFFFF;
    file.write_all(&(data.len() as u32).to_be_bytes()).unwrap();
    file.write_all(ct).unwrap();
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

    if args.read {
        // Read mode - suggest external tools
        if let Some(ref text) = args.text {
            println!("{}", "=== QR Code Reader ===".bold());
            println!("  To read QR codes from images, use:");
            println!("    zbarimg {}", text);
            println!("    python3 -c \"from PIL import Image; import pyzbar.pyzbar as z; print(z.decode(Image.open('{}'))[0].data.decode())\"", text);
            println!("\n  Install zbar:");
            println!("    pacman -S zbar");
        } else {
            eprintln!("{} Need image path for --read", "error:".red().bold());
        }
        return;
    }

    // Generate mode
    let text = args.text.as_deref().unwrap_or("Hello, CTF!");
    println!("{}", "=== QR Code Generator ===".bold());
    println!("  Text: \"{}\"", text);

    let size = 25; // Standard QR size
    let grid = generate_qr_pattern(text.as_bytes(), size);

    if args.ascii {
        print_ascii_qr(&grid);
    }

    if let Some(ref outpath) = args.output {
        write_qr_png(outpath, &grid, args.module_size);
        println!("  PNG written to {}", outpath.display());
    } else if !args.ascii {
        // Default: show ASCII
        print_ascii_qr(&grid);
    }

    println!("\n  Tip: Use --output to save as PNG");
    println!("  Tip: For real QR codes, use: qrencode -o out.png '{}'", text);
}
