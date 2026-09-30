use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "qr",
    version,
    about = "QR code read/generate",
    long_about = "QR 码读取/生成\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
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
    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Report {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    module_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ascii_art: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hints: Option<Vec<String>>,
}

fn generate_qr_pattern(text: &[u8], size: usize) -> Vec<Vec<bool>> {
    let mut grid = vec![vec![false; size]; size];

    let draw_finder = |grid: &mut Vec<Vec<bool>>, ox: usize, oy: usize| {
        for y in 0..7 {
            for x in 0..7 {
                if x == 0 || x == 6 || y == 0 || y == 6 || (x >= 2 && x <= 4 && y >= 2 && y <= 4)
                {
                    grid[oy + y][ox + x] = true;
                }
            }
        }
    };

    draw_finder(&mut grid, 0, 0);
    draw_finder(&mut grid, size - 7, 0);
    draw_finder(&mut grid, 0, size - 7);

    let mut bit_pos = 0;
    let bits: Vec<bool> = text
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
        .collect();

    for y in 8..size - 8 {
        for x in 8..size - 8 {
            if bit_pos < bits.len() {
                grid[y][x] = bits[bit_pos];
                bit_pos += 1;
            }
        }
    }
    for y in 8..size - 8 {
        for x in 8..size - 8 {
            if !grid[y][x] && bit_pos >= bits.len() {
                grid[y][x] = (x + y) % 2 == 0;
            }
        }
    }

    grid
}

fn print_ascii_qr(grid: &[Vec<bool>]) {
    println!("\n{}", "QR Code (ASCII):".bold());
    println!("  {}", "  ".repeat(grid.len() + 4));
    for row in grid {
        print!("    ");
        for &cell in row {
            if cell {
                print!("██");
            } else {
                print!("  ");
            }
        }
        println!();
    }
    println!("  {}", "  ".repeat(grid.len() + 4));
}

fn write_qr_png(filepath: &Path, grid: &[Vec<bool>], module_size: usize) -> io::Result<()> {
    let height = grid.len();
    let width = if !grid.is_empty() { grid[0].len() } else { 0 };
    let img_w = width * module_size;
    let img_h = height * module_size;

    let mut file = fs::File::create(filepath)?;
    file.write_all(b"\x89PNG\r\n\x1a\n")?;

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&(img_w as u32).to_be_bytes());
    ihdr.extend_from_slice(&(img_h as u32).to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]);
    write_chunk(&mut file, b"IHDR", &ihdr)?;

    let mut raw = Vec::new();
    for y in 0..img_h {
        raw.push(0);
        for x in 0..img_w {
            let gy = y / module_size;
            let gx = x / module_size;
            if gy < height && gx < width && grid[gy][gx] {
                raw.push(0);
                raw.push(0);
                raw.push(0);
            } else {
                raw.push(255);
                raw.push(255);
                raw.push(255);
            }
        }
    }

    let compressed = deflate(&raw);
    write_chunk(&mut file, b"IDAT", &compressed)?;
    write_chunk(&mut file, b"IEND", &[])?;
    Ok(())
}

fn write_chunk(file: &mut fs::File, ct: &[u8], data: &[u8]) -> io::Result<()> {
    let mut c = 0xFFFFFFFFu32;
    for &b in ct {
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
    file.write_all(ct)?;
    file.write_all(data)?;
    file.write_all(&c.to_be_bytes())?;
    Ok(())
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x78, 0x01, 0x01]);
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&((!data.len() & 0xFFFF) as u16).to_be_bytes());
    out.extend_from_slice(data);
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

    if args.read {
        return run_read(&args, &out);
    }
    run_generate(&args, &out)
}

fn run_read(args: &Args, out: &Out) -> ExitCode {
    let image = match args.text.clone() {
        Some(t) => t,
        None => {
            out.error("Need image path for --read");
            return finish(exit::USAGE);
        }
    };

    let hints = vec![
        format!("zbarimg {}", image),
        format!(
            "python3 -c \"from PIL import Image; import pyzbar.pyzbar as z; print(z.decode(Image.open('{}'))[0].data.decode())\"",
            image
        ),
    ];

    let report = Report {
        mode: "read".to_string(),
        text: None,
        size: None,
        module_size: None,
        output: None,
        ascii_art: None,
        image: Some(image),
        hints: Some(hints.clone()),
    };

    out.emit(
        || {
            println!("{}", "=== QR Code Reader ===".bold());
            println!("  To read QR codes from images, use:");
            println!("    {}", hints[0]);
            println!("    {}", hints[1]);
            println!("\n  Install zbar:");
            println!("    pacman -S zbar");
        },
        &report,
    );

    finish(exit::NO_RESULT)
}

fn run_generate(args: &Args, out: &Out) -> ExitCode {
    let text = args.text.as_deref().unwrap_or("Hello, CTF!").to_string();
    let size = 25;
    let grid = generate_qr_pattern(text.as_bytes(), size);

    let show_ascii = args.ascii || args.output.is_none();
    let ascii_art = if show_ascii {
        Some(
            grid.iter()
                .map(|row| {
                    row.iter()
                        .map(|&cell| if cell { "██" } else { "  " })
                        .collect::<String>()
                })
                .collect(),
        )
    } else {
        None
    };

    if let Some(path) = &args.output {
        if let Err(e) = write_qr_png(path, &grid, args.module_size) {
            out.error(&format!("cannot write {}: {e}", path.display()));
            return finish(exit::ERROR);
        }
    }

    let report = Report {
        mode: "generate".to_string(),
        text: Some(text.clone()),
        size: Some(size),
        module_size: Some(args.module_size),
        output: args.output.as_ref().map(|p| p.display().to_string()),
        ascii_art,
        image: None,
        hints: None,
    };

    out.emit(
        || {
            println!("{}", "=== QR Code Generator ===".bold());
            println!("  Text: \"{}\"", text);

            if args.ascii {
                print_ascii_qr(&grid);
            }

            if let Some(ref outpath) = args.output {
                println!("  PNG written to {}", outpath.display());
            } else if !args.ascii {
                print_ascii_qr(&grid);
            }
        },
        &report,
    );

    out.info("\n  Tip: Use --output to save as PNG");
    out.info(&format!(
        "  Tip: For real QR codes, use: qrencode -o out.png '{}'",
        text
    ));

    finish(exit::OK)
}
