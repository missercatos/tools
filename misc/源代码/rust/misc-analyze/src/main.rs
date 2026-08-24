use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-analyze", about = "File comprehensive analysis")]
struct Args {
    file: PathBuf,
    #[arg(long)]
    entropy: bool,
    #[arg(long)]
    hexdump: bool,
    #[arg(long)]
    strings: bool,
    #[arg(long, default_value = "32")]
    strings_min: usize,
    #[arg(long)]
    appended: bool,
    #[arg(long)]
    all: bool,
}

// Magic signatures: (offset, bytes, description)
fn detect_magic(data: &[u8]) -> Vec<(&'static str, &'static str)> {
    let mut results = Vec::new();
    if data.len() < 4 { return results; }

    let checks: Vec<(usize, &[u8], &str)> = vec![
        (0, b"\x89PNG\r\n\x1a\n", "PNG image"),
        (0, b"\xff\xd8\xff", "JPEG image"),
        (0, b"GIF87a", "GIF87a image"),
        (0, b"GIF89a", "GIF89a image"),
        (0, b"BM", "BMP image"),
        (0, b"PK\x03\x04", "ZIP archive / Office document"),
        (0, b"PK\x05\x06", "ZIP archive (empty)"),
        (0, b"PK\x07\x08", "ZIP spanned"),
        (0, b"\x1f\x8b", "GZIP compressed"),
        (0, b"BZ", "BZIP2 compressed (check next byte)"),
        (0, b"\xfd7zXZ", "XZ compressed"),
        (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (0, b"Rar!\x1a\x07", "RAR archive"),
        (0, b"%PDF", "PDF document"),
        (0, b"\xd0\xcf\x11\xe0", "OLE2 (Office 97-2003)"),
        (0, b"SQLite format 3", "SQLite database"),
        (0, b"\x1a\x45\xdf\xa3", "Matroska/WebM"),
        (0, b"\x00\x00\x00\x1c\x66\x74\x79\x70", "MP4/MOV (ISOM)"),
        (0, b"\x00\x00\x00\x18\x66\x74\x79\x70", "MP4/MOV"),
        (0, b"\x00\x00\x00\x20\x66\x74\x79\x70", "MP4/MOV"),
        (0, b"RIFF", "RIFF container (WAV/AVI)"),
        (0, b"\x49\x49\x2a\x00", "TIFF (little-endian)"),
        (0, b"\x4d\x4d\x00\x2a", "TIFF (big-endian)"),
        (0, b"\x00\x00\x01\x00", "ICO image"),
        (0, b"\x00\x00\x02\x00", "CUR cursor"),
        (0, b"ID3", "MP3 with ID3 tag"),
        (0, b"\xff\xfb", "MP3 audio"),
        (0, b"\xff\xf3", "MP3 audio"),
        (0, b"\xff\xf2", "MP3 audio"),
        (0, b"OggS", "OGG container"),
        (0, b"fLaC", "FLAC audio"),
        (0, b"\x7fELF", "ELF executable"),
        (0, b"MZ", "PE/COFF (Windows)"),
        (0, b"\xca\xfe\xba\xbe", "Mach-O fat / Java class"),
        (0, b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
        (0, b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
        (0, b"\xce\xfa\xed\xfe", "Mach-O 32-bit (reverse)"),
        (0, b"\xcf\xfa\xed\xfe", "Mach-O 64-bit (reverse)"),
        (0, b"\x28\xb5\x2f\xfd", "Zstandard compressed"),
        (0, b"LRZ", "LRZIP compressed"),
        (0, b"Shr", "SZIP compressed"),
        (0, b"\x4c\x5a\x49\x50", "LZIP compressed"),
        (0, b"\x89\x4c\x5a\x4f", "LZO compressed"),
        (4, b"ftypisom", "MP4 (ISOM)"),
        (4, b"ftypmp4", "MP4"),
        (4, b"ftypqt", "QuickTime"),
        (0, b"	form", "IFF FORM"),
        (0, b"\x04\x22\x4d\x18", "LZ4 compressed"),
        (0, b"\x28\x84\x01", "LZMA compressed"),
    ];

    for (offset, sig, desc) in checks {
        if data.len() >= offset + sig.len() && &data[offset..offset+sig.len()] == sig {
            // Special case: BZ2 needs 'BZ' + 'h' or 'Z'
            if desc.starts_with("BZIP2") {
                if data.len() > 2 && (data[2] == b'h' || data[2] == b'Z') {
                    results.push(("Type", desc));
                }
                continue;
            }
            results.push(("Type", desc));
        }
    }

    if results.is_empty() {
        // Check for text files
        let printable = data.iter().take(512).filter(|&&b| b >= 0x20 && b < 0x7f || b == b'\n' || b == b'\r' || b == b'\t').count();
        let total = data.len().min(512);
        if total > 0 && printable * 100 / total > 90 {
            results.push(("Type", "Text file (ASCII/UTF-8)"));
        } else {
            results.push(("Type", "Unknown (no magic match)"));
        }
    }

    results
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &f in &freq {
        if f > 0 {
            let p = f as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn block_entropies(data: &[u8], block_size: usize) -> Vec<f64> {
    data.chunks(block_size)
        .map(|chunk| calculate_entropy(chunk))
        .collect()
}

fn detect_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut strings = Vec::new();
    let mut current = String::new();
    let mut start = 0;

    for (i, &b) in data.iter().enumerate() {
        if b >= 0x20 && b < 0x7f {
            if current.is_empty() { start = i; }
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                strings.push((start, current.clone()));
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        strings.push((start, current));
    }
    strings
}

fn detect_appended_data(data: &[u8]) -> Vec<(usize, usize, &'static str)> {
    let mut findings = Vec::new();
    // Check for PK after non-ZIP content
    if data.len() > 100 {
        for i in (100..data.len()-4).rev() {
            if &data[i..i+4] == b"PK\x03\x04" {
                findings.push((i, data.len() - i, "ZIP data appended at end"));
                break;
            }
        }
    }

    // Check for multiple file signatures
    let signatures: Vec<(&[u8], &str)> = vec![
        (b"\x89PNG", "PNG"),
        (b"\xff\xd8\xff", "JPEG"),
        (b"%PDF", "PDF"),
        (b"\x7fELF", "ELF"),
        (b"MZ", "PE"),
    ];

    for (sig, name) in &signatures {
        let positions: Vec<usize> = data.windows(sig.len())
            .enumerate()
            .filter(|(_, w)| w == sig)
            .map(|(i, _)| i)
            .collect();
        if positions.len() > 1 {
            for &pos in &positions[1..] {
                findings.push((pos, data.len() - pos, "Possible embedded file"));
            }
        }
    }

    findings
}

fn print_hexdump(data: &[u8], offset: usize, length: usize) {
    let end = (offset + length).min(data.len());
    for i in (offset..end).step_by(16) {
        print!("  {:08x}  ", i);
        for j in i..(i+16).min(end) {
            print!("{:02x} ", data[j]);
            if j - i == 7 { print!(" "); }
        }
        // Pad
        for _ in 0..(16 - (end - i).min(16)) {
            print!("   ");
        }
        // ASCII
        print!(" |");
        for j in i..(i+16).min(end) {
            let c = data[j];
            if c >= 0x20 && c < 0x7f { print!("{}", c as char); }
            else { print!("."); }
        }
        println!("|");
    }
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
    println!("  Size: {} bytes ({:.2} KB)", data.len(), data.len() as f64 / 1024.0);

    // Magic detection
    let magics = detect_magic(&data);
    println!("\n{}", "=== Identification ===".bold());
    for (label, value) in &magics {
        println!("  {}: {}", label.green().bold(), value);
    }

    // Entropy
    let overall_entropy = calculate_entropy(&data);
    println!("\n{}", "=== Entropy ===".bold());
    println!("  Overall: {:.4} / 8.0", overall_entropy);
    if overall_entropy > 7.5 {
        println!("  {} Likely encrypted or compressed", "!!".yellow());
    } else if overall_entropy > 6.8 {
        println!("  {} Possibly compressed", "!".yellow());
    } else if overall_entropy < 2.0 {
        println!("  {} Very low entropy (sparse/empty data)", "!".yellow());
    }

    // Block entropy
    if data.len() > 256 {
        let block_size = (data.len() / 64).max(256);
        let blocks = block_entropies(&data, block_size);
        let min_e = blocks.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_e = blocks.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        println!("  Block range: {:.4} - {:.4} (block_size={})", min_e, max_e, block_size);
        if max_e - min_e > 2.0 {
            println!("  {} High entropy variation — possible hidden data", "!!".yellow());
        }
    }

    // Strings
    if args.strings || args.all {
        let strings = detect_strings(&data, args.strings_min);
        println!("\n{} ({} found, min_len={})", "=== Strings ===".bold(), strings.len(), args.strings_min);
        for (offset, s) in strings.iter().take(50) {
            println!("  0x{:08x}: {}", offset, s);
        }
        if strings.len() > 50 {
            println!("  ... and {} more", strings.len() - 50);
        }
    }

    // Appended data
    if args.appended || args.all {
        let findings = detect_appended_data(&data);
        if !findings.is_empty() {
            println!("\n{}", "=== Appended/Embedded Data ===".bold());
            for (offset, size, desc) in &findings {
                println!("  0x{:08x} ({} bytes) - {}", offset, size, desc.red());
            }
        }
    }

    // Hexdump
    if args.hexdump || args.all {
        let len = data.len().min(256);
        println!("\n{} (first {} bytes)", "=== Hexdump ===".bold(), len);
        print_hexdump(&data, 0, len);
    }

    // Key offsets for common formats
    if args.all {
        println!("\n{}", "=== Key Offsets ===".bold());
        if data.len() > 0x84 {
            // PNG IHDR
            if &data[0..8] == b"\x89PNG\r\n\x1a\n" {
                let w = u32::from_be_bytes(data[16..20].try_into().unwrap_or([0;4]));
                let h = u32::from_be_bytes(data[20..24].try_into().unwrap_or([0;4]));
                let bpp = data[24];
                let ct = data[25];
                println!("  PNG IHDR: {}x{}, {}-bit, color_type={}", w, h, bpp, ct);
            }
            // ELF
            if data.len() > 20 && &data[0..4] == b"\x7fELF" {
                let is64 = data[4] == 2;
                let is_le = data[5] == 1;
                let et = if data.len() > 16 { u16::from_le_bytes(data[16..18].try_into().unwrap_or([0;2])) } else { 0 };
                let em = if data.len() > 18 { u16::from_le_bytes(data[18..20].try_into().unwrap_or([0;2])) } else { 0 };
                println!("  ELF: {}-bit, {}, type=0x{:x}, machine=0x{:x}",
                    if is64 { "64" } else { "32" },
                    if is_le { "LE" } else { "BE" },
                    et, em);
            }
        }
    }
}
