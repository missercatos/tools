use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-carve", about = "File carving - recover files from binary dumps")]
struct Args {
    file: PathBuf,
    #[arg(short, long)]
    output_dir: Option<PathBuf>,
    /// Also search for ZIP (common)
    #[arg(long)]
    zip: bool,
    /// Search for all known signatures
    #[arg(long)]
    all: bool,
    /// List only, don't extract
    #[arg(long)]
    list: bool,
    /// Minimum file size
    #[arg(long, default_value = "16")]
    min_size: usize,
}

struct Signature {
    name: &'static str,
    magic: &'static [u8],
    end: Option<&'static [u8]>,
    max_size: usize,
}

fn get_signatures() -> Vec<Signature> {
    vec![
        Signature { name: "PNG", magic: b"\x89PNG\r\n\x1a\n", end: Some(b"IEND"), max_size: 100_000_000 },
        Signature { name: "JPEG", magic: b"\xff\xd8\xff", end: Some(b"\xff\xd9"), max_size: 50_000_000 },
        Signature { name: "GIF", magic: b"GIF8", end: Some(b"\x00\x3b"), max_size: 50_000_000 },
        Signature { name: "ZIP", magic: b"PK\x03\x04", end: None, max_size: 100_000_000 },
        Signature { name: "PDF", magic: b"%PDF", end: Some(b"%%EOF"), max_size: 100_000_000 },
        Signature { name: "ELF", magic: b"\x7fELF", end: None, max_size: 50_000_000 },
        Signature { name: "PE", magic: b"MZ", end: None, max_size: 50_000_000 },
        Signature { name: "GZIP", magic: b"\x1f\x8b", end: None, max_size: 100_000_000 },
        Signature { name: "BZIP2", magic: b"BZh", end: None, max_size: 100_000_000 },
        Signature { name: "7Z", magic: b"7z\xbc\xaf\x27\x1c", end: None, max_size: 100_000_000 },
        Signature { name: "RAR", magic: b"Rar!\x1a\x07", end: None, max_size: 100_000_000 },
        Signature { name: "SQLite", magic: b"SQLite format 3", end: None, max_size: 1_000_000_000 },
        Signature { name: "PCAP", magic: b"\xd4\xc3\xb2\xa1", end: None, max_size: 500_000_000 },
        Signature { name: "TIFF", magic: b"II\x2a\x00", end: None, max_size: 100_000_000 },
        Signature { name: "FLAC", magic: b"fLaC", end: None, max_size: 100_000_000 },
        Signature { name: "OGG", magic: b"OggS", end: None, max_size: 100_000_000 },
    ]
}

fn carve_file(data: &[u8], sig: &Signature, start: usize) -> Option<Vec<u8>> {
    if let Some(end_magic) = sig.end {
        // Find end marker
        let search_start = start + sig.magic.len();
        if search_start >= data.len() { return None; }

        for i in search_start..data.len().saturating_sub(end_magic.len()) {
            if &data[i..i+end_magic.len()] == end_magic {
                let end = i + end_magic.len();
                if end - start >= sig.max_size { return None; }
                return Some(data[start..end].to_vec());
            }
        }

        // If no end found, try to extract a reasonable chunk
        let max_search = (start + sig.max_size).min(data.len());
        if max_search > start {
            return Some(data[start..max_search].to_vec());
        }
    } else {
        // No end marker, extract up to max_size
        let end = (start + sig.max_size).min(data.len());
        return Some(data[start..end].to_vec());
    }
    None
}

fn main() {
    let args = Args::parse();

    let data = match fs::read(&args.file) {
        Ok(d) => d,
        Err(e) => { eprintln!("{} {}", "error:".red().bold(), e); std::process::exit(1); }
    };

    println!("{}", format!("=== {} ===", args.file.display()).bold());
    println!("  Size: {} bytes", data.len());

    let sigs = get_signatures();
    let mut found = Vec::new();

    for sig in &sigs {
        let mut i = 0;
        while i + sig.magic.len() <= data.len() {
            if &data[i..i+sig.magic.len()] == sig.magic {
                if let Some(carved) = carve_file(&data, sig, i) {
                    if carved.len() >= args.min_size {
                        found.push((i, sig.name, carved));
                    }
                }
                i += sig.magic.len();
            } else {
                i += 1;
            }
        }
    }

    if found.is_empty() {
        println!("\n  {} No files found", "warning:".yellow());
        return;
    }

    println!("\n{}", format!("=== Found {} file(s) ===", found.len()).bold());

    let outdir = args.output_dir.unwrap_or_else(|| {
        let stem = args.file.file_stem().unwrap_or_default().to_string_lossy();
        PathBuf::from(format!("{}_carved", stem))
    });

    if !args.list {
        fs::create_dir_all(&outdir).ok();
    }

    for (offset, name, data) in &found {
        let preview: String = data.iter().take(32).map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
        println!("  {} 0x{:08x} ({:>8} bytes)  {}", name.green().bold(), offset, data.len(), preview);

        if !args.list {
            let filename = format!("{}/{:08x}_{}.bin", outdir.display(), offset, name);
            fs::write(&filename, data).ok();
            println!("    -> {}", filename);
        }
    }

    if !args.list {
        println!("\n  Output: {}", outdir.display());
    }
}
