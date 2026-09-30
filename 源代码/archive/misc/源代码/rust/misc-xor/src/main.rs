use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-xor", about = "XOR cipher analysis and decryption")]
struct Args {
    /// Input file (or stdin with -)
    input: Option<PathBuf>,
    /// Known plaintext to find key
    #[arg(short, long)]
    known: Option<String>,
    /// Key (hex or plaintext)
    #[arg(short, long)]
    key: Option<String>,
    /// Single-byte brute force
    #[arg(long)]
    brute8: bool,
    /// Multi-byte key length to try (1-64)
    #[arg(long, default_value = "0")]
    brute_multi: usize,
    /// Output file
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// XOR with hex string
    #[arg(long)]
    hex_key: Option<String>,
    /// Show top N candidates
    #[arg(long, default_value = "10")]
    top: usize,
}

fn english_score(data: &[u8]) -> f64 {
    // English letter frequency
    let freq = [
        0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061,
        0.070, 0.002, 0.008, 0.040, 0.024, 0.067, 0.075, 0.019,
        0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
        0.020, 0.001,
    ];
    let mut score = 0.0;
    for &b in data {
        let idx = (b | 0x20) as usize;
        if idx >= b'a' as usize && idx <= b'z' as usize {
            score += freq[idx - b'a' as usize];
        } else if b == b' ' {
            score += 0.13;
        } else if b == b'\n' || b == b'\r' || b == b'\t' {
            score += 0.05;
        } else if b >= 0x20 && b < 0x7f {
            score += 0.01;
        } else {
            score -= 0.1;
        }
    }
    score / data.len() as f64
}

fn xor_single_byte(data: &[u8], key: u8) -> Vec<u8> {
    data.iter().map(|&b| b ^ key).collect()
}

fn xor_multi_byte(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().enumerate().map(|(i, &b)| b ^ key[i % key.len()]).collect()
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn find_key_length(data: &[u8], max_key: usize) -> Vec<(usize, f64)> {
    let mut results = Vec::new();

    for key_len in 2..=max_key.min(data.len() / 2) {
        let num_blocks = data.len() / key_len;
        if num_blocks < 2 { continue; }

        let mut total_dist = 0u32;
        let mut count = 0u32;

        for i in 0..num_blocks.saturating_sub(1) {
            let block1 = &data[i*key_len..(i+1)*key_len];
            let block2 = &data[(i+1)*key_len..(i+2)*key_len.min(data.len())];
            total_dist += hamming_distance(block1, block2);
            count += 1;
        }

        if count > 0 {
            let normalized = total_dist as f64 / count as f64 / key_len as f64;
            results.push((key_len, normalized));
        }
    }

    results.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    results
}

fn break_single_byte(data: &[u8], top: usize) -> Vec<(u8, f64, Vec<u8>)> {
    let mut results: Vec<(u8, f64, Vec<u8>)> = (0..=255)
        .map(|key| {
            let decrypted = xor_single_byte(data, key);
            let score = english_score(&decrypted);
            (key, score, decrypted)
        })
        .collect();

    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    results.truncate(top);
    results
}

fn break_multi_byte(data: &[u8], key_len: usize, _top: usize) -> Vec<(Vec<u8>, f64, Vec<u8>)> {
    let mut full_key = Vec::new();
    let mut total_score = 0.0;

    for i in 0..key_len {
        let block: Vec<u8> = data.iter().skip(i).step_by(key_len).cloned().collect();
        let mut best_key = 0u8;
        let mut best_score = f64::NEG_INFINITY;

        for key in 0..=255u8 {
            let decrypted = xor_single_byte(&block, key);
            let score = english_score(&decrypted);
            if score > best_score {
                best_score = score;
                best_key = key;
            }
        }
        full_key.push(best_key);
        total_score += best_score;
    }

    let decrypted = xor_multi_byte(data, &full_key);
    let avg_score = total_score / key_len as f64;
    vec![(full_key, avg_score, decrypted)]
}

fn xor_with_key(data: &[u8], key: &[u8]) -> Vec<u8> {
    xor_multi_byte(data, key)
}

fn parse_hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..clean.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&clean[i..i+2], 16).ok())
        .collect()
}

fn main() {
    let args = Args::parse();

    let data = if args.input.as_ref().map_or(false, |p| p.as_os_str() == "-") {
        let mut buf = Vec::new();
        use std::io::Read;
        std::io::stdin().read_to_end(&mut buf).unwrap();
        buf
    } else if let Some(path) = &args.input {
        match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{} {}", "error:".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("{} No input file", "error:".red().bold());
        std::process::exit(1);
    };

    println!("{} ({} bytes)", "Input:".bold(), data.len());

    // Known plaintext attack
    if let Some(ref known) = args.known {
        let known_bytes = known.as_bytes();
        println!("\n{}", "=== Known Plaintext Attack ===".bold());
        println!("  Known: \"{}\"", known);

        if known_bytes.len() > data.len() {
            eprintln!("{} Known text longer than data", "error:".red());
            std::process::exit(1);
        }

        // XOR known with ciphertext at various positions
        let mut possible_keys = Vec::new();
        for i in 0..=data.len() - known_bytes.len() {
            let key_fragment: Vec<u8> = data[i..i+known_bytes.len()].iter()
                .zip(known_bytes.iter())
                .map(|(c, p)| c ^ p)
                .collect();

            // Check if this key fragment makes sense at other positions
            let mut valid = 0;
            let mut total = 0;
            for j in (0..data.len() - known_bytes.len()).step_by(known_bytes.len()) {
                if j == i { continue; }
                total += 1;
                let decrypted: Vec<u8> = data[j..j+key_fragment.len()].iter()
                    .zip(key_fragment.iter())
                    .map(|(c, k)| c ^ k)
                    .collect();
                let score = english_score(&decrypted);
                if score > 0.03 { valid += 1; }
            }

            if total == 0 || valid as f64 / total as f64 > 0.5 {
                possible_keys.push((i, key_fragment, valid, total));
            }
        }

        for (pos, key_frag, valid, total) in possible_keys.iter().take(5) {
            let key_str: String = key_frag.iter().map(|b| format!("{:02x}", b)).collect();
            let key_ascii: String = key_frag.iter()
                .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                .collect();
            println!("  Key at 0x{:04x}: [{}] (\"{}\")  valid={}/{}",
                pos, key_str, key_ascii, valid, total);
        }
    }

    // Single-byte brute force
    if args.brute8 {
        println!("\n{}", "=== Single-byte XOR Brute Force ===".bold());
        let results = break_single_byte(&data, args.top);
        for (i, (key, score, decrypted)) in results.iter().enumerate() {
            let preview: String = decrypted.iter().take(64)
                .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                .collect();
            let score_color = if *score > 0.06 { "green" } else if *score > 0.03 { "yellow" } else { "red" };
            println!("\n  {} key=0x{:02x} ({}) score={:.4}",
                format!("{}.", i+1).bold(),
                key, *key as char, score);
            println!("    {}", preview.color(score_color));
        }
    }

    // Multi-byte brute force
    if args.brute_multi > 0 {
        println!("\n{}", "=== Multi-byte XOR Brute Force ===".bold());

        let key_lengths = find_key_length(&data, args.brute_multi);
        println!("  Key length candidates (Kasiski):");
        for (len, dist) in key_lengths.iter().take(8) {
            println!("    len={}  normalized_dist={:.4}", len, dist);
        }

        if let Some((best_len, _)) = key_lengths.first() {
            println!("\n  Trying key_len={}:", best_len);
            let results = break_multi_byte(&data, *best_len, args.top);
            for (key, score, decrypted) in results {
                let key_hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
                let key_ascii: String = key.iter()
                    .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                    .collect();
                let preview: String = decrypted.iter().take(64)
                    .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                    .collect();
                println!("    Key: [{}] \"{}\"", key_hex.green(), key_ascii.green());
                println!("    Score: {:.4}", score);
                println!("    Text:  {}", preview);
            }
        }
    }

    // XOR with provided key
    if let Some(ref key_str) = args.key {
        let key = key_str.as_bytes();
        let result = xor_with_key(&data, key);
        println!("\n{}", "=== XOR with key ===".bold());
        print_result(&result, &args.output);
    }

    // XOR with hex key
    if let Some(ref hex_str) = args.hex_key {
        let key = parse_hex(hex_str);
        if key.is_empty() {
            eprintln!("{} Invalid hex key", "error:".red());
            std::process::exit(1);
        }
        let result = xor_with_key(&data, &key);
        println!("\n{}", "=== XOR with hex key ===".bold());
        println!("  Key: {}", key.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "));
        print_result(&result, &args.output);
    }
}

fn print_result(data: &[u8], output: &Option<PathBuf>) {
    // Print text preview
    let preview: String = data.iter().take(200)
        .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
        .collect();
    println!("  Text: {}", preview);

    let hex_preview: String = data.iter().take(64)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    println!("  Hex:  {}...", hex_preview);

    if let Some(path) = output {
        match fs::write(path, data) {
            Ok(()) => println!("  Written to {}", path.display()),
            Err(e) => eprintln!("{} {}", "error:".red(), e),
        }
    }
}
