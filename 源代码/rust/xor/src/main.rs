use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "xor",
    version,
    about = "XOR cipher analysis and decryption",
    long_about = "XOR 密码分析与解密\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
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
    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct KnownKey {
    position: usize,
    key_hex: String,
    key_ascii: String,
    valid: u32,
    total: u32,
}

#[derive(Serialize)]
struct SingleByteResult {
    key: u8,
    key_char: String,
    score: f64,
    preview: String,
}

#[derive(Serialize)]
struct KeyLength {
    length: usize,
    normalized_distance: f64,
}

#[derive(Serialize)]
struct MultiByteResult {
    key_hex: String,
    key_ascii: String,
    score: f64,
    preview: String,
}

#[derive(Serialize)]
struct KeyOutcome {
    key_hex: String,
    text: String,
    hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
}

#[derive(Serialize)]
struct Report {
    input: String,
    size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    known: Option<Vec<KnownKey>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    brute8: Option<Vec<SingleByteResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_lengths: Option<Vec<KeyLength>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multi: Option<Vec<MultiByteResult>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<KeyOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hex_key: Option<KeyOutcome>,
}

fn english_score(data: &[u8]) -> f64 {
    let freq = [
        0.082, 0.015, 0.028, 0.043, 0.127, 0.022, 0.020, 0.061, 0.070, 0.002, 0.008, 0.040,
        0.024, 0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.091, 0.028, 0.010, 0.023, 0.002,
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
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

fn find_key_length(data: &[u8], max_key: usize) -> Vec<(usize, f64)> {
    let mut results = Vec::new();

    for key_len in 2..=max_key.min(data.len() / 2) {
        let num_blocks = data.len() / key_len;
        if num_blocks < 2 {
            continue;
        }

        let mut total_dist = 0u32;
        let mut count = 0u32;

        for i in 0..num_blocks.saturating_sub(1) {
            let block1 = &data[i * key_len..(i + 1) * key_len];
            let block2 = &data[(i + 1) * key_len..(i + 2) * key_len.min(data.len())];
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

fn break_multi_byte(data: &[u8], key_len: usize) -> Vec<(Vec<u8>, f64, Vec<u8>)> {
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
        .filter_map(|i| u8::from_str_radix(&clean[i..i + 2], 16).ok())
        .collect()
}

fn preview(data: &[u8], limit: usize) -> String {
    data.iter()
        .take(limit)
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

fn hex_string(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn ascii_key(key: &[u8]) -> String {
    key.iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect()
}

fn write_output(
    path: &Option<PathBuf>,
    data: &[u8],
    out: &Out,
    failed: &mut bool,
) -> Option<String> {
    if let Some(p) = path {
        match fs::write(p, data) {
            Ok(()) => Some(p.display().to_string()),
            Err(e) => {
                out.error(&format!("{e}"));
                *failed = true;
                None
            }
        }
    } else {
        None
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let data = if args.input.as_ref().map_or(false, |p| p.as_os_str() == "-") {
        let mut buf = Vec::new();
        if let Err(e) = std::io::stdin().read_to_end(&mut buf) {
            out.error(&format!("cannot read stdin: {e}"));
            return finish(exit::ERROR);
        }
        buf
    } else if let Some(path) = &args.input {
        match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                out.error(&format!("cannot read {}: {e}", path.display()));
                return finish(exit::ERROR);
            }
        }
    } else {
        out.error("No input file");
        return finish(exit::USAGE);
    };

    let has_op = args.known.is_some()
        || args.brute8
        || args.brute_multi > 0
        || args.key.is_some()
        || args.hex_key.is_some();
    if !has_op {
        out.error("No operation specified (use --known, --brute8, --brute-multi, --key or --hex-key)");
        return finish(exit::USAGE);
    }

    let mut report = Report {
        input: args
            .input
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
        size: data.len(),
        known: None,
        brute8: None,
        key_lengths: None,
        multi: None,
        key: None,
        hex_key: None,
    };
    let mut write_failed = false;

    if let Some(ref known) = args.known {
        let known_bytes = known.as_bytes();
        if known_bytes.is_empty() {
            out.error("Empty known plaintext");
            return finish(exit::USAGE);
        }
        if known_bytes.len() > data.len() {
            out.error("Known text longer than data");
            return finish(exit::ERROR);
        }

        let mut possible_keys = Vec::new();
        for i in 0..=data.len() - known_bytes.len() {
            let key_fragment: Vec<u8> = data[i..i + known_bytes.len()]
                .iter()
                .zip(known_bytes.iter())
                .map(|(c, p)| c ^ p)
                .collect();

            let mut valid = 0;
            let mut total = 0;
            for j in (0..data.len() - known_bytes.len()).step_by(known_bytes.len()) {
                if j == i {
                    continue;
                }
                total += 1;
                let decrypted: Vec<u8> = data[j..j + key_fragment.len()]
                    .iter()
                    .zip(key_fragment.iter())
                    .map(|(c, k)| c ^ k)
                    .collect();
                let score = english_score(&decrypted);
                if score > 0.03 {
                    valid += 1;
                }
            }

            if total == 0 || valid as f64 / total as f64 > 0.5 {
                possible_keys.push(KnownKey {
                    position: i,
                    key_hex: key_fragment
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect(),
                    key_ascii: ascii_key(&key_fragment),
                    valid,
                    total,
                });
            }
        }

        report.known = Some(possible_keys);
    }

    if args.brute8 {
        let results = break_single_byte(&data, args.top);
        report.brute8 = Some(
            results
                .into_iter()
                .map(|(key, score, decrypted)| SingleByteResult {
                    key,
                    key_char: (key as char).to_string(),
                    score,
                    preview: preview(&decrypted, 64),
                })
                .collect(),
        );
    }

    if args.brute_multi > 0 {
        let key_lengths = find_key_length(&data, args.brute_multi);
        let best = key_lengths.first().map(|(len, _)| *len);
        if let Some(best_len) = best {
            let results = break_multi_byte(&data, best_len);
            report.multi = Some(
                results
                    .into_iter()
                    .map(|(key, score, decrypted)| MultiByteResult {
                        key_hex: key.iter().map(|b| format!("{:02x}", b)).collect(),
                        key_ascii: ascii_key(&key),
                        score,
                        preview: preview(&decrypted, 64),
                    })
                    .collect(),
            );
        }
        report.key_lengths = Some(
            key_lengths
                .into_iter()
                .map(|(length, normalized_distance)| KeyLength {
                    length,
                    normalized_distance,
                })
                .collect(),
        );
    }

    if let Some(ref key_str) = args.key {
        let key = key_str.as_bytes();
        if key.is_empty() {
            out.error("Empty key");
            return finish(exit::USAGE);
        }
        let result = xor_with_key(&data, key);
        let text = preview(&result, 200);
        let hex = hex_string(&result[..result.len().min(64)]);
        let output = write_output(&args.output, &result, &out, &mut write_failed);
        report.key = Some(KeyOutcome {
            key_hex: hex_string(key),
            text,
            hex,
            output,
        });
    }

    if let Some(ref hex_str) = args.hex_key {
        let key = parse_hex(hex_str);
        if key.is_empty() {
            out.error("Invalid hex key");
            return finish(exit::ERROR);
        }
        let result = xor_with_key(&data, &key);
        let text = preview(&result, 200);
        let hex = hex_string(&result[..result.len().min(64)]);
        let output = write_output(&args.output, &result, &out, &mut write_failed);
        report.hex_key = Some(KeyOutcome {
            key_hex: hex_string(&key),
            text,
            hex,
            output,
        });
    }

    out.emit(
        || {
            println!("{} ({} bytes)", "Input:".bold(), report.size);

            if let Some(keys) = &report.known {
                println!("\n{}", "=== Known Plaintext Attack ===".bold());
                println!("  Known: \"{}\"", args.known.as_deref().unwrap_or(""));
                for k in keys.iter().take(5) {
                    println!(
                        "  Key at 0x{:04x}: [{}] (\"{}\")  valid={}/{}",
                        k.position, k.key_hex, k.key_ascii, k.valid, k.total
                    );
                }
            }

            if let Some(results) = &report.brute8 {
                println!("\n{}", "=== Single-byte XOR Brute Force ===".bold());
                for (i, r) in results.iter().enumerate() {
                    let score_color = if r.score > 0.06 {
                        "green"
                    } else if r.score > 0.03 {
                        "yellow"
                    } else {
                        "red"
                    };
                    println!(
                        "\n  {} key=0x{:02x} ({}) score={:.4}",
                        format!("{}.", i + 1).bold(),
                        r.key,
                        r.key_char,
                        r.score
                    );
                    println!("    {}", r.preview.color(score_color));
                }
            }

            if let Some(lengths) = &report.key_lengths {
                println!("\n{}", "=== Multi-byte XOR Brute Force ===".bold());
                println!("  Key length candidates (Kasiski):");
                for l in lengths.iter().take(8) {
                    println!(
                        "    len={}  normalized_dist={:.4}",
                        l.length, l.normalized_distance
                    );
                }

                if let Some(best) = lengths.first().map(|l| l.length) {
                    println!("\n  Trying key_len={}:", best);
                    if let Some(results) = &report.multi {
                        for r in results {
                            println!("    Key: [{}] \"{}\"", r.key_hex.green(), r.key_ascii.green());
                            println!("    Score: {:.4}", r.score);
                            println!("    Text:  {}", r.preview);
                        }
                    }
                }
            }

            if let Some(k) = &report.key {
                println!("\n{}", "=== XOR with key ===".bold());
                println!("  Text: {}", k.text);
                println!("  Hex:  {}...", k.hex);
                if let Some(o) = &k.output {
                    println!("  Written to {}", o);
                }
            }

            if let Some(k) = &report.hex_key {
                println!("\n{}", "=== XOR with hex key ===".bold());
                println!("  Key: {}", k.key_hex);
                println!("  Text: {}", k.text);
                println!("  Hex:  {}...", k.hex);
                if let Some(o) = &k.output {
                    println!("  Written to {}", o);
                }
            }
        },
        &report,
    );

    if write_failed {
        return finish(exit::ERROR);
    }

    let found = report.known.as_ref().map_or(false, |v| !v.is_empty())
        || report.brute8.as_ref().map_or(false, |v| !v.is_empty())
        || report.multi.as_ref().map_or(false, |v| !v.is_empty())
        || report.key.is_some()
        || report.hex_key.is_some();

    finish(if found { exit::OK } else { exit::NO_RESULT })
}
