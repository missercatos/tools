use clap::Parser;
use colored::Colorize;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "pcap",
    version,
    about = "PCAP analysis - extract files, DNS, HTTP",
    long_about = "PCAP 分析: 提取文件/DNS/HTTP\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    file: PathBuf,
    #[arg(short, long)]
    output_dir: Option<PathBuf>,
    /// Extract HTTP bodies
    #[arg(long)]
    http: bool,
    /// Extract DNS queries
    #[arg(long)]
    dns: bool,
    /// Extract files (look for common signatures)
    #[arg(long)]
    extract: bool,
    /// Show all TCP/UDP streams
    #[arg(long)]
    streams: bool,
    /// Show statistics
    #[arg(long)]
    stats: bool,
    /// Analyze all
    #[arg(long)]
    all: bool,
    /// Show packet hexdump
    #[arg(long)]
    hexdump: bool,
    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct HttpRequest {
    method: String,
    uri: String,
    port: u16,
}

#[derive(Serialize)]
struct Hexdump {
    method: String,
    uri: String,
    preview: String,
}

#[derive(Serialize)]
struct ExtractedFile {
    name: String,
    path: String,
    size: usize,
}

#[derive(Serialize)]
struct Report {
    file: String,
    size: usize,
    version: String,
    link_type: String,
    packets: u32,
    tcp: u32,
    udp: u32,
    http_requests: Vec<HttpRequest>,
    dns_queries: Vec<String>,
    extracted_files: Vec<ExtractedFile>,
    hexdumps: Vec<Hexdump>,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn analyze_pcap(data: &[u8], args: &Args) -> Result<Report, String> {
    if data.len() < 24 {
        return Err("File too small for PCAP".into());
    }

    let magic = read_u32(data, 0);
    match magic {
        0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 => {}
        _ => return Err(format!("Not a valid PCAP file (magic: 0x{:x})", magic)),
    }

    let ver_major = read_u16(data, 4);
    let ver_minor = read_u16(data, 6);
    let link_type = read_u32(data, 20);
    let link_name = match link_type {
        1 => "Ethernet",
        101 => "Raw IP",
        113 => "Linux cooked",
        _ => "Unknown",
    }
    .to_string();

    let mut offset = 24;
    let mut packet_count = 0u32;
    let mut tcp_count = 0u32;
    let mut udp_count = 0u32;
    let mut http_requests: Vec<HttpRequest> = Vec::new();
    let mut dns_queries: Vec<String> = Vec::new();
    let mut extracted_raw: Vec<(String, Vec<u8>)> = Vec::new();
    let mut hexdumps: Vec<Hexdump> = Vec::new();

    while offset + 16 <= data.len() {
        let ts_sec = read_u32(data, offset);
        let incl_len = read_u32(data, offset + 8) as usize;

        offset += 16;

        if offset + incl_len > data.len() {
            break;
        }

        let packet_data = &data[offset..offset + incl_len];
        packet_count += 1;

        let (ip_start, proto) = match link_type {
            1 => {
                if packet_data.len() < 14 {
                    offset += incl_len;
                    continue;
                }
                let ethertype = read_u16(packet_data, 12);
                match ethertype {
                    0x0800 => {
                        if packet_data.len() < 34 {
                            offset += incl_len;
                            continue;
                        }
                        (14, packet_data[23])
                    }
                    0x86DD => {
                        if packet_data.len() < 54 {
                            offset += incl_len;
                            continue;
                        }
                        (14, packet_data[20])
                    }
                    _ => {
                        offset += incl_len;
                        continue;
                    }
                }
            }
            101 => {
                if packet_data.len() < 20 {
                    offset += incl_len;
                    continue;
                }
                (0, packet_data[9])
            }
            _ => {
                offset += incl_len;
                continue;
            }
        };

        match proto {
            6 => {
                tcp_count += 1;
                let tcp_start = ip_start + 20;
                if packet_data.len() > tcp_start + 20 {
                    let src_port = read_u16(packet_data, tcp_start);
                    let dst_port = read_u16(packet_data, tcp_start + 2);
                    let header_len = ((packet_data[tcp_start + 12] >> 4) & 0xf) as usize * 4;
                    let payload_start = tcp_start + header_len;

                    if payload_start < packet_data.len() {
                        let payload = &packet_data[payload_start..];

                        if (src_port == 80
                            || dst_port == 80
                            || src_port == 8080
                            || dst_port == 8080)
                            && payload.len() > 10
                        {
                            if let Ok(s) = std::str::from_utf8(payload) {
                                if s.starts_with("GET ")
                                    || s.starts_with("POST ")
                                    || s.starts_with("HTTP/")
                                {
                                    let method = s.split_whitespace().next().unwrap_or("?");
                                    let uri = s.split_whitespace().nth(1).unwrap_or("?");
                                    let port = if dst_port == 80 || dst_port == 8080 {
                                        dst_port
                                    } else {
                                        src_port
                                    };
                                    http_requests.push(HttpRequest {
                                        method: method.to_string(),
                                        uri: uri.to_string(),
                                        port,
                                    });

                                    if args.hexdump && !payload.is_empty() {
                                        let preview: String = payload
                                            .iter()
                                            .take(200)
                                            .map(|&b| {
                                                if (0x20..0x7f).contains(&b) {
                                                    b as char
                                                } else {
                                                    '.'
                                                }
                                            })
                                            .collect();
                                        hexdumps.push(Hexdump {
                                            method: method.to_string(),
                                            uri: uri.to_string(),
                                            preview,
                                        });
                                    }
                                }
                            }
                        }

                        if args.extract || args.all {
                            let signatures: Vec<(&[u8], &str)> = vec![
                                (b"\x89PNG", ".png"),
                                (b"\xff\xd8\xff", ".jpg"),
                                (b"%PDF", ".pdf"),
                                (b"PK\x03\x04", ".zip"),
                                (b"GIF8", ".gif"),
                            ];

                            for (sig, ext) in &signatures {
                                if payload.len() > sig.len() && &payload[..sig.len()] == *sig {
                                    let filename = format!("http_{:08x}{}", ts_sec, ext);
                                    extracted_raw.push((filename, payload.to_vec()));
                                }
                            }
                        }
                    }
                }
            }
            17 => {
                udp_count += 1;
                let udp_start = ip_start + 8;
                if packet_data.len() > udp_start + 8 {
                    let src_port = read_u16(packet_data, udp_start);
                    let dst_port = read_u16(packet_data, udp_start + 2);
                    let payload_start = udp_start + 8;

                    if (src_port == 53 || dst_port == 53)
                        && packet_data.len() > payload_start + 12
                    {
                        let dns_data = &packet_data[payload_start..];
                        if dns_data.len() > 12 {
                            let qdcount = read_u16(dns_data, 4);
                            let mut qoffset = 12;

                            for _ in 0..qdcount {
                                let mut name = String::new();
                                while qoffset < dns_data.len() {
                                    let label_len = dns_data[qoffset] as usize;
                                    qoffset += 1;
                                    if label_len == 0 {
                                        break;
                                    }
                                    if qoffset + label_len <= dns_data.len() {
                                        if !name.is_empty() {
                                            name.push('.');
                                        }
                                        name.push_str(&String::from_utf8_lossy(
                                            &dns_data[qoffset..qoffset + label_len],
                                        ));
                                        qoffset += label_len;
                                    }
                                }
                                if !name.is_empty() {
                                    dns_queries.push(name);
                                }
                                qoffset += 4;
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        offset += incl_len;
    }

    let mut extracted_files = Vec::new();
    if !extracted_raw.is_empty() {
        let outdir = args
            .output_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("pcap_extracted"));
        fs::create_dir_all(&outdir).ok();
        for (name, content) in extracted_raw {
            let path = outdir.join(&name);
            fs::write(&path, &content).ok();
            extracted_files.push(ExtractedFile {
                name,
                path: path.display().to_string(),
                size: content.len(),
            });
        }
    }

    Ok(Report {
        file: args.file.display().to_string(),
        size: data.len(),
        version: format!("{}.{}", ver_major, ver_minor),
        link_type: link_name,
        packets: packet_count,
        tcp: tcp_count,
        udp: udp_count,
        http_requests,
        dns_queries,
        extracted_files,
        hexdumps,
    })
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

    let report = match analyze_pcap(&data, &args) {
        Ok(r) => r,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };

    out.emit(
        || {
            println!("{}", format!("=== {} ===", report.file).bold());
            println!("  Size: {} bytes", report.size);
            println!("{}", "=== PCAP Analysis ===".bold());
            println!("  Version: {}", report.version);
            println!("  Link type: {}", report.link_type);

            for h in &report.hexdumps {
                println!("\n  HTTP {}:{}", h.method, h.uri);
                println!("    {}", h.preview);
            }

            println!(
                "  Packets: {} (TCP: {}, UDP: {})",
                report.packets, report.tcp, report.udp
            );

            if args.http || args.all || args.dns || args.extract || args.streams {
                if !report.http_requests.is_empty() {
                    println!(
                        "\n{}",
                        format!("=== HTTP Requests ({}) ===", report.http_requests.len()).bold()
                    );
                    for req in &report.http_requests {
                        println!("  {} {} -> port {}", req.method, req.uri, req.port);
                    }
                }

                if !report.dns_queries.is_empty() {
                    println!(
                        "\n{}",
                        format!("=== DNS Queries ({}) ===", report.dns_queries.len()).bold()
                    );
                    let mut unique: Vec<&str> =
                        report.dns_queries.iter().map(|s| s.as_str()).collect();
                    unique.sort();
                    unique.dedup();
                    for q in &unique {
                        println!("  {}", q);
                    }
                }

                if !report.extracted_files.is_empty() {
                    println!(
                        "\n{}",
                        format!("=== Extracted Files ({}) ===", report.extracted_files.len()).bold()
                    );
                    for f in &report.extracted_files {
                        println!("  {} -> {}", f.name.green(), f.path);
                    }
                }
            }

            if args.stats || args.all {
                println!("\n{}", "=== Statistics ===".bold());
                println!("  Total packets: {}", report.packets);
                println!("  TCP: {}", report.tcp);
                println!("  UDP: {}", report.udp);
                println!("  HTTP requests: {}", report.http_requests.len());
                println!("  DNS queries: {}", report.dns_queries.len());
                println!("  Files extracted: {}", report.extracted_files.len());
            }
        },
        &report,
    );

    finish(if report.packets == 0 {
        exit::NO_RESULT
    } else {
        exit::OK
    })
}
