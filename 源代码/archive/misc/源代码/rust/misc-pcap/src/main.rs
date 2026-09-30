use clap::Parser;
use colored::*;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "misc-pcap", about = "PCAP analysis - extract files, DNS, HTTP")]
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
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(data[offset..offset+2].try_into().unwrap_or([0;2]))
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(data[offset..offset+4].try_into().unwrap_or([0;4]))
}

fn analyze_pcap(data: &[u8], args: &Args) {
    if data.len() < 24 {
        eprintln!("{} File too small for PCAP", "error:".red());
        return;
    }

    // PCAP global header
    let magic = read_u32(data, 0);
    let (swap, ts_resol) = match magic {
        0xa1b2c3d4 => (false, 1.0),
        0xd4c3b2a1 => (true, 1.0),
        0xa1b23c4d => (false, 0.000001),
        0x4d3cb2a1 => (true, 0.000001),
        _ => { eprintln!("{} Not a valid PCAP file (magic: 0x{:x})", "error:".red(), magic); return; }
    };

    let ver_major = read_u16(data, 4);
    let ver_minor = read_u16(data, 6);
    let link_type = read_u32(data, 20);

    println!("{}", format!("=== PCAP Analysis ===").bold());
    println!("  Version: {}.{}", ver_major, ver_minor);
    println!("  Link type: {}", match link_type {
        1 => "Ethernet",
        101 => "Raw IP",
        113 => "Linux cooked",
        _ => "Unknown",
    });

    let mut offset = 24;
    let mut packet_count = 0u32;
    let mut tcp_count = 0u32;
    let mut udp_count = 0u32;
    let mut http_requests = Vec::new();
    let mut dns_queries = Vec::new();
    let mut extracted_files = Vec::new();

    while offset + 16 <= data.len() {
        let ts_sec = read_u32(data, offset);
        let ts_usec = read_u32(data, offset + 4);
        let incl_len = read_u32(data, offset + 8) as usize;
        let orig_len = read_u32(data, offset + 12) as usize;

        offset += 16;

        if offset + incl_len > data.len() { break; }

        let packet_data = &data[offset..offset+incl_len];
        packet_count += 1;

        // Parse based on link type
        let (ip_start, proto) = match link_type {
            1 => { // Ethernet
                if packet_data.len() < 14 { offset += incl_len; continue; }
                let ethertype = read_u16(packet_data, 12);
                match ethertype {
                    0x0800 => { // IPv4
                        if packet_data.len() < 34 { offset += incl_len; continue; }
                        let ip_proto = packet_data[23];
                        (14, ip_proto)
                    }
                    0x86DD => { // IPv6
                        if packet_data.len() < 54 { offset += incl_len; continue; }
                        let ip_proto = packet_data[20];
                        (14, ip_proto)
                    }
                    _ => { offset += incl_len; continue; }
                }
            }
            101 => { // Raw IP
                if packet_data.len() < 20 { offset += incl_len; continue; }
                let ip_proto = packet_data[9];
                (0, ip_proto)
            }
            _ => { offset += incl_len; continue; }
        };

        match proto {
            6 => { // TCP
                tcp_count += 1;
                let tcp_start = ip_start + 20;
                if packet_data.len() > tcp_start + 20 {
                    let src_port = read_u16(packet_data, tcp_start);
                    let dst_port = read_u16(packet_data, tcp_start + 2);
                    let header_len = ((packet_data[tcp_start + 12] >> 4) & 0xf) as usize * 4;
                    let payload_start = tcp_start + header_len;

                    if payload_start < packet_data.len() {
                        let payload = &packet_data[payload_start..];

                        // HTTP detection
                        if (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080)
                            && payload.len() > 10
                        {
                            if let Ok(s) = std::str::from_utf8(payload) {
                                if s.starts_with("GET ") || s.starts_with("POST ") || s.starts_with("HTTP/") {
                                    let method = s.split_whitespace().next().unwrap_or("?");
                                    let uri = s.split_whitespace().nth(1).unwrap_or("?");
                                    http_requests.push(format!("{} {} -> port {}", method, uri,
                                        if dst_port == 80 || dst_port == 8080 { dst_port } else { src_port }));

                                    if args.hexdump && payload.len() > 0 {
                                        println!("\n  HTTP {}:{}", method, uri);
                                        let preview: String = payload.iter().take(200)
                                            .map(|&b| if b >= 0x20 && b < 0x7f { b as char } else { '.' })
                                            .collect();
                                        println!("    {}", preview);
                                    }
                                }
                            }
                        }

                        // File extraction from HTTP
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
                                    extracted_files.push((filename, payload.to_vec()));
                                }
                            }
                        }
                    }
                }
            }
            17 => { // UDP
                udp_count += 1;
                let udp_start = ip_start + 8;
                if packet_data.len() > udp_start + 8 {
                    let src_port = read_u16(packet_data, udp_start);
                    let dst_port = read_u16(packet_data, udp_start + 2);
                    let udp_len = read_u16(packet_data, udp_start + 4) as usize;
                    let payload_start = udp_start + 8;

                    // DNS
                    if (src_port == 53 || dst_port == 53) && packet_data.len() > payload_start + 12 {
                        let dns_data = &packet_data[payload_start..];
                        if dns_data.len() > 12 {
                            let qdcount = read_u16(dns_data, 4);
                            let mut qoffset = 12;

                            for _ in 0..qdcount {
                                let mut name = String::new();
                                while qoffset < dns_data.len() {
                                    let label_len = dns_data[qoffset] as usize;
                                    qoffset += 1;
                                    if label_len == 0 { break; }
                                    if qoffset + label_len <= dns_data.len() {
                                        if !name.is_empty() { name.push('.'); }
                                        name.push_str(&String::from_utf8_lossy(&dns_data[qoffset..qoffset+label_len]));
                                        qoffset += label_len;
                                    }
                                }
                                if !name.is_empty() {
                                    dns_queries.push(name);
                                }
                                qoffset += 4; // type + class
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        offset += incl_len;
    }

    println!("  Packets: {} (TCP: {}, UDP: {})", packet_count, tcp_count, udp_count);

    if args.http || args.all || args.dns || args.extract || args.streams {
        if !http_requests.is_empty() {
            println!("\n{}", format!("=== HTTP Requests ({}) ===", http_requests.len()).bold());
            for req in &http_requests {
                println!("  {}", req);
            }
        }

        if !dns_queries.is_empty() {
            println!("\n{}", format!("=== DNS Queries ({}) ===", dns_queries.len()).bold());
            let mut unique: Vec<&str> = dns_queries.iter().map(|s| s.as_str()).collect();
            unique.sort();
            unique.dedup();
            for q in &unique {
                println!("  {}", q);
            }
        }

        if !extracted_files.is_empty() {
            let outdir = args.output_dir.as_ref().map(|p| p.clone()).unwrap_or_else(|| {
                PathBuf::from("pcap_extracted")
            });
            fs::create_dir_all(&outdir).ok();

            println!("\n{}", format!("=== Extracted Files ({}) ===", extracted_files.len()).bold());
            for (name, content) in &extracted_files {
                let path = outdir.join(name);
                fs::write(&path, content).ok();
                println!("  {} -> {}", name.green(), path.display());
            }
        }
    }

    if args.stats || args.all {
        println!("\n{}", "=== Statistics ===".bold());
        println!("  Total packets: {}", packet_count);
        println!("  TCP: {}", tcp_count);
        println!("  UDP: {}", udp_count);
        println!("  HTTP requests: {}", http_requests.len());
        println!("  DNS queries: {}", dns_queries.len());
        println!("  Files extracted: {}", extracted_files.len());
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

    analyze_pcap(&data, &args);
}
