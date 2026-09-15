//! dumpvcs git: .git 目录泄露恢复
//! 纯 Rust: index/logs/HEAD/stash 解析 + loose/pack 对象读取 + 全历史文件恢复

use crate::{fetch, parallel_map, walk_files, write_out, GitArgs};
use common::http::HttpClient;
use common::Out;
use flate2::read::ZlibDecoder;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ObjKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

#[derive(Serialize, Clone)]
pub struct CommitInfo {
    sha: String,
    short: String,
    message: String,
    stash: bool,
}

#[derive(Serialize, Clone)]
pub struct FileInfo {
    path: String,
    blob: String,
    source: String,
}

#[derive(Serialize)]
pub struct GitReport {
    pub vcs: &'static str,
    pub target: String,
    pub out: String,
    pub index_files: usize,
    pub index_blobs: usize,
    pub log_commits: usize,
    pub stash_records: usize,
    pub objects_downloaded: usize,
    pub packs: Vec<String>,
    pub commits: Vec<CommitInfo>,
    pub files: Vec<FileInfo>,
    pub written: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub config_leaks: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn is_hex40(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
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
    let mut prev = String::new();
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
            let suffix = String::from_utf8_lossy(&data[pos..pos + nul]).to_string();
            pos += nul + 1;
            let keep = prev.len().saturating_sub(strip as usize);
            let path = format!("{}{}", &prev[..keep], suffix);
            prev = path.clone();
            out.push((path, sha));
        } else {
            if plen == 0x0FFF {
                let nul = data[pos..].iter().position(|&b| b == 0)?;
                plen = nul;
            }
            if pos + plen > data.len() {
                break;
            }
            let path = String::from_utf8_lossy(&data[pos..pos + plen]).to_string();
            pos += plen;
            prev = path.clone();
            out.push((path, sha));
            let rem = (pos - 12) % 8;
            if rem != 0 {
                pos += 8 - rem;
            }
        }
    }
    Some((count, out))
}

fn parse_log(text: &str) -> Vec<CommitInfo> {
    let mut out = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && is_hex40(parts[1]) {
            let msg = if parts.len() > 6 {
                parts[6..].join(" ")
            } else {
                String::new()
            };
            out.push(CommitInfo {
                sha: parts[1].to_string(),
                short: parts[1][..7].to_string(),
                message: msg,
                stash: false,
            });
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

fn parse_commit(body: &[u8]) -> (Option<String>, Vec<String>, String) {
    let text = String::from_utf8_lossy(body);
    let mut tree = None;
    let mut parents = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("tree ") {
            let v = rest.trim();
            if is_hex40(v) {
                tree = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("parent ") {
            let v = rest.trim();
            if is_hex40(v) {
                parents.push(v.to_string());
            }
        }
    }
    let message = text
        .split_once("\n\n")
        .map(|(_, m)| m.trim().to_string())
        .unwrap_or_default();
    (tree, parents, message)
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
    repo: String,
    objects_dir: PathBuf,
    packs: Mutex<Vec<Pack>>,
    packs_loaded: Mutex<bool>,
    downloaded: AtomicUsize,
}

impl<'a> GitStore<'a> {
    fn new(client: &'a HttpClient, repo: String, objects_dir: PathBuf) -> Self {
        GitStore {
            client,
            repo,
            objects_dir,
            packs: Mutex::new(Vec::new()),
            packs_loaded: Mutex::new(false),
            downloaded: AtomicUsize::new(0),
        }
    }

    fn loose_path(&self, sha: &str) -> PathBuf {
        self.objects_dir.join(&sha[..2]).join(&sha[2..])
    }

    fn read_loose(&self, sha: &str) -> Option<(ObjKind, Vec<u8>)> {
        let data = std::fs::read(self.loose_path(sha)).ok()?;
        parse_loose(&data)
    }

    fn fetch_loose(&self, sha: &str) -> bool {
        let url = format!("{}/.git/objects/{}/{}", self.repo, &sha[..2], &sha[2..]);
        let Some(data) = fetch(self.client, &url) else {
            return false;
        };
        if parse_loose(&data).is_none() {
            return false;
        }
        let path = self.loose_path(sha);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &data).is_err() {
            return false;
        }
        self.downloaded.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn ensure_packs(&self) {
        let mut loaded = self.packs_loaded.lock().unwrap();
        if *loaded {
            return;
        }
        *loaded = true;
        let Some(info) = fetch(
            self.client,
            &format!("{}/.git/objects/info/packs", self.repo),
        ) else {
            return;
        };
        let text = String::from_utf8_lossy(&info).to_string();
        let mut packs = self.packs.lock().unwrap();
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
            let Some(idx_data) = fetch(
                self.client,
                &format!("{}/.git/objects/pack/{idx_name}", self.repo),
            ) else {
                continue;
            };
            let Some(idx) = parse_pack_idx(&idx_data) else {
                continue;
            };
            let pack_dir = self.objects_dir.join("pack");
            let _ = std::fs::create_dir_all(&pack_dir);
            let _ = std::fs::write(pack_dir.join(&idx_name), &idx_data);
            packs.push(Pack {
                name: name.to_string(),
                idx,
                pack_path: pack_dir.join(name),
                data: None,
                cache: HashMap::new(),
            });
        }
    }

    fn pack_names(&self) -> Vec<String> {
        self.packs
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }

    fn pack_has(&self, sha: &str) -> bool {
        self.ensure_packs();
        let Some(key) = hex20(sha) else {
            return false;
        };
        self.packs
            .lock()
            .unwrap()
            .iter()
            .any(|p| p.idx.contains_key(&key))
    }

    fn read_packed(&self, sha: &str) -> Option<(ObjKind, Vec<u8>)> {
        self.ensure_packs();
        let key = hex20(sha)?;
        let mut packs = self.packs.lock().unwrap();
        for pack in packs.iter_mut() {
            let Some(&off) = pack.idx.get(&key) else {
                continue;
            };
            if pack.data.is_none() {
                let url = format!("{}/.git/objects/pack/{}", self.repo, pack.name);
                let Some(d) = fetch(self.client, &url) else {
                    continue;
                };
                if !d.starts_with(b"PACK") {
                    continue;
                }
                let _ = std::fs::write(&pack.pack_path, &d);
                pack.data = Some(d);
            }
            let Some(data) = pack.data.as_ref() else {
                continue;
            };
            if let Some(obj) = pack_read(data, off, &pack.idx, &mut pack.cache) {
                self.downloaded.fetch_add(1, Ordering::Relaxed);
                return Some(obj);
            }
        }
        None
    }

    fn read_object(&self, sha: &str) -> Option<(ObjKind, Vec<u8>)> {
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

fn resolve_tree(store: &GitStore, root: &str) -> BTreeMap<String, String> {
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

fn interesting_config(line: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?i)url\s*=|user\s*=|password|token|credential").expect("config regex")
    });
    re.is_match(line)
}

pub fn run(args: &GitArgs, client: &HttpClient, out: &Out) -> (GitReport, u8) {
    let mut repo = args.url.trim_end_matches('/').to_string();
    if repo.ends_with("/.git") {
        repo.truncate(repo.len() - 5);
    }
    let out_dir = args.out.clone();
    let objects_dir = Path::new(&out_dir).join(".git").join("objects");
    let _ = std::fs::create_dir_all(&objects_dir);
    let store = GitStore::new(client, repo.clone(), objects_dir.clone());

    out.info(&format!("[*] 目标: {repo}"));

    let mut index_count = 0usize;
    let mut known_blobs: BTreeSet<String> = BTreeSet::new();
    if let Some(idx) = fetch(client, &format!("{repo}/.git/index")) {
        if let Some((count, entries)) = parse_index(&idx) {
            index_count = count;
            for (_, sha) in entries {
                known_blobs.insert(sha);
            }
            out.info(&format!(
                "[*] index: {count} 个文件, 起始对象 {}",
                known_blobs.len()
            ));
        } else {
            out.info("[!] index 不可用, 仅按日志恢复");
        }
    } else {
        out.info("[!] index 不可用, 仅按日志恢复");
    }

    let mut commits: Vec<CommitInfo> = Vec::new();
    let mut log_commits = 0usize;
    if let Some(log) = fetch(client, &format!("{repo}/.git/logs/HEAD")) {
        commits.extend(parse_log(&String::from_utf8_lossy(&log)));
        log_commits = commits.len();
        out.info(&format!("[*] 日志: {log_commits} 次提交"));
    } else {
        out.info("[!] logs/HEAD 不可用");
    }

    let mut stash_records = 0usize;
    let mut stash_commits: Vec<CommitInfo> = Vec::new();
    if let Some(refs) = fetch(client, &format!("{repo}/.git/refs/stash")) {
        let s = String::from_utf8_lossy(&refs).trim().to_string();
        if is_hex40(&s) {
            stash_commits.push(CommitInfo {
                short: s[..7].to_string(),
                sha: s,
                message: "stash: (refs/stash)".to_string(),
                stash: true,
            });
            stash_records += 1;
        }
    }
    if let Some(log) = fetch(client, &format!("{repo}/.git/logs/refs/stash")) {
        for c in parse_log(&String::from_utf8_lossy(&log)) {
            stash_commits.push(CommitInfo {
                message: format!("stash: {}", c.message),
                stash: true,
                ..c
            });
            stash_records += 1;
        }
    }
    if stash_records > 0 {
        out.info(&format!("[*] stash: 发现 {stash_records} 条 stash 记录"));
    }
    commits.extend(stash_commits);

    if commits.is_empty() {
        let mut head_sha: Option<String> = None;
        if let Some(head) = fetch(client, &format!("{repo}/.git/HEAD")) {
            let h = String::from_utf8_lossy(&head).trim().to_string();
            if let Some(r) = h.strip_prefix("ref:") {
                let r = r.trim();
                if let Some(d) = fetch(client, &format!("{repo}/.git/{r}")) {
                    let s = String::from_utf8_lossy(&d).trim().to_string();
                    if is_hex40(&s) {
                        head_sha = Some(s);
                    }
                }
                if head_sha.is_none() {
                    if let Some(packed) = fetch(client, &format!("{repo}/.git/packed-refs")) {
                        head_sha = packed_ref_lookup(&String::from_utf8_lossy(&packed), r);
                    }
                }
            } else if is_hex40(&h) {
                head_sha = Some(h);
            }
        }
        if let Some(sha) = head_sha {
            out.info("[*] 按 HEAD 恢复");
            commits.push(CommitInfo {
                short: sha[..7].to_string(),
                sha,
                message: "HEAD".to_string(),
                stash: false,
            });
        }
    }

    let mut seen: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = commits.iter().map(|c| c.sha.clone()).collect();

    while let Some(sha) = stack.pop() {
        if !seen.insert(sha.clone()) {
            continue;
        }
        let Some((kind, body)) = store.read_object(&sha) else {
            continue;
        };
        match kind {
            ObjKind::Commit => {
                let (tree, parents, _) = parse_commit(&body);
                if let Some(t) = tree {
                    stack.push(t);
                }
                stack.extend(parents);
            }
            ObjKind::Tree => {
                for e in parse_tree(&body) {
                    stack.push(e.sha.clone());
                    if !e.is_dir() && !e.is_gitlink() {
                        known_blobs.insert(e.sha);
                    }
                }
            }
            _ => {}
        }
    }

    let missing: Vec<String> = known_blobs
        .iter()
        .filter(|b| !seen.contains(*b))
        .cloned()
        .collect();
    if !missing.is_empty() {
        let results = parallel_map(&missing, args.jobs, |sha| store.read_object(sha).is_some());
        for (sha, ok) in missing.iter().zip(results) {
            if ok {
                seen.insert(sha.clone());
            }
        }
    }

    out.info(&format!(
        "[*] 下载对象: {}",
        store.downloaded.load(Ordering::Relaxed)
    ));

    out.info("");
    out.info("[+] 提交历史:");
    for c in &commits {
        out.info(&format!("    {}  {}", c.short, c.message));
    }
    if commits.is_empty() {
        out.info("    (无日志)");
    }

    out.info("");
    out.info("[+] 恢复文件:");
    let mut commit_files: Vec<(usize, BTreeMap<String, String>)> = Vec::new();
    let mut printed: HashSet<String> = HashSet::new();
    for (i, c) in commits.iter().enumerate() {
        let Some((kind, body)) = store.read_object(&c.sha) else {
            continue;
        };
        if kind != ObjKind::Commit {
            continue;
        }
        let (tree, _, _) = parse_commit(&body);
        let Some(tree) = tree else {
            continue;
        };
        let files = resolve_tree(&store, &tree);
        if printed.insert(c.sha.clone()) {
            let label = if c.message.is_empty() {
                "none"
            } else {
                c.message.as_str()
            };
            out.info(&format!("    commit {} ({label}):", c.short));
            for name in files.keys() {
                out.info(&format!("        {name}"));
            }
        }
        commit_files.push((i, files));
    }

    let mut chosen: BTreeMap<String, (String, usize)> = BTreeMap::new();
    for (i, files) in &commit_files {
        if commits[*i].stash {
            continue;
        }
        for (name, blob) in files {
            chosen
                .entry(name.clone())
                .or_insert_with(|| (blob.clone(), *i));
        }
    }
    for (i, files) in commit_files.iter().rev() {
        if !commits[*i].stash {
            continue;
        }
        for (name, blob) in files {
            chosen.insert(name.clone(), (blob.clone(), *i));
        }
    }

    let mut written: Vec<String> = Vec::new();
    let mut file_infos: Vec<FileInfo> = Vec::new();
    for (name, (blob, ci)) in &chosen {
        let Some((kind, data)) = store.read_object(blob) else {
            continue;
        };
        if kind != ObjKind::Blob {
            continue;
        }
        if let Ok(true) = write_out(Path::new(&out_dir), name, &data) {
            written.push(name.clone());
            file_infos.push(FileInfo {
                path: name.clone(),
                blob: blob.clone(),
                source: commits[*ci].message.clone(),
            });
        }
    }
    out.info(&format!("[+] 写出文件: {} 个 -> {out_dir}/", written.len()));
    out.info("    提示: 被删除的文件在历史提交里, 用 git log 与 git show <commit>:<file> 找回");

    let mut config_leaks: Vec<String> = Vec::new();
    if let Some(cfg) = fetch(client, &format!("{repo}/.git/config")) {
        let text = String::from_utf8_lossy(&cfg);
        for line in text.lines() {
            if interesting_config(line) {
                config_leaks.push(line.trim().to_string());
            }
        }
        if !config_leaks.is_empty() {
            out.info("");
            out.info("[+] .git/config 线索:");
            for l in &config_leaks {
                out.info(&format!("    {l}"));
            }
        }
    }

    out.info("");
    out.info("[+] 扫描结果:");
    let mut flag_found = false;
    let mut flags: Vec<String> = Vec::new();
    let mut all_files: Vec<(String, PathBuf)> = Vec::new();
    walk_files(Path::new(&out_dir), Path::new(&out_dir), 0, &mut all_files);
    for (rel, path) in &all_files {
        let Ok(data) = std::fs::read(path) else {
            continue;
        };
        if data.is_empty() || data[..data.len().min(512)].contains(&0) {
            continue;
        }
        let s = String::from_utf8_lossy(&data);
        let lines: Vec<&str> = s
            .lines()
            .filter(|l| l.to_lowercase().contains("flag") || l.contains("ctfhub{"))
            .collect();
        if !lines.is_empty() {
            out.info(&format!("    {rel}:"));
            for l in lines {
                out.info(&format!("        {l}"));
            }
            flag_found = true;
        }
        flags.extend(common::scan_flags(&data));
    }
    if !flag_found {
        out.info("    (未自动发现 flag，请手动检查还原文件)");
    }
    flags.sort();
    flags.dedup();

    let objects_downloaded = store.downloaded.load(Ordering::Relaxed);
    let report = GitReport {
        vcs: "git",
        target: repo,
        out: out_dir,
        index_files: index_count,
        index_blobs: known_blobs.len(),
        log_commits,
        stash_records,
        objects_downloaded,
        packs: store.pack_names(),
        commits,
        files: file_infos,
        written: written.clone(),
        config_leaks,
        flags,
    };

    if written.is_empty() && objects_downloaded == 0 {
        (report, common::exit::NO_RESULT)
    } else {
        (report, common::exit::OK)
    }
}
