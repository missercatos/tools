//! dsstore - 解析 macOS .DS_Store，列出目录里的文件名清单
//! 纯 Rust 解析 Bud1/B-tree 二进制格式, 支持本地文件与 HTTP URL (可递归)

use clap::Parser;
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::collections::BTreeSet;
use std::process::ExitCode;

const MAX_RECURSE_DEPTH: u32 = 5;

#[derive(Parser, Debug)]
#[command(
    name = "dsstore",
    version,
    about = "解析 macOS .DS_Store，列出目录里的文件名清单",
    long_about = "dsstore -- 解析 .DS_Store，列出目录里的文件名清单\n\n用法: dsstore [--notes] [--recurse] <本地文件|URL>\n\n输入:\n  /path/.DS_Store   本地文件\n  http://x/.DS_Store URL(自动下载后解析)\n\n退出码: 0=有结果 1=无结果 2=用法错误 3=运行错误",
    after_help = "退出码: 0=有结果 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 本地文件或 URL
    #[arg(value_name = "本地文件|URL")]
    input: String,

    /// 同时显示每条记录的自定义属性备注(如 "flag here!")
    #[arg(long)]
    notes: bool,

    /// 仅 URL 模式: 发现子目录后递归抓取下一层 .DS_Store
    #[arg(long)]
    recurse: bool,

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
struct Record {
    name: String,
    id: String,
    note: String,
}

#[derive(Serialize)]
struct Report {
    source: String,
    mode: &'static str,
    names: Vec<Record>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<Child>,
}

#[derive(Serialize)]
struct Child {
    url: String,
    dir: String,
    names: Vec<Record>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<Child>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn utf16be(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn ascii_lossy(b: &[u8]) -> String {
    b.iter()
        .map(|&c| if c.is_ascii() { c as char } else { '\u{fffd}' })
        .collect()
}

fn skip_len(stype: &str) -> usize {
    match stype {
        "bool" => 1,
        "type" | "long" | "shor" => 4,
        "comp" | "dutc" | "icgo" | "lssp" | "modD" | "moDD" | "phyS" | "ph1S" => 8,
        "BKGD" => 12,
        "ICVO" | "LSVO" | "dscl" => 1,
        "Iloc" | "fwi0" => 16,
        "dilc" => 32,
        "lsvo" => 76,
        _ => 4,
    }
}

fn read_entry(block: &[u8], mut pos: usize, want_notes: bool) -> Option<(Record, usize)> {
    if pos + 8 > block.len() {
        return None;
    }
    let length = be32(&block[pos..pos + 4]) as usize;
    if length == 0 || length > 512 || pos + 4 + 2 * length + 8 > block.len() {
        return None;
    }
    let name = utf16be(&block[pos + 4..pos + 4 + 2 * length]);
    pos += 4 + 2 * length;
    if pos + 8 > block.len() {
        return None;
    }
    let sid = ascii_lossy(&block[pos..pos + 4]);
    let stype = ascii_lossy(&block[pos + 4..pos + 8]);
    pos += 8;
    let mut note = String::new();
    match stype.as_str() {
        "ustr" | "cmmt" | "extn" => {
            if pos + 4 > block.len() {
                return None;
            }
            let blen = be32(&block[pos..pos + 4]) as usize;
            pos += 4;
            if want_notes && sid == "note" && pos + 2 * blen <= block.len() {
                note = utf16be(&block[pos..pos + 2 * blen]);
            }
            pos += 2 * blen;
        }
        "blob" => {
            if pos + 4 > block.len() {
                return None;
            }
            let blen = be32(&block[pos..pos + 4]) as usize;
            pos += 4 + blen;
        }
        _ => {
            pos += skip_len(&stype);
        }
    }
    Some((
        Record {
            name,
            id: sid,
            note,
        },
        pos,
    ))
}

fn read_records(block: &[u8], want_notes: bool) -> Vec<Record> {
    let mut records = Vec::new();
    if block.len() < 8 {
        return records;
    }
    let count = be32(&block[4..8]) as usize;
    if count > 10000 {
        return records;
    }
    let mut pos = 8usize;
    for _ in 0..count {
        match read_entry(block, pos, want_notes) {
            Some((rec, next)) => {
                pos = next;
                if !rec.name.is_empty() {
                    records.push(rec);
                }
            }
            None => break,
        }
    }
    records
}

fn block_span(addr: usize) -> Option<(usize, usize)> {
    let off = (addr >> 5) << 5;
    let size = 1usize.checked_shl((addr & 0x1f) as u32)?;
    Some((off, size))
}

fn block_content(data: &[u8], addr: usize) -> Option<&[u8]> {
    let (off, size) = block_span(addr)?;
    let end = off.checked_add(4)?.checked_add(size)?;
    if end > data.len() {
        return None;
    }
    Some(&data[off + 4..end])
}

fn walk_node(
    data: &[u8],
    offsets: &[usize],
    num: usize,
    want_notes: bool,
    records: &mut Vec<Record>,
    visited: &mut BTreeSet<usize>,
    depth: u32,
) {
    if depth > 64 || visited.len() > 100_000 || num >= offsets.len() || !visited.insert(num) {
        return;
    }
    let node = match block_content(data, offsets[num]) {
        Some(n) if n.len() >= 8 => n,
        _ => return,
    };
    let next = be32(&node[0..4]) as usize;
    let ncount = be32(&node[4..8]) as usize;
    if next == 0 {
        records.extend(read_records(node, want_notes));
        return;
    }
    let mut p = 8usize;
    for _ in 0..ncount.min(100_000) {
        if p + 4 > node.len() {
            return;
        }
        let ptr = be32(&node[p..p + 4]) as usize;
        p += 4;
        match read_entry(node, p, want_notes) {
            Some((rec, np)) => {
                walk_node(data, offsets, ptr, want_notes, records, visited, depth + 1);
                if !rec.name.is_empty() {
                    records.push(rec);
                }
                p = np;
            }
            None => return,
        }
    }
    walk_node(data, offsets, next, want_notes, records, visited, depth + 1);
}

/// 正确路径: 分配器块表 -> DSDB 超级块 -> B-tree 根节点 -> 叶子记录
fn parse_btree(data: &[u8], want_notes: bool, records: &mut Vec<Record>) -> Result<(), String> {
    if data.len() < 36 {
        return Err("数据太短".to_string());
    }
    let root_off = be32(&data[8..12]) as usize;
    let size = be32(&data[12..16]) as usize;
    let root_off2 = be32(&data[16..20]) as usize;
    let root_end = root_off
        .checked_add(4)
        .and_then(|v| v.checked_add(size))
        .ok_or_else(|| "头部 offset 异常".to_string())?;
    if root_off != root_off2 || root_end > data.len() {
        return Err("头部 offset 异常".to_string());
    }
    let root = &data[root_off + 4..root_end];
    if root.len() < 12 {
        return Err("根块太短".to_string());
    }
    let count = be32(&root[0..4]) as usize;
    let padded = count.div_ceil(256) * 256;
    let mut offsets = Vec::with_capacity(count);
    for i in 0..count {
        let p = 8 + i * 4;
        if p + 4 > root.len() {
            break;
        }
        offsets.push(be32(&root[p..p + 4]) as usize);
    }
    let toc_pos = 8 + padded * 4;
    if toc_pos + 4 > root.len() {
        return Err("TOC 越界".to_string());
    }
    let toc_count = be32(&root[toc_pos..toc_pos + 4]) as usize;
    let mut pos = toc_pos + 4;
    let mut dsdb: Option<usize> = None;
    for _ in 0..toc_count.min(1024) {
        if pos + 1 > root.len() {
            break;
        }
        let nlen = root[pos] as usize;
        pos += 1;
        if pos + nlen + 4 > root.len() {
            break;
        }
        let name = ascii_lossy(&root[pos..pos + nlen]);
        let value = be32(&root[pos + nlen..pos + nlen + 4]) as usize;
        pos += nlen + 4;
        if name == "DSDB" {
            dsdb = Some(value);
        }
    }
    let super_num = dsdb.ok_or_else(|| "未找到 DSDB".to_string())?;
    if super_num >= offsets.len() {
        return Err("DSDB 指针越界".to_string());
    }
    let super_blk =
        block_content(data, offsets[super_num]).ok_or_else(|| "超级块越界".to_string())?;
    if super_blk.len() < 4 {
        return Err("超级块太短".to_string());
    }
    let root_node = be32(&super_blk[0..4]) as usize;
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    walk_node(
        data,
        &offsets,
        root_node,
        want_notes,
        records,
        &mut visited,
        0,
    );
    Ok(())
}

/// 旧版逻辑兜底: 把 TOC 值当索引, 目标块直接当记录块
fn parse_btree_legacy(
    data: &[u8],
    want_notes: bool,
    records: &mut Vec<Record>,
) -> Result<(), String> {
    if data.len() < 20 {
        return Err("数据太短".to_string());
    }
    let offset = be32(&data[8..12]) as usize;
    let size = be32(&data[12..16]) as usize;
    let offset2 = be32(&data[16..20]) as usize;
    let end = offset
        .checked_add(4)
        .and_then(|v| v.checked_add(size))
        .ok_or_else(|| "头部 offset 异常".to_string())?;
    if offset != offset2 || end > data.len() {
        return Err("头部 offset 异常".to_string());
    }
    let root = &data[offset + 4..end];
    if root.len() < 4 {
        return Err("根块太短".to_string());
    }
    let count = be32(&root[0..4]) as usize;
    if count == 0 || count >= 65536 {
        return Ok(());
    }
    let mut pos = 8usize;
    let mut addrs = Vec::new();
    for _ in 0..count {
        if pos + 4 > root.len() {
            break;
        }
        let addr = be32(&root[pos..pos + 4]) as usize;
        pos += 4;
        if addr != 0 {
            addrs.push(addr);
        }
    }
    let section_end = (count / 256 + 1) * 256 * 4 - count * 4;
    pos += section_end;
    if pos + 4 > root.len() {
        return Ok(());
    }
    let toc_count = be32(&root[pos..pos + 4]) as usize;
    pos += 4;
    let mut toc: Vec<(String, u32)> = Vec::new();
    for _ in 0..toc_count.min(128) {
        if pos + 1 > root.len() {
            break;
        }
        let tlen = root[pos] as usize;
        pos += 1;
        if pos + tlen + 4 > root.len() {
            break;
        }
        let tname = ascii_lossy(&root[pos..pos + tlen]);
        let block_id = be32(&root[pos + tlen..pos + tlen + 4]);
        toc.push((tname, block_id));
        pos += tlen + 4;
    }
    let block_id = match toc.iter().find(|(n, _)| n == "DSDB") {
        Some((_, id)) => *id as usize,
        None => return Ok(()),
    };
    if block_id >= addrs.len() {
        return Ok(());
    }
    let addr = addrs[block_id];
    let boff = (addr >> 5) << 5;
    let bsize = 1usize
        .checked_shl((addr & 0x1f) as u32)
        .ok_or_else(|| "块大小异常".to_string())?;
    let bend = boff
        .checked_add(4)
        .and_then(|v| v.checked_add(bsize))
        .ok_or_else(|| "块偏移异常".to_string())?;
    if bend > data.len() {
        return Ok(());
    }
    records.extend(read_records(&data[boff + 4..bend], want_notes));
    Ok(())
}

fn fallback_scan(data: &[u8], records: &mut Vec<Record>) {
    let n = data.len();
    let mut i = 0usize;
    while i + 12 < n {
        if data[i] == 0 && (0x20..0x7f).contains(&data[i + 1]) {
            let mut j = i;
            let mut s = String::new();
            while j + 1 < n && data[j] == 0 && (0x20..0x7f).contains(&data[j + 1]) {
                s.push(data[j + 1] as char);
                j += 2;
            }
            if s.chars().count() >= 3 {
                let tag = ascii_lossy(&data[j..(j + 4).min(n)]);
                if ["note", "ustr", "blob", "long", "bool"].contains(&tag.as_str()) {
                    records.push(Record {
                        name: s,
                        id: tag,
                        note: String::new(),
                    });
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }
}

fn parse(data: &[u8], want_notes: bool) -> (Vec<Record>, Vec<String>) {
    let mut warnings = Vec::new();
    if data.len() < 36 {
        warnings.push("文件太短，不是 .DS_Store".to_string());
        return (Vec::new(), warnings);
    }
    if &data[4..8] != b"Bud1" {
        warnings.push("警告: 魔数不是 Bud1，可能不是标准 .DS_Store".to_string());
    }
    let mut records = Vec::new();
    if parse_btree(data, want_notes, &mut records).is_err() {
        let mut legacy = Vec::new();
        match parse_btree_legacy(data, want_notes, &mut legacy) {
            Ok(()) => records = legacy,
            Err(e) => warnings.push(format!("B-tree 解析失败({e})，回退扫描")),
        }
    }
    if records.is_empty() {
        fallback_scan(data, &mut records);
    }
    (records, warnings)
}

fn dedup(records: Vec<Record>) -> Vec<Record> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in records {
        if r.name.is_empty() || !seen.insert(r.name.clone()) {
            continue;
        }
        out.push(r);
    }
    out
}

fn scan_names(data: &[u8]) -> Vec<String> {
    let mut out = BTreeSet::new();
    let n = data.len();
    let mut i = 0usize;
    while i + 2 < n {
        if data[i] == 0 && (0x20..0x7f).contains(&data[i + 1]) {
            let mut j = i;
            while j + 1 < n && data[j] == 0 && (0x20..0x7f).contains(&data[j + 1]) {
                j += 2;
            }
            if j - i >= 6 {
                out.insert(utf16be(&data[i..j]));
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.into_iter().collect()
}

fn fetch(client: &HttpClient, url: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .map_err(|e| format!("下载失败: {url} ({e})"))?;
    if !resp.is_success() {
        return Err(format!("下载失败: {url} (HTTP {})", resp.status));
    }
    Ok(resp.body)
}

fn walk(client: &HttpClient, url: &str, depth: u32, want_notes: bool) -> Option<Child> {
    if depth > MAX_RECURSE_DEPTH {
        return None;
    }
    let data = fetch(client, url).ok()?;
    if data.is_empty() {
        return None;
    }
    let dir = url.strip_suffix("/.DS_Store").unwrap_or(url).to_string();
    let (records, warnings) = parse(&data, want_notes);
    let mut child = Child {
        url: url.to_string(),
        dir,
        names: dedup(records),
        warnings,
        children: Vec::new(),
    };
    for name in scan_names(&data) {
        if name.contains('.') {
            continue;
        }
        let next = format!("{}/{name}/.DS_Store", child.dir);
        if let Some(c) = walk(client, &next, depth + 1, want_notes) {
            child.children.push(c);
        }
    }
    Some(child)
}

fn print_records(records: &[Record], want_notes: bool) {
    for r in records {
        if want_notes && !r.note.is_empty() {
            println!("{}\t(备注: {})", r.name, r.note);
        } else {
            println!("{}", r.name);
        }
    }
}

fn print_child(child: &Child, want_notes: bool) {
    println!();
    println!("[*] {} 的 .DS_Store:", child.dir);
    for w in &child.warnings {
        eprintln!("{w}");
    }
    print_records(&child.names, want_notes);
    for c in &child.children {
        print_child(c, want_notes);
    }
}

fn has_names(child: &Child) -> bool {
    !child.names.is_empty() || child.children.iter().any(has_names)
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let is_url = args.input.starts_with("http://") || args.input.starts_with("https://");

    let client = if is_url {
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
        match HttpClient::new(&opts) {
            Ok(c) => Some(c),
            Err(e) => {
                out.error(&format!("HTTP 初始化失败: {e}"));
                return finish(exit::ERROR);
            }
        }
    } else {
        None
    };

    let data = if is_url {
        let client = client.as_ref().expect("http client");
        match fetch(client, &args.input) {
            Ok(d) => d,
            Err(e) => {
                out.error(&e);
                return finish(exit::ERROR);
            }
        }
    } else {
        match std::fs::read(&args.input) {
            Ok(d) => d,
            Err(e) => {
                out.error(&format!("文件不存在: {} ({e})", args.input));
                return finish(exit::ERROR);
            }
        }
    };

    let (records, warnings) = parse(&data, args.notes);
    let mut report = Report {
        source: args.input.clone(),
        mode: if is_url { "url" } else { "file" },
        names: dedup(records),
        warnings,
        children: Vec::new(),
    };

    if args.recurse && is_url {
        let client = client.as_ref().expect("http client");
        if let Some(child) = walk(client, &args.input, 0, args.notes) {
            report.children.push(child);
        }
    }

    let found = !report.names.is_empty() || report.children.iter().any(has_names);

    out.emit(
        || {
            for w in &report.warnings {
                eprintln!("{w}");
            }
            print_records(&report.names, args.notes);
            for c in &report.children {
                print_child(c, args.notes);
            }
        },
        &report,
    );

    if found {
        finish(exit::OK)
    } else {
        finish(exit::NO_RESULT)
    }
}
