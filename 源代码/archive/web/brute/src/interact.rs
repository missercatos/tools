#![forbid(unsafe_code)]

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use crate::engine::Engine;
use crate::session::resolve_url;

/// 全会话 REPL：命中后（或单独 --repl）在同一会话里继续手工访问/爆破
pub async fn repl(engine: &Arc<Engine>) -> anyhow::Result<()> {
    let session = engine.session.clone();
    let base = session.base.clone();
    println!(
        "已认证 REPL（会话 {}）。输入 help 查看命令。",
        &base
    );
    loop {
        print!("brute> ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        let n = io::stdin().lock().read_line(&mut line).unwrap_or(0);
        if n == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let cmd = it.next().unwrap_or("");
        match cmd {
            "help" | "?" | "h" => help(),
            "exit" | "quit" | "q" => break,
            "get" => {
                let p = it.next().unwrap_or("/");
                do_get(session.clone(), &resolve_url(&base, p)).await?;
            }
            "post" => {
                let p = it.next().unwrap_or("/");
                let body = it.next().unwrap_or("");
                let url = resolve_url(&base, p);
                let client = session.client().await;
                let fields: Vec<(String, String)> = body
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                match client.post(&url).form(&fields).send().await {
                    Ok(resp) => show(&url, resp).await,
                    Err(e) => eprintln!("[error] {e}"),
                }
            }
            "import" => {
                let f = it.next();
                match f {
                    Some(f) => match session.import_file(f) {
                        Ok(()) => println!("已导入 {f} 并切换会话"),
                        Err(e) => eprintln!("[error] {e}"),
                    },
                    None => eprintln!("用法: import <Netscape cookie 文件>"),
                }
            }
            "cookie" => {
                for (d, n, v) in session.dump() {
                    println!("{d}\t{n}={v}");
                }
            }
            "brute" => run_repl_brute(engine, &mut it).await?,
            _ => eprintln!("未知命令 {cmd}（help 查看）"),
        }
    }
    Ok(())
}

fn help() {
    println!(
        "命令:
  get <路径>              GET 请求（保存全文到 /tmp/brute_last.html）
  post <路径> <k=v&...>   POST 表单请求
  brute --dict <文件> [--workers N]   用当前会话继续字典爆破
  import <文件>           导入 Netscape cookie 并切换会话
  cookie                  导出当前会话 cookie
  exit / q                退出"
    );
}

async fn do_get(session: Arc<crate::session::Session>, url: &str) -> anyhow::Result<()> {
    let client = session.client().await;
    match client.get(url).send().await {
        Ok(resp) => show(url, resp).await,
        Err(e) => eprintln!("[error] {e}"),
    }
    Ok(())
}

async fn show(url: &str, resp: reqwest::Response) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let text = resp.text().await.unwrap_or_default();
    let len = text.len();
    println!("== {url} → {status} ({len}B) ==");
    for (k, v) in headers.iter().take(12) {
        println!("{k}: {v:?}");
    }
    let shown: String = text.chars().take(2500).collect();
    println!("{shown}");
    let _ = std::fs::write("/tmp/brute_last.html", &text);
}

async fn run_repl_brute(
    engine: &Arc<Engine>,
    it: &mut std::str::SplitWhitespace<'_>,
) -> anyhow::Result<()> {
    match it.next() {
        Some("--dict") => {
            let Some(d) = it.next() else {
                eprintln!("用法: brute --dict <文件>");
                return Ok(());
            };
            eprintln!("[repl] 用当前会话爆破字典 {d}");
            let hit = engine.run_dict(d).await?;
            eprintln!("[repl] 字典完成，命中: {hit}");
        }
        Some(other) => eprintln!("[repl] 未知参数 {other}（用法: brute --dict <文件>）"),
        None => eprintln!("用法: brute --dict <文件>"),
    }
    Ok(())
}