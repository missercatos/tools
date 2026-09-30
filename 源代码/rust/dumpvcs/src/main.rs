//! dumpvcs - 版本控制(VCS)目录泄露统一恢复工具（git/hg/svn）
//! 纯 Rust: 不依赖 svn/git/hg 命令行

mod git;
mod hg;
mod svn;

use clap::{Args, Parser, Subcommand};
use common::http::{HttpClient, HttpOpts};
use common::{exit, finish, Mode, Out};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

const EPILOG: &str = "子命令:
  dumpvcs auto <URL> [--out 目录] [--jobs N]
      自动探测 VCS 类型后直接利用
  dumpvcs git <URL> [--out 目录] [--jobs N]
      .git 泄露恢复: index/logs/HEAD/stash → 全历史文件
  dumpvcs hg <URL> [--out 目录] [--list] [--cat 文件] [--jobs N]
      .hg 泄露利用: fncache + revlog 解压 → 还原 + 自动 cat flag
  dumpvcs svn <URL> [--out 目录] [--list] [--cat 文件] [--jobs N]
      .svn 泄露利用: wc.db + pristine → 还原 + 自动 cat flag

示例:
  dumpvcs auto http://target/
  dumpvcs git http://target/.git
  dumpvcs git http://target/.git --jobs 8
  dumpvcs hg http://target --cat flag_xxx.txt
  dumpvcs svn http://target --list";

#[derive(Parser, Debug)]
#[command(
    name = "dumpvcs",
    version,
    about = "版本控制(VCS)目录泄露统一恢复工具（git/hg/svn）",
    long_about = "dumpvcs -- 版本控制(VCS)目录泄露统一恢复工具（整合 gitdump + hgdump + svndump）\n\n用法: dumpvcs <auto|git|hg|svn> <URL> [--out 目录] [--list] [--cat 文件] [--jobs N]\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    after_help = EPILOG
)]
struct Cli {
    #[command(subcommand)]
    tool: Tool,

    /// JSON 输出
    #[arg(long, global = true)]
    json: bool,

    /// HTTP 超时(秒)
    #[arg(long, global = true, default_value_t = 10, value_name = "SECS")]
    timeout: u64,

    /// HTTP 代理
    #[arg(long, global = true, value_name = "URL")]
    proxy: Option<String>,

    /// 跳过 TLS 证书校验
    #[arg(long, global = true)]
    insecure: bool,

    /// 自定义 User-Agent
    #[arg(long, global = true, value_name = "UA")]
    ua: Option<String>,

    /// Cookie
    #[arg(long, global = true, value_name = "COOKIE")]
    cookie: Option<String>,
}

#[derive(Args, Debug, Clone)]
struct CommonArgs {
    /// 目标 URL
    #[arg(value_name = "URL")]
    url: String,

    /// 输出目录
    #[arg(long, value_name = "目录")]
    out: Option<String>,

    /// 只列出清单，不下载
    #[arg(long)]
    list: bool,

    /// 还原后 cat 指定文件
    #[arg(long, value_name = "文件")]
    cat: Option<String>,

    /// 并发下载数（默认 1）
    #[arg(long, default_value_t = 1, value_name = "N")]
    jobs: usize,
}

#[derive(Args, Debug, Clone)]
struct GitArgs {
    /// 目标 URL
    #[arg(value_name = "URL")]
    url: String,

    /// 输出目录（默认 gitdump_restore）
    #[arg(long, default_value = "gitdump_restore", value_name = "目录")]
    out: String,

    /// 并发下载数（默认 1）
    #[arg(long, default_value_t = 1, value_name = "N")]
    jobs: usize,
}

#[derive(Subcommand, Debug)]
enum Tool {
    /// 自动探测 VCS 类型并利用
    #[command(
        about = "自动探测 VCS 类型并利用",
        long_about = "自动探测: 探测 /.git/HEAD、/.hg/requires、/.svn/wc.db"
    )]
    Auto(CommonArgs),

    /// .git 目录泄露恢复
    #[command(
        about = ".git 目录泄露恢复",
        long_about = "gitdump 移植: .git 泄露 → 恢复所有历史提交文件清单"
    )]
    Git(GitArgs),

    /// .hg(Mercurial) 泄露自动利用（fncache + revlog 解压）
    Hg(CommonArgs),

    /// .svn 泄露自动利用（wc.db 解析 + pristine 下载）
    Svn(CommonArgs),
}

pub fn encode_url(url: &str) -> String {
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

pub fn fetch(client: &HttpClient, url: &str) -> Option<Vec<u8>> {
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

pub fn parallel_map<T, R>(items: &[T], jobs: usize, f: impl Fn(&T) -> R + Sync) -> Vec<R>
where
    T: Sync,
    R: Send,
{
    let n = items.len();
    if n == 0 {
        return Vec::new();
    }
    let jobs = jobs.max(1).min(n);
    if jobs == 1 {
        return items.iter().map(f).collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<R>>> = (0..n).map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..jobs {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let r = f(&items[i]);
                *slots[i].lock().unwrap() = Some(r);
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap().unwrap())
        .collect()
}

pub fn host_slug(url: &str) -> String {
    url.split("://")
        .last()
        .unwrap_or(url)
        .replace(['/', ':'], "_")
}

pub fn safe_join(base: &Path, rel: &str) -> Option<PathBuf> {
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

pub fn write_out(base: &Path, rel: &str, data: &[u8]) -> std::io::Result<bool> {
    let dest = match safe_join(base, rel) {
        Some(d) => d,
        None => return Ok(false),
    };
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(dest, data)?;
    Ok(true)
}

pub fn walk_files(dir: &Path, base: &Path, depth: usize, out: &mut Vec<(String, PathBuf)>) {
    if depth > 64 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_files(&path, base, depth + 1, out);
        } else if let Ok(rel) = path.strip_prefix(base) {
            out.push((rel.to_string_lossy().replace('\\', "/"), path));
        }
    }
}

fn detect_vcs(client: &HttpClient, url: &str) -> Option<&'static str> {
    let url = url.trim_end_matches('/');
    if url.ends_with("/.git") {
        return Some("git");
    }
    if url.ends_with("/.hg") {
        return Some("hg");
    }
    if url.ends_with("/.svn") {
        return Some("svn");
    }
    let probes = [
        ("git", "/.git/HEAD"),
        ("hg", "/.hg/requires"),
        ("svn", "/.svn/wc.db"),
    ];
    let results = parallel_map(&probes, 3, |(_, path)| {
        fetch(client, &format!("{url}{path}")).is_some()
    });
    for (i, (kind, _)) in probes.iter().enumerate() {
        if results[i] {
            return Some(kind);
        }
    }
    None
}

fn run_auto(args: &CommonArgs, client: &HttpClient, out: &Out) -> ExitCode {
    let kind = match detect_vcs(client, &args.url) {
        Some(k) => k,
        None => {
            out.info("[-] 未检测到 git/hg/svn 泄露（探测过 /.git/HEAD、/.hg/requires、/.svn/wc.db）");
            return finish(exit::NO_RESULT);
        }
    };
    out.info(&format!("[+] 检测到: {kind}"));
    match kind {
        "git" => {
            let git_args = GitArgs {
                url: args.url.clone(),
                out: args
                    .out
                    .clone()
                    .unwrap_or_else(|| "gitdump_restore".to_string()),
                jobs: args.jobs,
            };
            let (report, code) = git::run(&git_args, client, out);
            out.emit(
                || {},
                &serde_json::json!({ "vcs": "git", "report": report }),
            );
            finish(code)
        }
        "hg" => {
            let (report, code) = hg::run(args, client, out);
            out.emit(
                || {},
                &serde_json::json!({ "vcs": "hg", "report": report }),
            );
            finish(code)
        }
        _ => {
            let (report, code) = svn::run(args, client, out);
            out.emit(
                || {},
                &serde_json::json!({ "vcs": "svn", "report": report }),
            );
            finish(code)
        }
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let cli = Cli::parse();
    let out = Out::new(Mode::from_flag(cli.json));

    let opts = HttpOpts {
        timeout: cli.timeout,
        proxy: cli.proxy.clone(),
        insecure: cli.insecure,
        user_agent: cli
            .ua
            .clone()
            .unwrap_or_else(|| HttpOpts::default().user_agent),
        cookie: cli.cookie.clone(),
        ..HttpOpts::default()
    };
    let client = match HttpClient::new(&opts) {
        Ok(c) => c,
        Err(e) => {
            out.error(&format!("HTTP 初始化失败: {e}"));
            return finish(exit::ERROR);
        }
    };

    match cli.tool {
        Tool::Auto(args) => run_auto(&args, &client, &out),
        Tool::Git(args) => {
            let (report, code) = git::run(&args, &client, &out);
            out.emit(|| {}, &report);
            finish(code)
        }
        Tool::Hg(args) => {
            let (report, code) = hg::run(&args, &client, &out);
            out.emit(|| {}, &report);
            finish(code)
        }
        Tool::Svn(args) => {
            let (report, code) = svn::run(&args, &client, &out);
            out.emit(|| {}, &report);
            finish(code)
        }
    }
}
