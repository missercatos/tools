#![forbid(unsafe_code)]

mod auth;
mod defaults;
mod engine;
mod gate;
mod interact;
mod judge;
mod notify;
mod rules;
mod session;

use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "brute",
    version,
    about = "Web 爆破终端：登录爆破 / 验证码闸门 / 会话轮换 / 已认证 REPL",
    disable_help_subcommand = true
)]
pub struct Args {
    #[arg(value_name = "URL", help = "目标 URL（GET 模式可含 {user}/{pass} 占位符）")]
    pub url: String,
    #[arg(long, help = "POST 表单模板，如 user_id=admin&user_pass={}")]
    pub post: Option<String>,
    #[arg(long, help = "JSON 请求体模板，如 {\"user\":\"{user}\",\"pass\":\"{pass}\"}")]
    pub json: Option<String>,
    #[arg(long, help = "Basic 认证用户名（密码来自字典，GET 模式）")]
    pub basic_user: Option<String>,
    #[arg(long, default_value = "admin", help = "{user} 占位符取值")]
    pub user: String,
    #[arg(long, help = "密码字典文件（流式读取，支持断点）")]
    pub dict: Option<String>,
    #[arg(long, help = "内置默认口令分类：all|eyou|phpmyadmin|tomcat|router|dvr|weblogic")]
    pub defaults: Option<String>,
    #[arg(long, default_value_t = 6, help = "并发 worker 数")]
    pub workers: usize,
    #[arg(long, help = "请求最小间隔（毫秒），慢速模式")]
    pub interval_ms: Option<u64>,
    #[arg(long, help = "响应包含该字符串 → 判失败")]
    pub fail_contains: Option<String>,
    #[arg(long, help = "响应包含该字符串 → 判成功（优先于 fail）")]
    pub success_contains: Option<String>,
    #[arg(long, help = "期望成功状态码")]
    pub code: Option<u16>,
    #[arg(long, default_value = r"ctfhub\{[^}]+\}", help = "命中后 flag 提取正则")]
    pub flag_regex: String,
    #[arg(long, help = "断点续跑（从 offset 文件位置继续）")]
    pub resume: bool,
    #[arg(long, default_value = ".brute.offset", help = "进度偏移文件")]
    pub offset_file: String,
    #[arg(long, help = "验证码闸门：\"验证码URL:码字段[,时间字段...]\"，时间字段自动填当前时间戳")]
    pub gate_image: Option<String>,
    #[arg(long, default_value = "captcha", help = "闸门失效信号（响应包含即重新取码）")]
    pub gate_error: String,
    #[arg(long, help = "token 闸门：\"GET 页面URL:正则\"（取捕获组 1），配合 --gate-token-inject")]
    pub gate_token: Option<String>,
    #[arg(long, help = "token 注入字段（逗号分隔）")]
    pub gate_token_inject: Option<String>,
    #[arg(long, help = "手动闸门：\"提示语:注入字段\"")]
    pub gate_manual: Option<String>,
    #[arg(long, help = "会话失效信号（响应包含则换新会话并冷却）")]
    pub lockout: Option<String>,
    #[arg(long, default_value_t = 60, help = "换会话后冷却秒数")]
    pub lockout_wait: u64,
    #[arg(long, default_value_t = 10000, help = "请求超时（毫秒）")]
    pub timeout_ms: u64,
    #[arg(long, default_value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", help = "User-Agent")]
    pub ua: String,
    #[arg(long, help = "导入 Netscape 格式 cookie 文件")]
    pub import_cookie: Option<String>,
    #[arg(long, help = "HTTP 代理，如 http://127.0.0.1:8080")]
    pub proxy: Option<String>,
    #[arg(long, help = "字典变换: case(大小写变体)|suffix(数字/符号后缀)|all")]
    pub mangle: Option<String>,
    #[arg(long, help = "用户枚举模式: 用户字典文件（固定错误密码探测响应差异）")]
    pub enum_users: Option<String>,
    #[arg(long, help = "JSON 报告输出文件（结束时写入）")]
    pub report: Option<String>,
    #[arg(long, default_value_t = 2, help = "网络错误重试次数（默认 2）")]
    pub retry: u32,
    #[arg(long, help = "结束（或命中）后进入已认证 REPL")]
    pub repl: bool,
    #[arg(long, help = "规则：save:名称（存档本次打法）或 名称（复现）")]
    pub rule: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    match run(&args).await {
        Ok(true) => {
            eprintln!("[done] 命中，退出码 0");
            std::process::exit(0);
        }
        Ok(false) => {
            eprintln!("[done] 未命中，退出码 1");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[error] {e}");
            std::process::exit(2);
        }
    }
}

async fn run(args: &Args) -> anyhow::Result<bool> {
    if args.dict.is_some() && args.defaults.is_some() {
        anyhow::bail!("--dict 与 --defaults 不能同时使用");
    }
    if args.post.is_some() && args.json.is_some() {
        anyhow::bail!("--post 与 --json 不能同时使用");
    }
    if args.basic_user.is_some() && (args.post.is_some() || args.json.is_some()) {
        anyhow::bail!("--basic-user 与 --post/--json 不能同时使用");
    }
    if args.enum_users.is_some() && (args.dict.is_some() || args.defaults.is_some()) {
        anyhow::bail!("--enum-users 与 --dict/--defaults 不能同时使用");
    }

    if let Some(r) = &args.rule {
        if let Some(name) = r.strip_prefix("save:") {
            let argv = rules::argv_of(args);
            rules::save(name, &argv)?;
            eprintln!("[rules] 已存档 {} 条参数到 rules/{name}", argv.len());
            return Ok(false);
        }
        let argv = rules::load(r)?;
        eprintln!("[rules] 复现 rules/{r}: brute {}", argv.join(" "));
        Command::new(std::env::current_exe()?.as_os_str())
            .args(&argv)
            .status()?;
        return Ok(false);
    }

    let session = Arc::new(session::Session::new(args)?);
    let auth = auth::Auth::new(args)?;
    let judge = judge::Judge::new(args)?;
    let gate = gate::Gate::new(args)?;
    let (ntx, njoin) = notify::spawn();
    let engine = Arc::new(engine::Engine::new(args, session.clone(), auth, judge, gate, ntx)?);

    let start = Instant::now();
    let hit = if let Some(cat) = &args.defaults {
        let pairs = defaults::get(cat);
        eprintln!("[defaults] 分类 {cat}: {} 组口令", pairs.len());
        engine.run_pairs(pairs).await?
    } else if let Some(d) = &args.dict {
        engine.run_dict(d).await?
    } else if let Some(uf) = &args.enum_users {
        engine.run_enum(uf).await?
    } else if args.repl {
        false
    } else {
        anyhow::bail!("需要 --dict / --defaults / --enum-users / --repl 之一")
    };

    if let Some(rp) = &args.report {
        let rep = serde_json::json!({
            "url": args.url,
            "attempts": engine.attempts(),
            "elapsed_ms": start.elapsed().as_millis(),
            "hit": hit,
            "hits": engine.hits(),
        });
        std::fs::write(rp, serde_json::to_string_pretty(&rep)?)?;
        eprintln!("[report] 报告已写入 {rp}");
    }

    eprintln!(
        "[done] {} 次请求，耗时 {:?}，命中: {}",
        engine.attempts(),
        start.elapsed(),
        hit
    );

    if args.repl {
        interact::repl(&engine).await?;
    }
    drop(njoin.join());
    Ok(hit)
}