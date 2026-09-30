//! ctfhelp - CTF 工具集方向导航 (树形展示)

use clap::Parser;
use colored::Colorize;
use common::{exit, finish};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "ctfhelp",
    version,
    about = "CTF 工具集方向导航: 树形展示方向/类型/工具",
    long_about = "用法:\n  ctfhelp              显示完整工具树\n  ctfhelp --web        只看Web方向\n  ctfhelp --pwn        只看PWN方向\n  ctfhelp --misc       只看MISC方向\n  ctfhelp --search xx  搜索工具\n  ctfhelp --list       列出所有工具名",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 只看Web方向
    #[arg(long, conflicts_with_all = ["pwn", "misc"])]
    web: bool,

    /// 只看PWN方向
    #[arg(long, conflicts_with_all = ["web", "misc"])]
    pwn: bool,

    /// 只看MISC方向
    #[arg(long, conflicts_with_all = ["web", "pwn"])]
    misc: bool,

    /// 搜索工具 (名称或描述)
    #[arg(long, short = 's', value_name = "KEY")]
    search: Option<String>,

    /// 列出所有工具名
    #[arg(long, short = 'l')]
    list: bool,
}

struct Tool {
    name: &'static str,
    desc: &'static str,
}

struct Category {
    name: &'static str,
    tools: &'static [Tool],
}

struct Direction {
    name: &'static str,
    categories: &'static [Category],
}

const TOOLS: &[Direction] = &[
    Direction {
        name: "Web安全",
        categories: &[
            Category {
                name: "信息泄露",
                tools: &[
                    Tool { name: "trav", desc: "目录遍历(内置字典/wildcard过滤/限速)" },
                    Tool { name: "dumpvcs", desc: "VCS泄露恢复(git/hg/svn自动识别+flag扫描)" },
                    Tool { name: "gitdump", desc: ".git目录泄露恢复" },
                    Tool { name: "githack", desc: "GitHack风格.git泄露利用+flag扫描" },
                    Tool { name: "hgdump", desc: ".hg泄露利用" },
                    Tool { name: "svndump", desc: ".svn泄露利用" },
                    Tool { name: "dsstore", desc: ".DS_Store解析(支持递归URL)" },
                ],
            },
            Category {
                name: "爆破",
                tools: &[Tool { name: "brute", desc: "Web登录爆破终端(Rust，验证码/会话轮换/代理)" }],
            },
            Category {
                name: "注入",
                tools: &[
                    Tool { name: "sqli", desc: "SQL注入自动化(五步方法论/union/盲注/tamper)" },
                    Tool { name: "lfi", desc: "文件包含探测(php://filter/日志投毒)" },
                    Tool { name: "ssti", desc: "模板注入检测+payload字典" },
                    Tool { name: "cmdi", desc: "命令注入payload+反弹shell生成" },
                ],
            },
            Category {
                name: "认证绕过",
                tools: &[Tool { name: "jwt", desc: "JWT解码/伪造(alg none/HS256)/弱密钥爆破" }],
            },
            Category {
                name: "杂项",
                tools: &[
                    Tool { name: "encdec", desc: "编码转换(url/base64/hex/rot13/html/unicode/gzip)" },
                    Tool { name: "xssserv", desc: "XSS回调服务器(cookie/路径捕获)" },
                ],
            },
        ],
    },
    Direction {
        name: "PWN 二进制漏洞利用",
        categories: &[
            Category {
                name: "保护检测",
                tools: &[
                    Tool { name: "checksec", desc: "纯Rust ELF保护检测(NX/PIE/canary/RELRO)" },
                    Tool { name: "libc-sym", desc: "libc符号偏移查询" },
                ],
            },
            Category {
                name: "ELF分析",
                tools: &[Tool { name: "elf", desc: "ELF解析+保护检测" }],
            },
            Category {
                name: "堆利用",
                tools: &[
                    Tool { name: "heap", desc: "堆块元数据解析" },
                    Tool { name: "one", desc: "one_gadget查找(libc中execve /bin/sh)" },
                ],
            },
            Category {
                name: "格式串攻击",
                tools: &[
                    Tool { name: "got", desc: "GOT覆写计算器(格式串攻击辅助)" },
                    Tool { name: "fmt", desc: "格式串payload生成器(%p/%n/%s)" },
                    Tool { name: "offset", desc: "溢出偏移计算器(ret/canary/ret2libc)" },
                ],
            },
            Category {
                name: "漏洞利用",
                tools: &[
                    Tool { name: "shell", desc: "shellcode/反弹shell生成器(x86/x64)" },
                    Tool { name: "gdb-gen", desc: "GDB exploit脚本生成器" },
                    Tool { name: "seccomp", desc: "seccomp BPF规则分析器" },
                ],
            },
        ],
    },
    Direction {
        name: "MISC 杂项",
        categories: &[
            Category {
                name: "文件分析",
                tools: &[
                    Tool { name: "analyze", desc: "文件综合分析(magic/熵/元数据/隐藏数据)" },
                    Tool { name: "filetype", desc: "快速文件类型检测(magic number)" },
                ],
            },
            Category {
                name: "隐写检测",
                tools: &[Tool { name: "stego", desc: "图片隐写检测(LSB/通道/metadata)" }],
            },
            Category {
                name: "数据可视化",
                tools: &[
                    Tool { name: "entropy", desc: "熵可视化(PNG热力图+ASCII art)" },
                    Tool { name: "visual", desc: "二进制数据可视化(发现数据规律)" },
                ],
            },
            Category {
                name: "密码分析",
                tools: &[Tool { name: "xor", desc: "XOR分析/爆破(单字节/多字节/已知明文)" }],
            },
            Category {
                name: "文件恢复",
                tools: &[Tool { name: "carve", desc: "文件雕刻(扫描magic恢复文件)" }],
            },
            Category {
                name: "压缩解压",
                tools: &[Tool { name: "extract", desc: "嵌套压缩包自动解压" }],
            },
            Category {
                name: "二维码",
                tools: &[Tool { name: "qr", desc: "QR码生成/读取(ASCII art+PNG)" }],
            },
            Category {
                name: "流量分析",
                tools: &[Tool { name: "pcap", desc: "PCAP解析(提取HTTP/DNS/文件)" }],
            },
            Category {
                name: "音频分析",
                tools: &[Tool { name: "spectro", desc: "频谱图生成(ffmpeg/sox wrapper)" }],
            },
        ],
    },
];

fn count_tools(dir: &Direction) -> usize {
    dir.categories.iter().map(|c| c.tools.len()).sum()
}

fn show_direction(dir: &Direction) {
    println!("{} {}", dir.name.bold(), format!("({}个工具)", count_tools(dir)).dimmed());
    let ncat = dir.categories.len();
    for (ci, cat) in dir.categories.iter().enumerate() {
        let cat_last = ci == ncat - 1;
        let cat_prefix = if cat_last { "└──" } else { "├──" };
        println!(
            "  {} {} {}",
            cat_prefix,
            cat.name.cyan(),
            format!("({})", cat.tools.len()).dimmed()
        );
        let ntool = cat.tools.len();
        for (ti, tool) in cat.tools.iter().enumerate() {
            let tool_last = ti == ntool - 1;
            let branch = if tool_last { "└──" } else { "├──" };
            let indent = if cat_last { "    " } else { "│   " };
            println!(
                "  {}{} {}  {}",
                indent,
                branch,
                tool.name.green(),
                tool.desc.dimmed()
            );
        }
    }
}

fn all_tools() -> Vec<(&'static str, &'static str)> {
    let mut v = Vec::new();
    for d in TOOLS {
        for c in d.categories {
            for t in c.tools {
                v.push((t.name, t.desc));
            }
        }
    }
    v
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();

    if let Some(key) = &args.search {
        let lk = key.to_lowercase();
        let hits: Vec<_> = all_tools()
            .into_iter()
            .filter(|(n, d)| n.to_lowercase().contains(&lk) || d.to_lowercase().contains(&lk))
            .collect();
        println!("{} {}\n", "搜索:".bold(), key);
        for (n, d) in &hits {
            println!("  {}  {}", n.green(), d.dimmed());
        }
        println!("\n{}", format!("找到 {} 个工具", hits.len()).dimmed());
        return finish(if hits.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        });
    }

    if args.list {
        let mut names: Vec<&str> = all_tools().into_iter().map(|(n, _)| n).collect();
        names.sort();
        for n in names {
            println!("{}", n.green());
        }
        return finish(exit::OK);
    }

    let only = if args.web {
        Some("Web安全")
    } else if args.pwn {
        Some("PWN 二进制漏洞利用")
    } else if args.misc {
        Some("MISC 杂项")
    } else {
        None
    };

    match only {
        Some(name) => {
            for d in TOOLS.iter().filter(|d| d.name == name) {
                println!();
                show_direction(d);
            }
        }
        None => {
            let total = all_tools().len();
            println!("\n  {} {}\n", "CTF 工具集".bold(), format!("共{total}个工具").dimmed());
            let n = TOOLS.len();
            for (i, d) in TOOLS.iter().enumerate() {
                if i > 0 {
                    println!();
                }
                show_direction(d);
                let _ = n;
            }
            println!(
                "\n{}",
                "提示: ctfhelp --search <关键词> 搜索 | ctfhelp --web 只看某个方向".dimmed()
            );
            println!();
        }
    }
    finish(exit::OK)
}
