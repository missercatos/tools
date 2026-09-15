//! seccomp - seccomp BPF规则查看/分析
//! 解析原始BPF字节码 / seccomp-tools dump文本, 并扫描二进制中的seccomp痕迹

use clap::Parser;
use common::{exit, finish, Mode, Out};
use serde::Serialize;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

const DOC: &str = "pwn-seccomp: seccomp规则查看/分析
用法:
    pwn-seccomp <binary>                      # 分析二进制中的seccomp调用
    pwn-seccomp --bpf <hex_bytes>             # 解析BPF字节码
    pwn-seccomp --file <bpf_dump>             # 从文件解析BPF
    pwn-seccomp --pwntools <pwntools_output>  # 解析pwntools的seccompTools输出
    pwn-seccomp --list                        # 列出常用syscall号
";

#[derive(Parser, Debug)]
#[command(
    name = "seccomp",
    version,
    about = "seccomp BPF规则查看/分析",
    long_about = "用法:\n    seccomp <binary>                      # 分析二进制中的seccomp调用\n    seccomp --bpf <hex_bytes>             # 解析BPF字节码\n    seccomp --file <bpf_dump>             # 从文件解析BPF\n    seccomp --pwntools <pwntools_output>  # 解析pwntools/seccomp-tools输出(缺省读stdin)\n    seccomp --list                        # 列出常用syscall号",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 目标二进制
    #[arg(value_name = "BINARY")]
    binary: Option<PathBuf>,

    /// 解析BPF字节码 (hex)
    #[arg(long, value_name = "HEX")]
    bpf: Option<String>,

    /// 从文件解析BPF
    #[arg(long, value_name = "FILE")]
    file: Option<PathBuf>,

    /// 解析pwntools/seccomp-tools输出 (缺省读stdin)
    #[arg(long, value_name = "TEXT", num_args = 0..)]
    pwntools: Option<Vec<String>>,

    /// 列出常用syscall号
    #[arg(long)]
    list: bool,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

const SYSCALLS: &[(u32, &str)] = &[
    (0, "read"),
    (1, "write"),
    (2, "open"),
    (3, "close"),
    (4, "stat"),
    (5, "fstat"),
    (6, "lstat"),
    (7, "poll"),
    (8, "lseek"),
    (9, "mmap"),
    (10, "mprotect"),
    (11, "munmap"),
    (12, "brk"),
    (13, "rt_sigaction"),
    (14, "rt_sigprocmask"),
    (16, "ioctl"),
    (17, "pread64"),
    (18, "pwrite64"),
    (20, "writev"),
    (21, "access"),
    (22, "pipe"),
    (24, "sched_yield"),
    (32, "dup"),
    (33, "dup2"),
    (35, "nanosleep"),
    (39, "getpid"),
    (41, "socket"),
    (42, "connect"),
    (43, "accept"),
    (49, "bind"),
    (50, "listen"),
    (56, "clone"),
    (57, "fork"),
    (59, "execve"),
    (60, "exit"),
    (61, "wait4"),
    (62, "kill"),
    (63, "uname"),
    (72, "fcntl"),
    (78, "getdents"),
    (79, "getcwd"),
    (82, "rename"),
    (83, "mkdir"),
    (87, "unlink"),
    (89, "readlink"),
    (90, "chmod"),
    (102, "getuid"),
    (104, "getgid"),
    (107, "geteuid"),
    (108, "getegid"),
    (158, "arch_prctl"),
    (217, "getdents64"),
    (231, "exit_group"),
    (257, "openat"),
    (262, "newfstatat"),
    (302, "prlimit64"),
    (318, "getrandom"),
    (332, "statx"),
    (334, "rseq"),
];

fn syscall_name(n: u32) -> String {
    SYSCALLS
        .iter()
        .find(|(num, _)| *num == n)
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| format!("syscall_{n}"))
}

const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JGT: u16 = 0x20;
const BPF_JSET: u16 = 0x40;

const SCMP_ACT_KILL: u32 = 0x00000000;
const SCMP_ACT_TRAP: u32 = 0x00030000;
const SCMP_ACT_ERRNO: u32 = 0x00050000;
const SCMP_ACT_TRACE: u32 = 0x00040000;
const SCMP_ACT_ALLOW: u32 = 0x7fff0000;
const SCMP_ACT_LOG: u32 = 0x7ffc0000;
const SCMP_ACT_MASK: u32 = 0xffff0000;

#[derive(Serialize, Clone)]
struct Rule {
    offset: usize,
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    op: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    syscall: Option<String>,
}

impl Rule {
    fn desc(&self) -> String {
        let mut desc = self
            .op
            .clone()
            .or_else(|| self.action.clone())
            .unwrap_or_default();
        if let Some(name) = &self.syscall {
            desc += &format!("  -> {name}");
        }
        desc
    }
}

fn action_str(k: u32) -> String {
    match k & SCMP_ACT_MASK {
        SCMP_ACT_ALLOW => "ALLOW".to_string(),
        SCMP_ACT_KILL => "KILL".to_string(),
        SCMP_ACT_TRAP => "TRAP".to_string(),
        SCMP_ACT_ERRNO => format!("ERRNO({})", k & 0x0000ffff),
        SCMP_ACT_TRACE => "TRACE".to_string(),
        SCMP_ACT_LOG => "LOG".to_string(),
        _ => format!("UNKNOWN(0x{k:x})"),
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned = s.replace(' ', "").replace("\\x", "").replace("0x", "");
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!("odd-length hex string: {s}"));
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex string: {s}"))?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("invalid hex string: {s}"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn parse_bpf(mut bytes: Vec<u8>) -> Vec<Rule> {
    if !bytes.len().is_multiple_of(8) {
        let pad = 8 - bytes.len() % 8;
        bytes.resize(bytes.len() + pad, 0);
    }

    let mut rules = Vec::new();
    let mut i = 0;
    while i + 8 <= bytes.len() {
        let code = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        let jt = bytes[i + 2];
        let jf = bytes[i + 3];
        let k = u32::from_le_bytes([bytes[i + 4], bytes[i + 5], bytes[i + 6], bytes[i + 7]]);

        let op = code & 0x07;
        let size = code & 0x18;
        let mode = code & 0xe0;

        let mut rule = Rule {
            offset: i,
            code,
            jt,
            jf,
            k,
            op: None,
            action: None,
            syscall: None,
        };

        if op == BPF_RET {
            rule.action = Some(action_str(k));
        } else if op == BPF_JMP {
            let jmp_type = code & 0xf0;
            rule.op = Some(if jmp_type == BPF_JEQ {
                format!("JEQ 0x{k:x}")
            } else if jmp_type == BPF_JGE {
                format!("JGE 0x{k:x}")
            } else if jmp_type == BPF_JGT {
                format!("JGT 0x{k:x}")
            } else if jmp_type == BPF_JSET {
                format!("JSET 0x{k:x}")
            } else {
                format!("JMP 0x{k:x}")
            });
            if jmp_type == BPF_JEQ {
                rule.syscall = Some(syscall_name(k));
            }
        } else if op == BPF_LD {
            if mode == BPF_ABS {
                if size == BPF_W {
                    rule.op = Some(format!("LD [data_width:4 + 0x{k:x}]"));
                } else if size == BPF_H {
                    rule.op = Some(format!("LD [data_width:2 + 0x{k:x}]"));
                } else if size == BPF_B {
                    rule.op = Some(format!("LD [data_width:1 + 0x{k:x}]"));
                }
            } else if mode == BPF_W {
                rule.op = Some(format!("LD 0x{k:x}"));
            }
        }

        rules.push(rule);
        i += 8;
    }
    rules
}

fn print_rules(rules: &[Rule]) {
    println!("[*] Parsed {} BPF instructions:\n", rules.len());
    println!(
        "{:>8}  {:>6}  {:>3}  {:>3}  {:>10}  Description",
        "Offset", "Code", "JT", "JF", "K"
    );
    println!("{}", "-".repeat(65));
    for r in rules {
        println!(
            "0x{:06x}  0x{:04x}  {:3}  {:3}  0x{:08x}  {}",
            r.offset,
            r.code,
            r.jt,
            r.jf,
            r.k,
            r.desc()
        );
    }
}

fn parse_dump_rules(text: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((idx_str, rest)) = line.split_once(':') else {
            continue;
        };
        let Ok(idx) = idx_str.trim().parse::<usize>() else {
            continue;
        };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        if toks.len() < 4 {
            continue;
        }
        let parse_tok = |s: &str| -> Option<u32> {
            let t = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            u32::from_str_radix(t, 16).ok()
        };
        let (Some(code), Some(jt), Some(jf), Some(k)) = (
            parse_tok(toks[0]),
            parse_tok(toks[1]),
            parse_tok(toks[2]),
            parse_tok(toks[3]),
        ) else {
            continue;
        };
        if code > 0xff || jt > 0xff || jf > 0xff {
            continue;
        }
        let bytes = vec![
            code as u8,
            0,
            jt as u8,
            jf as u8,
            (k & 0xff) as u8,
            ((k >> 8) & 0xff) as u8,
            ((k >> 16) & 0xff) as u8,
            ((k >> 24) & 0xff) as u8,
        ];
        if let Some(mut r) = parse_bpf(bytes).into_iter().next() {
            r.offset = idx * 8;
            rules.push(r);
        }
    }
    rules
}

fn run_capture(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&output.stdout).to_string())
}

fn analyze_binary(path: &std::path::Path) -> (Vec<String>, Vec<String>) {
    let path_str = path.to_string_lossy().to_string();
    let mut strings_hits = Vec::new();
    let mut disasm_hits = Vec::new();

    if let Some(strings_out) = run_capture("strings", &[path_str.as_str()]) {
        let patterns = [
            "seccomp",
            "SECCOMP",
            "prctl",
            "PR_SET_SECCOMP",
            "seccomp_rule_add",
        ];
        for pat in patterns {
            for line in strings_out.lines() {
                if line.to_lowercase().contains(&pat.to_lowercase()) {
                    strings_hits.push(line.to_string());
                }
            }
        }
    }

    if let Some(objdump) = run_capture("objdump", &["-d", path_str.as_str()]) {
        for line in objdump.lines() {
            let lower = line.to_lowercase();
            if lower.contains("prctl") || lower.contains("seccomp") {
                disasm_hits.push(line.trim().to_string());
            }
            if lower.contains("mov")
                && (lower.contains("eax") || lower.contains("rax"))
                && lower.contains("158")
            {
                disasm_hits.push(line.trim().to_string());
            }
        }
    }

    (strings_hits, disasm_hits)
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    let selected = [
        args.binary.is_some(),
        args.bpf.is_some(),
        args.file.is_some(),
        args.pwntools.is_some(),
        args.list,
    ]
    .iter()
    .filter(|b| **b)
    .count();

    if selected == 0 {
        if out.json() {
            out.error("no command specified");
        } else {
            println!("{DOC}");
        }
        return finish(exit::USAGE);
    }
    if selected > 1 {
        out.error("参数冲突: 一次只能使用一个命令");
        return finish(exit::USAGE);
    }

    if args.list {
        #[derive(Serialize)]
        struct Syscall {
            num: u32,
            hex: String,
            name: String,
        }
        #[derive(Serialize)]
        struct ListReport {
            arch: String,
            count: usize,
            syscalls: Vec<Syscall>,
        }
        let list: Vec<Syscall> = SYSCALLS
            .iter()
            .map(|(num, name)| Syscall {
                num: *num,
                hex: format!("0x{num:03x}"),
                name: name.to_string(),
            })
            .collect();
        let report = ListReport {
            arch: "x86_64".to_string(),
            count: list.len(),
            syscalls: list,
        };
        out.emit(
            || {
                println!("[*] x86_64 syscall表 (常用):\n");
                for (num, name) in SYSCALLS {
                    println!("  {num:4}  0x{num:03x}  {name}");
                }
                println!("\n  ... 共 {} 个", SYSCALLS.len());
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(hex_in) = &args.bpf {
        let bytes = match parse_hex(hex_in) {
            Ok(b) => b,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let rules = parse_bpf(bytes);
        #[derive(Serialize)]
        struct BpfReport {
            hex: String,
            count: usize,
            rules: Vec<Rule>,
        }
        let report = BpfReport {
            hex: hex_in.clone(),
            count: rules.len(),
            rules,
        };
        out.emit(|| print_rules(&report.rules), &report);
        return finish(if report.count == 0 {
            exit::NO_RESULT
        } else {
            exit::OK
        });
    }

    if let Some(file) = &args.file {
        let data = match std::fs::read(file) {
            Ok(d) => d,
            Err(e) => {
                out.error(&format!("cannot read {}: {e}", file.display()));
                return finish(exit::ERROR);
            }
        };
        let size = data.len();
        let rules = parse_bpf(data);
        #[derive(Serialize)]
        struct FileReport {
            file: String,
            size: usize,
            count: usize,
            rules: Vec<Rule>,
        }
        let report = FileReport {
            file: file.display().to_string(),
            size,
            count: rules.len(),
            rules,
        };
        out.emit(|| print_rules(&report.rules), &report);
        return finish(if report.count == 0 {
            exit::NO_RESULT
        } else {
            exit::OK
        });
    }

    if let Some(text_args) = &args.pwntools {
        let text = if text_args.is_empty() {
            let mut buf = String::new();
            let _ = std::io::stdin().read_to_string(&mut buf);
            buf
        } else {
            text_args.join(" ")
        };
        let lines: Vec<String> = text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let rules = parse_dump_rules(&text);
        #[derive(Serialize)]
        struct PwntoolsReport {
            lines: Vec<String>,
            count: usize,
            rules: Vec<Rule>,
        }
        let report = PwntoolsReport {
            count: rules.len(),
            lines,
            rules,
        };
        out.emit(
            || {
                println!("[*] Parsed seccomp rules from pwntools output:\n");
                for line in &report.lines {
                    println!("  {line}");
                }
            },
            &report,
        );
        return finish(if report.lines.is_empty() {
            exit::NO_RESULT
        } else {
            exit::OK
        });
    }

    let path = args.binary.as_ref().expect("binary");
    if !path.is_file() {
        out.error(&format!("Unknown command or file: {}", path.display()));
        return finish(exit::ERROR);
    }

    let (strings_hits, disasm_hits) = analyze_binary(path);
    let found = !strings_hits.is_empty() || !disasm_hits.is_empty();
    #[derive(Serialize)]
    struct BinReport {
        file: String,
        found: bool,
        strings: Vec<String>,
        disasm: Vec<String>,
    }
    let report = BinReport {
        file: path.display().to_string(),
        found,
        strings: strings_hits,
        disasm: disasm_hits,
    };
    out.emit(
        || {
            println!("[*] Scanning {} for seccomp patterns...\n", report.file);
            for line in &report.strings {
                println!("  [strings] {line}");
            }
            for line in &report.disasm {
                println!("  [disasm] {line}");
            }
            println!("\n[*] 如需精确分析BPF, 用: pwn-seccomp --bpf <hex_bytes>");
            println!("    或用 pwntools: pwn.pwnlib.seccomp SeccompWindow()");
        },
        &report,
    );

    finish(if found { exit::OK } else { exit::NO_RESULT })
}
