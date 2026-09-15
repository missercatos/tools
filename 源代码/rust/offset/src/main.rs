//! offset - PWN偏移计算器
//! 纯计算 + 纯 Rust gadget 扫描, 无外部依赖

use clap::{ArgGroup, Parser};
use common::{exit, finish, Mode, Out};
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS};
use goblin::elf::Elf;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "offset",
    version,
    about = "PWN偏移计算器",
    long_about = "pwn-offset: PWN偏移计算器\n用法:\n    pwn-offset --overflow <buf_size> <ret_offset>   # 计算溢出偏移\n    pwn-offset --canary <buf_size> <canary_offset>  # canary偏移\n    pwn-offset --ret2libc <libc_base> <func_off>    # ret2libc地址\n    pwn-offset --rop-gadget <binary> <gadget_str>   # 查找gadget地址\n    pwn-offset --calc <expr>                        # 地址计算\n    pwn-offset --diff <addr1> <addr2>               # 两个地址差值",
    after_help = "退出码: 0=成功 1=无结果 2=用法错误 3=运行错误",
    group(
        ArgGroup::new("cmd")
            .multiple(false)
            .args(["overflow", "canary", "ret2libc", "rop_gadget", "calc", "diff", "offset"])
    )
)]
struct Args {
    /// 计算溢出偏移: --overflow [buf_size] [ret_offset]
    #[arg(long, value_names = ["BUF_SIZE", "RET_OFFSET"], num_args = 0..=2)]
    overflow: Option<Vec<String>>,

    /// canary偏移: --canary [buf_size] [canary_offset]
    #[arg(long, value_names = ["BUF_SIZE", "CANARY_OFFSET"], num_args = 0..=2)]
    canary: Option<Vec<String>>,

    /// ret2libc地址: --ret2libc <libc_base_hex> <func_off_hex>
    #[arg(long, value_names = ["LIBC_BASE", "FUNC_OFF"], num_args = 2)]
    ret2libc: Option<Vec<String>>,

    /// 查找gadget地址: --rop-gadget <binary> <gadget_str>
    #[arg(long = "rop-gadget", value_names = ["BINARY", "GADGET"], num_args = 2)]
    rop_gadget: Option<Vec<String>>,

    /// 地址计算: --calc <expr>
    #[arg(long, value_name = "EXPR", num_args = 1, allow_hyphen_values = true)]
    calc: Option<String>,

    /// 两个地址差值: --diff <addr1> <addr2>
    #[arg(long, value_names = ["ADDR1", "ADDR2"], num_args = 2)]
    diff: Option<Vec<String>>,

    /// 直接输入一个偏移值
    #[arg(value_name = "OFFSET")]
    offset: Option<String>,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize, Clone)]
struct GadgetMatch {
    addr: u64,
    text: String,
}

#[derive(Serialize, Default)]
struct Report {
    mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    buf_size: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ret_offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canary_offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_to_ret: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_payload: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    libc_base: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    func_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gadget: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matches: Option<Vec<GadgetMatch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<i128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addr1: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    addr2: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    abs_diff: Option<i128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_ret: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    advice: Option<String>,
}

fn hex_signed(v: i128) -> String {
    if v < 0 {
        format!("0x-{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    common::parse_hex(s)
}

fn parse_dec_i64(s: &str) -> Result<i64, String> {
    s.trim()
        .parse::<i64>()
        .map_err(|e| format!("invalid number '{s}': {e}"))
}

fn parse_auto(s: &str) -> Result<i64, String> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).map_err(|e| format!("invalid hex '{s}': {e}"))
    } else {
        t.parse::<i64>()
            .map_err(|e| format!("invalid number '{s}': {e}"))
    }
}

fn py_mod(a: i128, b: i128) -> Result<i128, String> {
    if b == 0 {
        return Err("modulo by zero".into());
    }
    let r = a % b;
    Ok(if r != 0 && (r < 0) != (b < 0) {
        r + b
    } else {
        r
    })
}

fn py_floor_div(a: i128, b: i128) -> Result<i128, String> {
    if b == 0 {
        return Err("division by zero".into());
    }
    let q = a / b;
    let r = a % b;
    Ok(if r != 0 && (r < 0) != (b < 0) {
        q - 1
    } else {
        q
    })
}

struct ExprParser {
    s: Vec<char>,
    pos: usize,
}

impl ExprParser {
    fn new(input: &str) -> Self {
        ExprParser {
            s: input.chars().collect(),
            pos: 0,
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }

    fn peek(&mut self) -> Option<char> {
        self.skip_ws();
        self.s.get(self.pos).copied()
    }

    fn bump(&mut self) {
        self.skip_ws();
        self.pos += 1;
    }

    fn parse(&mut self) -> Result<i128, String> {
        let v = self.bitor()?;
        self.skip_ws();
        if self.pos != self.s.len() {
            return Err("unexpected token".into());
        }
        Ok(v)
    }

    fn bitor(&mut self) -> Result<i128, String> {
        let mut v = self.bitxor()?;
        while self.peek() == Some('|') {
            self.bump();
            v |= self.bitxor()?;
        }
        Ok(v)
    }

    fn bitxor(&mut self) -> Result<i128, String> {
        let mut v = self.bitand()?;
        while self.peek() == Some('^') {
            self.bump();
            v ^= self.bitand()?;
        }
        Ok(v)
    }

    fn bitand(&mut self) -> Result<i128, String> {
        let mut v = self.shift()?;
        while self.peek() == Some('&') {
            self.bump();
            v &= self.shift()?;
        }
        Ok(v)
    }

    fn shift(&mut self) -> Result<i128, String> {
        let mut v = self.addsub()?;
        loop {
            match self.peek() {
                Some('<') if self.s.get(self.pos + 1) == Some(&'<') => {
                    self.bump();
                    self.bump();
                    let n = self.addsub()?;
                    if !(0..128).contains(&n) {
                        return Err("shift out of range".into());
                    }
                    v = v.checked_shl(n as u32).ok_or("shift overflow")?;
                }
                Some('>') if self.s.get(self.pos + 1) == Some(&'>') => {
                    self.bump();
                    self.bump();
                    let n = self.addsub()?;
                    if !(0..128).contains(&n) {
                        return Err("shift out of range".into());
                    }
                    v = v.checked_shr(n as u32).ok_or("shift overflow")?;
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn addsub(&mut self) -> Result<i128, String> {
        let mut v = self.muldiv()?;
        loop {
            match self.peek() {
                Some('+') => {
                    self.bump();
                    v = v.checked_add(self.muldiv()?).ok_or("overflow")?;
                }
                Some('-') => {
                    self.bump();
                    v = v.checked_sub(self.muldiv()?).ok_or("overflow")?;
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn muldiv(&mut self) -> Result<i128, String> {
        let mut v = self.unary()?;
        loop {
            match self.peek() {
                Some('*') => {
                    self.bump();
                    v = v.checked_mul(self.unary()?).ok_or("overflow")?;
                }
                Some('/') => {
                    self.bump();
                    if self.peek() == Some('/') {
                        self.bump();
                        v = py_floor_div(v, self.unary()?)?;
                    } else {
                        return Err("division not supported".into());
                    }
                }
                Some('%') => {
                    self.bump();
                    v = py_mod(v, self.unary()?)?;
                }
                _ => break,
            }
        }
        Ok(v)
    }

    fn unary(&mut self) -> Result<i128, String> {
        match self.peek() {
            Some('-') => {
                self.bump();
                Ok(-self.unary()?)
            }
            Some('+') => {
                self.bump();
                self.unary()
            }
            Some('~') => {
                self.bump();
                Ok(!self.unary()?)
            }
            _ => self.power(),
        }
    }

    fn power(&mut self) -> Result<i128, String> {
        let base = self.primary()?;
        if self.peek() == Some('*') && self.s.get(self.pos + 1) == Some(&'*') {
            self.bump();
            self.bump();
            let exp = self.unary()?;
            if !(0..128).contains(&exp) {
                return Err("exponent out of range".into());
            }
            return base.checked_pow(exp as u32).ok_or("overflow".into());
        }
        Ok(base)
    }

    fn primary(&mut self) -> Result<i128, String> {
        match self.peek() {
            Some('(') => {
                self.bump();
                let v = self.bitor()?;
                if self.peek() != Some(')') {
                    return Err("missing ')'".into());
                }
                self.bump();
                Ok(v)
            }
            Some(c) if c.is_ascii_digit() => self.number(),
            _ => Err("expected number".into()),
        }
    }

    fn number(&mut self) -> Result<i128, String> {
        self.skip_ws();
        if self.s.get(self.pos) == Some(&'0')
            && matches!(self.s.get(self.pos + 1), Some('x') | Some('X'))
        {
            self.pos += 2;
            let start = self.pos;
            while self.pos < self.s.len() && self.s[self.pos].is_ascii_hexdigit() {
                self.pos += 1;
            }
            if start == self.pos {
                return Err("invalid hex literal".into());
            }
            let text: String = self.s[start..self.pos].iter().collect();
            return i128::from_str_radix(&text, 16).map_err(|e| e.to_string());
        }
        let start = self.pos;
        while self.pos < self.s.len()
            && (self.s[self.pos].is_ascii_digit() || self.s[self.pos] == '_')
        {
            self.pos += 1;
        }
        if start == self.pos {
            return Err("expected number".into());
        }
        let text: String = self.s[start..self.pos]
            .iter()
            .filter(|c| **c != '_')
            .collect();
        text.parse::<i128>().map_err(|e| e.to_string())
    }
}

fn eval_expr(expr: &str) -> Result<i128, String> {
    ExprParser::new(expr).parse()
}

fn reg_num(name: &str) -> Option<u8> {
    let n = match name {
        "rax" | "eax" | "ax" | "al" => 0,
        "rcx" | "ecx" | "cx" | "cl" => 1,
        "rdx" | "edx" | "dx" | "dl" => 2,
        "rbx" | "ebx" | "bx" | "bl" => 3,
        "rsp" | "esp" | "sp" | "spl" => 4,
        "rbp" | "ebp" | "bp" | "bpl" => 5,
        "rsi" | "esi" | "si" | "sil" => 6,
        "rdi" | "edi" | "di" | "dil" => 7,
        _ => {
            let rest = name.strip_prefix('r')?;
            let idx: u8 = rest.parse().ok()?;
            if (8..=15).contains(&idx) {
                idx
            } else {
                return None;
            }
        }
    };
    Some(n)
}

fn insn_bytes(text: &str) -> Option<Vec<u8>> {
    let t = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let toks: Vec<&str> = t.split_whitespace().collect();
    if !toks.is_empty()
        && toks.iter().all(|x| {
            let h = x.strip_prefix("0x").unwrap_or(x);
            !h.is_empty() && h.len() <= 2 && h.chars().all(|c| c.is_ascii_hexdigit())
        })
    {
        return toks
            .iter()
            .map(|x| u8::from_str_radix(x.strip_prefix("0x").unwrap_or(x), 16).ok())
            .collect();
    }

    match t.as_str() {
        "ret" | "retn" | "retq" => return Some(vec![0xc3]),
        "leave" | "leaveq" => return Some(vec![0xc9]),
        "nop" => return Some(vec![0x90]),
        "syscall" => return Some(vec![0x0f, 0x05]),
        "int 0x80" | "int80" => return Some(vec![0xcd, 0x80]),
        _ => {}
    }

    if let Some(rest) = t.strip_prefix("xor ") {
        let (a, b) = rest.split_once(',')?;
        let ra = reg_num(a.trim())?;
        let rb = reg_num(b.trim())?;
        if ra != rb {
            return None;
        }
        let mut x = Vec::new();
        if ra >= 8 {
            x.push(0x45);
        }
        x.extend_from_slice(&[0x31, 0xc0 | (ra & 7)]);
        return Some(x);
    }

    let (op, rest) = t.split_once(' ')?;
    let reg = reg_num(rest)?;
    let lo = reg & 7;
    let mut v = Vec::new();
    if reg >= 8 {
        v.push(0x41);
    }
    match op {
        "pop" => v.push(0x58 + lo),
        "push" => v.push(0x50 + lo),
        "jmp" => v.extend_from_slice(&[0xff, 0xe0 + lo]),
        "call" => v.extend_from_slice(&[0xff, 0xd0 + lo]),
        _ => return None,
    }
    Some(v)
}

fn parse_gadget(gadget: &str) -> Option<(Vec<u8>, String)> {
    let parts: Vec<String> = gadget
        .split(';')
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut bytes = Vec::new();
    for p in &parts {
        bytes.extend_from_slice(&insn_bytes(p)?);
    }
    Some((bytes, parts.join(" ; ")))
}

fn find_gadget(data: &[u8], elf: &Elf, pattern: &[u8]) -> Vec<u64> {
    let mut hits = Vec::new();
    if pattern.is_empty() {
        return hits;
    }
    for sh in &elf.section_headers {
        if sh.sh_flags & u64::from(SHF_EXECINSTR) == 0 || sh.sh_type == SHT_NOBITS {
            continue;
        }
        let start = sh.sh_offset as usize;
        let size = sh.sh_size as usize;
        if start.checked_add(size).is_none_or(|end| end > data.len()) {
            continue;
        }
        let sec = &data[start..start + size];
        if sec.len() < pattern.len() {
            continue;
        }
        for i in 0..=sec.len() - pattern.len() {
            if &sec[i..i + pattern.len()] == pattern {
                hits.push(sh.sh_addr + i as u64);
            }
        }
    }
    hits.sort_unstable();
    hits.dedup();
    hits
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));

    if let Some(vals) = &args.overflow {
        let buf_size = match vals.first() {
            Some(s) => match parse_dec_i64(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 64,
        };
        let ret_offset = match vals.get(1) {
            Some(s) => match parse_dec_i64(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 72,
        };
        let advice = if ret_offset <= 64 {
            format!("使用 cyclic({ret_offset}) 找偏移")
        } else {
            "使用 pattern_offset 找偏移".to_string()
        };
        let report = Report {
            mode: "overflow".into(),
            buf_size: Some(buf_size),
            ret_offset: Some(ret_offset),
            total_to_ret: Some(ret_offset + 8),
            full_payload: Some(ret_offset + 16),
            advice: Some(advice.clone()),
            ..Default::default()
        };
        out.emit(
            || {
                println!("[*] Buffer size: {buf_size} bytes");
                println!("[*] Return address offset: {ret_offset}");
                println!("[*] Payload structure:");
                println!("    [padding: {ret_offset} bytes] [saved rbp: 8 bytes] [ret addr]");
                println!("    Total to ret: {} bytes", ret_offset + 8);
                println!(
                    "    Full payload: {} bytes (with 8-byte ret)",
                    ret_offset + 16
                );
                println!();
                println!("[*] 常见偏移参考:");
                println!("    {advice}");
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.canary {
        let buf_size = match vals.first() {
            Some(s) => match parse_dec_i64(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 64,
        };
        let canary_offset = match vals.get(1) {
            Some(s) => match parse_dec_i64(s) {
                Ok(v) => v,
                Err(e) => {
                    out.error(&e);
                    return finish(exit::USAGE);
                }
            },
            None => 72,
        };
        let report = Report {
            mode: "canary".into(),
            buf_size: Some(buf_size),
            canary_offset: Some(canary_offset),
            total: Some(canary_offset + 24),
            ..Default::default()
        };
        out.emit(
            || {
                println!("[*] Buffer size: {buf_size} bytes");
                println!("[*] Canary offset: {canary_offset}");
                println!("[*] Payload structure:");
                println!(
                    "    [padding: {canary_offset} bytes] [canary: 8 bytes] [saved rbp: 8 bytes] [ret addr]"
                );
                println!("    Total: {} bytes", canary_offset + 24);
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.ret2libc {
        let libc_base = match parse_hex_u64(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let func_offset = match parse_hex_u64(&vals[1]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let resolved = libc_base.wrapping_add(func_offset);
        let report = Report {
            mode: "ret2libc".into(),
            libc_base: Some(libc_base),
            func_offset: Some(func_offset),
            resolved: Some(resolved),
            ..Default::default()
        };
        out.emit(
            || {
                println!("[*] Libc base:   0x{libc_base:x}");
                println!("[*] Func offset: 0x{func_offset:x}");
                println!("[*] Resolved:    0x{resolved:x}");
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.rop_gadget {
        let binary = vals[0].clone();
        let gadget = vals[1].clone();
        let (pattern, text) = match parse_gadget(&gadget) {
            Some(p) => p,
            None => {
                out.error(&format!("不支持的gadget语法: {gadget}"));
                return finish(exit::USAGE);
            }
        };
        let path = PathBuf::from(&binary);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => {
                out.error(&format!("cannot read {binary}: {e}"));
                return finish(exit::ERROR);
            }
        };
        let elf = match Elf::parse(&data) {
            Ok(e) => e,
            Err(e) => {
                out.error(&format!("not an ELF file: {e}"));
                return finish(exit::ERROR);
            }
        };
        let hits = find_gadget(&data, &elf, &pattern);
        let matches: Vec<GadgetMatch> = hits
            .iter()
            .map(|a| GadgetMatch {
                addr: *a,
                text: text.clone(),
            })
            .collect();
        let report = Report {
            mode: "rop-gadget".into(),
            binary: Some(binary.clone()),
            gadget: Some(text.clone()),
            pattern: Some(to_hex(&pattern)),
            count: Some(matches.len()),
            matches: Some(matches.clone()),
            ..Default::default()
        };
        out.emit(
            || {
                for m in &matches {
                    println!("  [ROPgadget] 0x{:016x} : {}", m.addr, m.text);
                }
            },
            &report,
        );
        if matches.is_empty() {
            out.error(&format!("未找到gadget: {gadget}"));
            return finish(exit::NO_RESULT);
        }
        return finish(exit::OK);
    }

    if let Some(expr) = &args.calc {
        let value = match eval_expr(expr) {
            Ok(v) => v,
            Err(_) => {
                out.error(&format!("无法计算: {expr}"));
                return finish(exit::NO_RESULT);
            }
        };
        let report = Report {
            mode: "calc".into(),
            expr: Some(expr.clone()),
            value: Some(value),
            ..Default::default()
        };
        out.emit(
            || {
                println!("[*] {expr} = {} ({value})", hex_signed(value));
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(vals) = &args.diff {
        let a1 = match parse_auto(&vals[0]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let a2 = match parse_auto(&vals[1]) {
            Ok(v) => v,
            Err(e) => {
                out.error(&e);
                return finish(exit::USAGE);
            }
        };
        let diff = a2.wrapping_sub(a1);
        let direction = if diff > 0 { "forward" } else { "backward" };
        let report = Report {
            mode: "diff".into(),
            addr1: Some(a1),
            addr2: Some(a2),
            diff: Some(diff),
            abs_diff: Some((diff as i128).abs()),
            direction: Some(direction.into()),
            ..Default::default()
        };
        out.emit(
            || {
                println!(
                    "[*] {} -> {}",
                    hex_signed(a1 as i128),
                    hex_signed(a2 as i128)
                );
                println!("[*] Diff: {diff} (0x{:x})", (diff as i128).abs());
                if diff > 0 {
                    println!("[*] 需要跳过 {diff} 字节");
                } else {
                    println!("[*] 回退 {} 字节", -(diff as i128));
                }
            },
            &report,
        );
        return finish(exit::OK);
    }

    if let Some(raw) = &args.offset {
        let offset = match raw.trim().parse::<i64>() {
            Ok(v) => v,
            Err(_) => {
                out.error(&format!("Unknown command: {raw}"));
                out.info(
                    "pwn-offset: PWN偏移计算器\n用法:\n    pwn-offset --overflow <buf_size> <ret_offset>   # 计算溢出偏移\n    pwn-offset --canary <buf_size> <canary_offset>  # canary偏移\n    pwn-offset --ret2libc <libc_base> <func_off>    # ret2libc地址\n    pwn-offset --rop-gadget <binary> <gadget_str>   # 查找gadget地址\n    pwn-offset --calc <expr>                        # 地址计算\n    pwn-offset --diff <addr1> <addr2>               # 两个地址差值",
                );
                return finish(exit::USAGE);
            }
        };
        let report = Report {
            mode: "offset".into(),
            offset: Some(offset),
            hex: Some(hex_signed(offset as i128)),
            to_ret: Some(offset + 8),
            ..Default::default()
        };
        out.emit(
            || {
                println!("[*] Offset: {offset} bytes");
                println!("    hex: {}", hex_signed(offset as i128));
                println!("    to ret: {} bytes (including saved rbp)", offset + 8);
            },
            &report,
        );
        return finish(exit::OK);
    }

    out.info(
        "pwn-offset: PWN偏移计算器\n用法:\n    pwn-offset --overflow <buf_size> <ret_offset>   # 计算溢出偏移\n    pwn-offset --canary <buf_size> <canary_offset>  # canary偏移\n    pwn-offset --ret2libc <libc_base> <func_off>    # ret2libc地址\n    pwn-offset --rop-gadget <binary> <gadget_str>   # 查找gadget地址\n    pwn-offset --calc <expr>                        # 地址计算\n    pwn-offset --diff <addr1> <addr2>               # 两个地址差值",
    );
    finish(exit::USAGE)
}
