//! encdec - 编码解码全家桶
//! 纯 Rust 实现, 不再依赖 python3

use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use clap::Parser;
use common::{exit, finish, Mode, Out};
use flate2::read::{MultiGzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::Serialize;
use std::io::{Read, Write};
use std::process::ExitCode;

const QUOTE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~')
    .remove(b'/');

const QUOTE_ALL_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

#[derive(Parser, Debug)]
#[command(
    name = "encdec",
    version,
    about = "编码解码全家桶(零依赖)",
    long_about = "模式: b64|b64url|hex|url|urlall|rot:N|ascii|binary|oct|html|unicode|gzip|zlib|md5|sha1|sha256\n\n退出码: 0=成功 1=无结果 2=用法错误 3=运行错误"
)]
struct Args {
    /// 模式: b64|b64url|hex|url|urlall|rot:N|ascii|binary|oct|html|unicode|gzip|zlib|md5|sha1|sha256
    #[arg(value_name = "MODE")]
    mode: String,

    /// 要处理的字符串(可用 @文件 或 - 从 stdin)
    #[arg(value_name = "STRING")]
    string: String,

    /// 解码(默认编码); hash/rot 不受影响
    #[arg(short, long)]
    decode: bool,

    /// 编码
    #[arg(short, long)]
    encode: bool,

    /// JSON 输出
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Report {
    mode: String,
    decode: bool,
    output: String,
}

fn strip_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}

fn read_input(s: &str) -> Result<String, String> {
    let raw = if s == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("读取 stdin 失败: {e}"))?;
        buf
    } else if let Some(path) = s.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(|e| format!("读取 {path} 失败: {e}"))?
    } else {
        return Ok(s.to_string());
    };
    Ok(raw.trim_end_matches('\n').to_string())
}

fn enc_b64(s: &str) -> String {
    STANDARD.encode(s.as_bytes())
}

fn dec_b64(s: &str) -> Result<String, String> {
    let clean = strip_ws(s);
    let data = STANDARD
        .decode(clean.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

fn enc_b64url(s: &str) -> String {
    URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn dec_b64url(s: &str) -> Result<String, String> {
    let mut clean = strip_ws(s);
    let pad = (4 - clean.len() % 4) % 4;
    clean.extend(std::iter::repeat('=').take(pad));
    let data = URL_SAFE
        .decode(clean.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

fn enc_hex(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(s.len() * 2);
    for &b in s.as_bytes() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn dec_hex(s: &str) -> Result<String, String> {
    let clean = strip_ws(s);
    if clean.len() % 2 != 0 {
        return Err("十六进制字符串长度必须为偶数".to_string());
    }
    let b = clean.as_bytes();
    let mut data = Vec::with_capacity(clean.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("非法十六进制字符: {}", b[i] as char))?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("非法十六进制字符: {}", b[i + 1] as char))?;
        data.push((hi * 16 + lo) as u8);
    }
    Ok(String::from_utf8_lossy(&data).into_owned())
}

fn enc_url(s: &str) -> String {
    utf8_percent_encode(s, QUOTE_SET).to_string()
}

fn enc_urlall(s: &str) -> String {
    utf8_percent_encode(s, QUOTE_ALL_SET).to_string()
}

fn dec_url(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn rot_n(mode: &str) -> Option<i32> {
    if mode == "rot" {
        return Some(13);
    }
    let rest = mode.strip_prefix("rot")?;
    let digits = rest.trim_start_matches(':');
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i32>().ok()
}

fn rot(s: &str, n: i32) -> String {
    let n = n.rem_euclid(26) as u8;
    s.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                ((c as u8 - b'a' + n) % 26 + b'a') as char
            } else if c.is_ascii_uppercase() {
                ((c as u8 - b'A' + n) % 26 + b'A') as char
            } else {
                c
            }
        })
        .collect()
}

fn enc_ascii(s: &str) -> String {
    s.chars()
        .map(|c| (c as u32).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn dec_ascii(s: &str) -> Result<String, String> {
    let mut out = String::new();
    for tok in s.split_whitespace() {
        let v: u32 = tok.parse().map_err(|_| format!("非法数字: {tok}"))?;
        out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
    }
    Ok(out)
}

fn enc_binary(s: &str) -> String {
    s.chars()
        .map(|c| format!("{:08b}", c as u32))
        .collect::<Vec<_>>()
        .join(" ")
}

fn dec_binary(s: &str) -> Result<String, String> {
    let groups: Vec<&str> = if s.chars().any(|c| c.is_whitespace()) {
        s.split_whitespace().collect()
    } else {
        s.as_bytes()
            .chunks(8)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect()
    };
    let mut out = String::new();
    for g in groups {
        let v = u32::from_str_radix(g, 2).map_err(|e| format!("非法二进制: {g} ({e})"))?;
        out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
    }
    Ok(out)
}

fn enc_oct(s: &str) -> String {
    s.chars()
        .map(|c| format!("{:o}", c as u32))
        .collect::<Vec<_>>()
        .join(" ")
}

fn dec_oct(s: &str) -> Result<String, String> {
    let mut out = String::new();
    for tok in s.split_whitespace() {
        let v = u32::from_str_radix(tok, 8).map_err(|e| format!("非法八进制: {tok} ({e})"))?;
        out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
    }
    Ok(out)
}

fn enc_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

const HTML_ENTITIES: &[(&str, char)] = &[
    ("nbsp", '\u{a0}'), ("iexcl", '¡'), ("cent", '¢'), ("pound", '£'),
    ("curren", '¤'), ("yen", '¥'), ("brvbar", '¦'), ("sect", '§'),
    ("uml", '¨'), ("copy", '©'), ("ordf", 'ª'), ("laquo", '«'),
    ("not", '¬'), ("shy", '\u{ad}'), ("reg", '®'), ("macr", '¯'),
    ("deg", '°'), ("plusmn", '±'), ("sup2", '²'), ("sup3", '³'),
    ("acute", '´'), ("micro", 'µ'), ("para", '¶'), ("middot", '·'),
    ("cedil", '¸'), ("sup1", '¹'), ("ordm", 'º'), ("raquo", '»'),
    ("frac14", '¼'), ("frac12", '½'), ("frac34", '¾'), ("iquest", '¿'),
    ("Agrave", 'À'), ("Aacute", 'Á'), ("Acirc", 'Â'), ("Atilde", 'Ã'),
    ("Auml", 'Ä'), ("Aring", 'Å'), ("AElig", 'Æ'), ("Ccedil", 'Ç'),
    ("Egrave", 'È'), ("Eacute", 'É'), ("Ecirc", 'Ê'), ("Euml", 'Ë'),
    ("Igrave", 'Ì'), ("Iacute", 'Í'), ("Icirc", 'Î'), ("Iuml", 'Ï'),
    ("ETH", 'Ð'), ("Ntilde", 'Ñ'), ("Ograve", 'Ò'), ("Oacute", 'Ó'),
    ("Ocirc", 'Ô'), ("Otilde", 'Õ'), ("Ouml", 'Ö'), ("times", '×'),
    ("Oslash", 'Ø'), ("Ugrave", 'Ù'), ("Uacute", 'Ú'), ("Ucirc", 'Û'),
    ("Uuml", 'Ü'), ("Yacute", 'Ý'), ("THORN", 'Þ'), ("szlig", 'ß'),
    ("agrave", 'à'), ("aacute", 'á'), ("acirc", 'â'), ("atilde", 'ã'),
    ("auml", 'ä'), ("aring", 'å'), ("aelig", 'æ'), ("ccedil", 'ç'),
    ("egrave", 'è'), ("eacute", 'é'), ("ecirc", 'ê'), ("euml", 'ë'),
    ("igrave", 'ì'), ("iacute", 'í'), ("icirc", 'î'), ("iuml", 'ï'),
    ("eth", 'ð'), ("ntilde", 'ñ'), ("ograve", 'ò'), ("oacute", 'ó'),
    ("ocirc", 'ô'), ("otilde", 'õ'), ("ouml", 'ö'), ("divide", '÷'),
    ("oslash", 'ø'), ("ugrave", 'ù'), ("uacute", 'ú'), ("ucirc", 'û'),
    ("uuml", 'ü'), ("yacute", 'ý'), ("thorn", 'þ'), ("yuml", 'ÿ'),
    ("OElig", 'Œ'), ("oelig", 'œ'), ("Scaron", 'Š'), ("scaron", 'š'),
    ("Yuml", 'Ÿ'), ("fnof", 'ƒ'), ("circ", 'ˆ'), ("tilde", '˜'),
    ("Alpha", 'Α'), ("Beta", 'Β'), ("Gamma", 'Γ'), ("Delta", 'Δ'),
    ("Epsilon", 'Ε'), ("Zeta", 'Ζ'), ("Eta", 'Η'), ("Theta", 'Θ'),
    ("Iota", 'Ι'), ("Kappa", 'Κ'), ("Lambda", 'Λ'), ("Mu", 'Μ'),
    ("Nu", 'Ν'), ("Xi", 'Ξ'), ("Omicron", 'Ο'), ("Pi", 'Π'),
    ("Rho", 'Ρ'), ("Sigma", 'Σ'), ("Tau", 'Τ'), ("Upsilon", 'Υ'),
    ("Phi", 'Φ'), ("Chi", 'Χ'), ("Psi", 'Ψ'), ("Omega", 'Ω'),
    ("alpha", 'α'), ("beta", 'β'), ("gamma", 'γ'), ("delta", 'δ'),
    ("epsilon", 'ε'), ("zeta", 'ζ'), ("eta", 'η'), ("theta", 'θ'),
    ("iota", 'ι'), ("kappa", 'κ'), ("lambda", 'λ'), ("mu", 'μ'),
    ("nu", 'ν'), ("xi", 'ξ'), ("omicron", 'ο'), ("pi", 'π'),
    ("rho", 'ρ'), ("sigmaf", 'ς'), ("sigma", 'σ'), ("tau", 'τ'),
    ("upsilon", 'υ'), ("phi", 'φ'), ("chi", 'χ'), ("psi", 'ψ'),
    ("omega", 'ω'), ("thetasym", 'ϑ'), ("upsih", 'ϒ'), ("piv", 'ϖ'),
    ("ensp", '\u{2002}'), ("emsp", '\u{2003}'), ("thinsp", '\u{2009}'),
    ("zwnj", '\u{200c}'), ("zwj", '\u{200d}'), ("lrm", '\u{200e}'),
    ("rlm", '\u{200f}'), ("ndash", '–'), ("mdash", '—'), ("lsquo", '‘'),
    ("rsquo", '’'), ("sbquo", '‚'), ("ldquo", '“'), ("rdquo", '”'),
    ("bdquo", '„'), ("dagger", '†'), ("Dagger", '‡'), ("bull", '•'),
    ("hellip", '…'), ("permil", '‰'), ("prime", '′'), ("Prime", '″'),
    ("lsaquo", '‹'), ("rsaquo", '›'), ("oline", '‾'), ("frasl", '⁄'),
    ("euro", '€'), ("image", 'ℑ'), ("weierp", '℘'), ("real", 'ℜ'),
    ("trade", '™'), ("alefsym", 'ℵ'), ("larr", '←'), ("uarr", '↑'),
    ("rarr", '→'), ("darr", '↓'), ("harr", '↔'), ("crarr", '↵'),
    ("lArr", '⇐'), ("uArr", '⇑'), ("rArr", '⇒'), ("dArr", '⇓'),
    ("hArr", '⇔'), ("forall", '∀'), ("part", '∂'), ("exist", '∃'),
    ("empty", '∅'), ("nabla", '∇'), ("isin", '∈'), ("notin", '∉'),
    ("ni", '∋'), ("prod", '∏'), ("sum", '∑'), ("minus", '−'),
    ("lowast", '∗'), ("radic", '√'), ("prop", '∝'), ("infin", '∞'),
    ("ang", '∠'), ("and", '∧'), ("or", '∨'), ("cap", '∩'),
    ("cup", '∪'), ("int", '∫'), ("there4", '∴'), ("sim", '∼'),
    ("cong", '≅'), ("asymp", '≈'), ("ne", '≠'), ("equiv", '≡'),
    ("le", '≤'), ("ge", '≥'), ("sub", '⊂'), ("sup", '⊃'),
    ("nsub", '⊄'), ("sube", '⊆'), ("supe", '⊇'), ("oplus", '⊕'),
    ("otimes", '⊗'), ("perp", '⊥'), ("sdot", '⋅'), ("lceil", '⌈'),
    ("rceil", '⌉'), ("lfloor", '⌊'), ("rfloor", '⌋'), ("lang", '⟨'),
    ("rang", '⟩'), ("loz", '◊'), ("spades", '♠'), ("clubs", '♣'),
    ("hearts", '♥'), ("diams", '♦'), ("amp", '&'), ("lt", '<'),
    ("gt", '>'), ("quot", '"'), ("apos", '\''), ("AMP", '&'),
    ("LT", '<'), ("GT", '>'), ("QUOT", '"'), ("COPY", '©'),
    ("REG", '®'),
];

const LEGACY_ENTITIES: &[&str] = &[
    "AElig", "AMP", "Aacute", "Acirc", "Agrave", "Aring", "Atilde", "Auml",
    "COPY", "Ccedil", "ETH", "Eacute", "Ecirc", "Egrave", "Euml", "GT",
    "Iacute", "Icirc", "Igrave", "Iuml", "LT", "Ntilde", "Oacute", "Ocirc",
    "Ograve", "Oslash", "Otilde", "Ouml", "QUOT", "REG", "THORN", "Uacute",
    "Ucirc", "Ugrave", "Uuml", "Yacute", "aacute", "acirc", "acute", "aelig",
    "agrave", "amp", "aring", "atilde", "auml", "brvbar", "ccedil", "cedil",
    "cent", "copy", "curren", "deg", "divide", "eacute", "ecirc", "egrave",
    "eth", "euml", "frac12", "frac14", "frac34", "gt", "iacute", "icirc",
    "iexcl", "igrave", "iquest", "iuml", "laquo", "lt", "macr", "micro",
    "middot", "nbsp", "not", "ntilde", "oacute", "ocirc", "ograve", "ordf",
    "ordm", "oslash", "otilde", "ouml", "para", "plusmn", "pound", "quot",
    "raquo", "reg", "sect", "shy", "sup1", "sup2", "sup3", "szlig", "thorn",
    "times", "uacute", "ucirc", "ugrave", "uml", "uuml", "yacute", "yen",
    "yuml",
];

fn lookup_entity(name: &str) -> Option<char> {
    HTML_ENTITIES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, c)| *c)
}

fn lookup_legacy(name: &str) -> Option<char> {
    if LEGACY_ENTITIES.contains(&name) {
        lookup_entity(name)
    } else {
        None
    }
}

fn invalid_charref(v: u64) -> Option<char> {
    let c = match v {
        0x00 => '\u{fffd}',
        0x0d => '\r',
        0x80 => '\u{20ac}',
        0x81 => '\u{81}',
        0x82 => '\u{201a}',
        0x83 => '\u{192}',
        0x84 => '\u{201e}',
        0x85 => '\u{2026}',
        0x86 => '\u{2020}',
        0x87 => '\u{2021}',
        0x88 => '\u{2c6}',
        0x89 => '\u{2030}',
        0x8a => '\u{160}',
        0x8b => '\u{2039}',
        0x8c => '\u{152}',
        0x8d => '\u{8d}',
        0x8e => '\u{17d}',
        0x8f => '\u{8f}',
        0x90 => '\u{90}',
        0x91 => '\u{2018}',
        0x92 => '\u{2019}',
        0x93 => '\u{201c}',
        0x94 => '\u{201d}',
        0x95 => '\u{2022}',
        0x96 => '\u{2013}',
        0x97 => '\u{2014}',
        0x98 => '\u{2dc}',
        0x99 => '\u{2122}',
        0x9a => '\u{161}',
        0x9b => '\u{203a}',
        0x9c => '\u{153}',
        0x9d => '\u{9d}',
        0x9e => '\u{17e}',
        0x9f => '\u{178}',
        _ => return None,
    };
    Some(c)
}

fn invalid_codepoint(v: u32) -> bool {
    (0x01..=0x08).contains(&v)
        || (0x0e..=0x1f).contains(&v)
        || (0x7f..=0x9f).contains(&v)
        || (0xfdd0..=0xfdef).contains(&v)
        || v == 0x0b
        || (v >= 0xfffe && (v & 0xffff == 0xfffe || v & 0xffff == 0xffff))
}

fn numeric_ref(v: u64) -> Option<String> {
    if let Some(c) = invalid_charref(v) {
        return Some(c.to_string());
    }
    if (0xd800..=0xdfff).contains(&v) || v > 0x10ffff {
        return Some('\u{fffd}'.to_string());
    }
    let v = v as u32;
    if invalid_codepoint(v) {
        return Some(String::new());
    }
    char::from_u32(v).map(|c| c.to_string())
}

fn parse_charref(s: &str) -> Option<(String, usize)> {
    let b = s.as_bytes();
    if b.len() < 2 {
        return None;
    }
    if b[1] == b'#' {
        let mut j = 2;
        let hex = j < b.len() && (b[j] == b'x' || b[j] == b'X');
        if hex {
            j += 1;
        }
        let start = j;
        while j < b.len()
            && if hex {
                b[j].is_ascii_hexdigit()
            } else {
                b[j].is_ascii_digit()
            }
        {
            j += 1;
        }
        if j == start {
            return None;
        }
        let digits = &s[start..j];
        let v = if hex {
            u64::from_str_radix(digits, 16)
        } else {
            digits.parse::<u64>()
        }
        .unwrap_or(u64::MAX);
        let consumed = if j < b.len() && b[j] == b';' { j + 1 } else { j };
        return numeric_ref(v).map(|t| (t, consumed));
    }
    let mut j = 1;
    while j < b.len() && j - 1 < 32 {
        let c = b[j];
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\x0c' || c == b'<' || c == b'&' || c == b'#' || c == b';' {
            break;
        }
        j += 1;
    }
    if j == 1 {
        return None;
    }
    let name = &s[1..j];
    let has_semi = j < b.len() && b[j] == b';';
    let consumed = if has_semi { j + 1 } else { j };
    let lookup = |n: &str| {
        if has_semi {
            lookup_entity(n)
        } else {
            lookup_legacy(n)
        }
    };
    if let Some(c) = lookup(name) {
        return Some((c.to_string(), consumed));
    }
    for x in (2..=name.len()).rev() {
        if let Some(c) = lookup(&name[..x]) {
            let rest = &name[x..];
            let text = if has_semi {
                format!("{c}{rest};")
            } else {
                format!("{c}{rest}")
            };
            return Some((text, consumed));
        }
    }
    let text = if has_semi {
        format!("&{name};")
    } else {
        format!("&{name}")
    };
    Some((text, consumed))
}

fn dec_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s.as_bytes()[i] != b'&' {
            let c = s[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
            continue;
        }
        match parse_charref(&s[i..]) {
            Some((text, consumed)) => {
                out.push_str(&text);
                i += consumed;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

fn enc_unicode(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (0x20..=0x7e).contains(&(c as u32)) => out.push(c),
            c if (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) < 0x10000 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out
}

fn read_hex(b: &[u8], i: &mut usize, n: usize) -> Result<u32, String> {
    if *i + n > b.len() {
        return Err("转义序列不完整".to_string());
    }
    let mut v = 0u32;
    for _ in 0..n {
        let d = (b[*i] as char)
            .to_digit(16)
            .ok_or_else(|| format!("非法十六进制字符: {}", b[*i] as char))?;
        v = v * 16 + d;
        *i += 1;
    }
    Ok(v)
}

fn dec_unicode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        i += 1;
        if i >= b.len() {
            out.push('\\');
            break;
        }
        match b[i] {
            b'n' => {
                out.push('\n');
                i += 1;
            }
            b't' => {
                out.push('\t');
                i += 1;
            }
            b'r' => {
                out.push('\r');
                i += 1;
            }
            b'a' => {
                out.push('\u{7}');
                i += 1;
            }
            b'b' => {
                out.push('\u{8}');
                i += 1;
            }
            b'f' => {
                out.push('\u{c}');
                i += 1;
            }
            b'v' => {
                out.push('\u{b}');
                i += 1;
            }
            b'\\' => {
                out.push('\\');
                i += 1;
            }
            b'\'' => {
                out.push('\'');
                i += 1;
            }
            b'"' => {
                out.push('"');
                i += 1;
            }
            b'x' => {
                i += 1;
                let v = read_hex(b, &mut i, 2)?;
                out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
            }
            b'u' => {
                i += 1;
                let v = read_hex(b, &mut i, 4)?;
                out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
            }
            b'U' => {
                i += 1;
                let v = read_hex(b, &mut i, 8)?;
                out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
            }
            d @ b'0'..=b'7' => {
                let mut v = (d - b'0') as u32;
                i += 1;
                let mut n = 1;
                while n < 3 && i < b.len() && (b'0'..=b'7').contains(&b[i]) {
                    v = v * 8 + (b[i] - b'0') as u32;
                    i += 1;
                    n += 1;
                }
                out.push(char::from_u32(v).ok_or_else(|| format!("非法码点: {v}"))?);
            }
            other => {
                out.push('\\');
                out.push(other as char);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn enc_gzip(s: &str) -> Result<String, String> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::best());
    enc.write_all(s.as_bytes()).map_err(|e| e.to_string())?;
    let data = enc.finish().map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(data))
}

fn dec_gzip(s: &str) -> Result<String, String> {
    let raw = STANDARD
        .decode(strip_ws(s).as_bytes())
        .map_err(|e| format!("base64 解码失败: {e}"))?;
    let mut dec = MultiGzDecoder::new(raw.as_slice());
    let mut buf = Vec::new();
    dec.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn enc_zlib(s: &str) -> Result<String, String> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(s.as_bytes()).map_err(|e| e.to_string())?;
    let data = enc.finish().map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(data))
}

fn dec_zlib(s: &str) -> Result<String, String> {
    let raw = STANDARD
        .decode(strip_ws(s).as_bytes())
        .map_err(|e| format!("base64 解码失败: {e}"))?;
    let mut dec = ZlibDecoder::new(raw.as_slice());
    let mut buf = Vec::new();
    dec.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn is_hash(mode: &str) -> bool {
    matches!(
        mode,
        "md5" | "sha1" | "sha224" | "sha256" | "sha384" | "sha512"
    )
}

fn hash_hex(mode: &str, data: &[u8]) -> String {
    use sha2::Digest;
    match mode {
        "md5" => format!("{:x}", md5::Md5::digest(data)),
        "sha1" => format!("{:x}", sha1::Sha1::digest(data)),
        "sha224" => format!("{:x}", sha2::Sha224::digest(data)),
        "sha256" => format!("{:x}", sha2::Sha256::digest(data)),
        "sha384" => format!("{:x}", sha2::Sha384::digest(data)),
        _ => format!("{:x}", sha2::Sha512::digest(data)),
    }
}

fn known_mode(mode: &str) -> bool {
    matches!(
        mode,
        "b64"
            | "b64url"
            | "hex"
            | "url"
            | "urlall"
            | "ascii"
            | "binary"
            | "oct"
            | "html"
            | "unicode"
            | "gzip"
            | "gz"
            | "zlib"
    ) || is_hash(mode)
        || rot_n(mode).is_some()
}

fn process(mode: &str, s: &str, decode: bool) -> Result<String, String> {
    if let Some(n) = rot_n(mode) {
        return Ok(rot(s, n));
    }
    match mode {
        "b64" => {
            if decode {
                dec_b64(s)
            } else {
                Ok(enc_b64(s))
            }
        }
        "b64url" => {
            if decode {
                dec_b64url(s)
            } else {
                Ok(enc_b64url(s))
            }
        }
        "hex" => {
            if decode {
                dec_hex(s)
            } else {
                Ok(enc_hex(s))
            }
        }
        "url" => Ok(if decode { dec_url(s) } else { enc_url(s) }),
        "urlall" => Ok(if decode { dec_url(s) } else { enc_urlall(s) }),
        "ascii" => {
            if decode {
                dec_ascii(s)
            } else {
                Ok(enc_ascii(s))
            }
        }
        "binary" => {
            if decode {
                dec_binary(s)
            } else {
                Ok(enc_binary(s))
            }
        }
        "oct" => {
            if decode {
                dec_oct(s)
            } else {
                Ok(enc_oct(s))
            }
        }
        "html" => Ok(if decode { dec_html(s) } else { enc_html(s) }),
        "unicode" => {
            if decode {
                dec_unicode(s)
            } else {
                Ok(enc_unicode(s))
            }
        }
        "gzip" | "gz" => {
            if decode {
                dec_gzip(s)
            } else {
                enc_gzip(s)
            }
        }
        "zlib" => {
            if decode {
                dec_zlib(s)
            } else {
                enc_zlib(s)
            }
        }
        m if is_hash(m) => Ok(hash_hex(m, s.as_bytes())),
        _ => Err(format!("未知模式: {mode}")),
    }
}

fn main() -> ExitCode {
    common::reset_sigpipe();
    let args = Args::parse();
    let out = Out::new(Mode::from_flag(args.json));
    let _ = args.encode;

    let mode = args.mode.to_lowercase();
    if !known_mode(&mode) {
        out.error(&format!("未知模式: {mode}"));
        return finish(exit::USAGE);
    }

    let mut s = match read_input(&args.string) {
        Ok(s) => s,
        Err(e) => {
            out.error(&e);
            return finish(exit::ERROR);
        }
    };
    if args.decode {
        s = s.trim().to_string();
    }

    let output = match process(&mode, &s, args.decode) {
        Ok(v) => v,
        Err(e) => {
            out.error(&format!("处理失败: {e}"));
            return finish(exit::ERROR);
        }
    };

    let report = Report {
        mode,
        decode: args.decode,
        output: output.clone(),
    };
    out.emit(|| println!("{output}"), &report);

    finish(exit::OK)
}
