#!/bin/bash
# hackingtools 构建脚本: 编译 Rust workspace 并部署二进制到功能目录
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$ROOT/源代码/rust"
TARGET="$WORKSPACE/target/release"

echo "[*] 编译 workspace (源代码/rust)..."
cargo build --release --workspace --manifest-path "$WORKSPACE/Cargo.toml"

declare -A DEPLOY=(
  [checksec]="pwn/保护检测" [libc-sym]="pwn/保护检测"
  [elf]="pwn/ELF分析"
  [heap]="pwn/堆利用" [one]="pwn/堆利用"
  [got]="pwn/格式串攻击" [fmt]="pwn/格式串攻击" [offset]="pwn/格式串攻击"
  [shell]="pwn/漏洞利用" [gdb-gen]="pwn/漏洞利用" [seccomp]="pwn/漏洞利用"
  [analyze]="misc/文件分析" [filetype]="misc/文件分析"
  [stego]="misc/隐写检测"
  [entropy]="misc/数据可视化" [visual]="misc/数据可视化"
  [xor]="misc/密码分析"
  [carve]="misc/文件恢复"
  [extract]="misc/压缩解压"
  [qr]="misc/二维码"
  [pcap]="misc/流量分析"
  [spectro]="misc/音频分析"
  [trav]="web/信息泄露" [dumpvcs]="web/信息泄露" [gitdump]="web/信息泄露"
  [githack]="web/信息泄露" [hgdump]="web/信息泄露" [svndump]="web/信息泄露"
  [dsstore]="web/信息泄露"
  [brute]="web/爆破"
  [sqli]="web/注入" [lfi]="web/注入" [ssti]="web/注入" [cmdi]="web/注入"
  [jwt]="web/认证绕过"
  [encdec]="web/杂项" [xssserv]="web/杂项"
)

echo "[*] 部署二进制到功能目录..."
count=0
for tool in "${!DEPLOY[@]}"; do
  install -m755 "$TARGET/$tool" "$ROOT/${DEPLOY[$tool]}/$tool"
  count=$((count + 1))
done
install -m755 "$TARGET/ctfhelp" "$ROOT/ctfhelp"

echo "[+] 完成: $count 个工具 + ctfhelp"
echo "    运行 'source setup.sh' 或 'ctfhelp' 查看工具集"
