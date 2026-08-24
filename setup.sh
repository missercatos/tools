#!/bin/bash
# hackingtools 环境配置
# 用法: source setup.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PATH="$SCRIPT_DIR/bin:$PATH"

echo "[+] hackingtools 已加载"
echo "    可用工具: $(ls "$SCRIPT_DIR/bin" | wc -l) 个"
echo "    输入工具名直接使用，如: checksec, analyze, sqli, trav"
