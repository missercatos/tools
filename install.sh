#!/bin/bash
# hackingtools 安装脚本
# 用法: ./install.sh [--prefix 目录] [--uninstall]

set -euo pipefail

# ==================== 颜色定义 ====================
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
RESET='\033[0m'

# ==================== 配置 ====================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.local/bin"
UNINSTALL=0
FORCE=0

# 工具列表: 源路径|目标文件名
declare -a TOOLS=(
    # Web - 信息泄露
    "web/信息泄露/trav|trav"
    "web/信息泄露/dumpvcs|dumpvcs"
    "web/信息泄露/gitdump|gitdump"
    "web/信息泄露/githack|githack"
    "web/信息泄露/hgdump|hgdump"
    "web/信息泄露/svndump|svndump"
    "web/信息泄露/dsstore|dsstore"
    # Web - 爆破
    "web/爆破/brute|brute"
    # Web - 注入
    "web/注入/sqli|sqli"
    "web/注入/lfi|lfi"
    "web/注入/ssti|ssti"
    "web/注入/cmdi|cmdi"
    # Web - 认证绕过
    "web/认证绕过/jwt|jwt"
    # Web - 杂项
    "web/杂项/encdec|encdec"
    "web/杂项/xssserv|xssserv"
    # PWN - 保护检测
    "pwn/保护检测/checksec|checksec"
    "pwn/保护检测/libc-sym|libc-sym"
    # PWN - ELF分析
    "pwn/ELF分析/elf|elf"
    # PWN - 堆利用
    "pwn/堆利用/heap|heap"
    "pwn/堆利用/one|one"
    # PWN - 格式串攻击
    "pwn/格式串攻击/got|got"
    "pwn/格式串攻击/fmt|fmt"
    "pwn/格式串攻击/offset|offset"
    # PWN - 漏洞利用
    "pwn/漏洞利用/shell|shell"
    "pwn/漏洞利用/gdb-gen|gdb-gen"
    "pwn/漏洞利用/seccomp|seccomp"
    # MISC - 文件分析
    "misc/文件分析/analyze|analyze"
    "misc/文件分析/filetype|filetype"
    # MISC - 隐写检测
    "misc/隐写检测/stego|stego"
    # MISC - 数据可视化
    "misc/数据可视化/entropy|entropy"
    "misc/数据可视化/visual|visual"
    # MISC - 密码分析
    "misc/密码分析/xor|xor"
    # MISC - 文件恢复
    "misc/文件恢复/carve|carve"
    # MISC - 压缩解压
    "misc/压缩解压/extract|extract"
    # MISC - 二维码
    "misc/二维码/qr|qr"
    # MISC - 流量分析
    "misc/流量分析/pcap|pcap"
    # MISC - 音频分析
    "misc/音频分析/spectro|spectro"
    # 附加工具
    "ctfhelp|ctfhelp"
)

TOTAL=${#TOOLS[@]}
SUCCESS=0
SKIPPED=0
FAILED=0

# ==================== 函数 ====================

show_banner() {
    echo -e "\n${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║       hackingtools 安装程序          ║"
    echo "  ╚══════════════════════════════════════╝"
    echo -e "${RESET}\n"
}

show_progress() {
    local current=$1
    local total=$2
    local width=30
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))

    printf "\r  ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] %3d%% (%d/%d)" "$percent" "$current" "$total"
}

print_status() {
    local status="$1"
    local msg="$2"
    case "$status" in
        ok)    echo -e "  ${GREEN}[✓]${RESET} ${msg}" ;;
        skip)  echo -e "  ${YELLOW}[→]${RESET} ${msg}" ;;
        fail)  echo -e "  ${RED}[✗]${RESET} ${msg}" ;;
        info)  echo -e "  ${BLUE}[i]${RESET} ${msg}" ;;
        warn)  echo -e "  ${YELLOW}[!]${RESET} ${msg}" ;;
    esac
}

check_deps() {
    print_status "info" "检查依赖..."
    local missing=0
    for cmd in cp chmod; do
        if ! command -v "$cmd" &>/dev/null; then
            print_status "fail" "缺少命令: $cmd"
            missing=1
        fi
    done
    if [ $missing -eq 1 ]; then
        echo -e "\n${RED}无法继续，缺少必要命令${RESET}"
        exit 1
    fi
    print_status "ok" "依赖检查通过"
}

check_install_dir() {
    print_status "info" "安装目录: ${INSTALL_DIR}"

    if [ ! -d "$INSTALL_DIR" ]; then
        print_status "warn" "目录不存在，创建中..."
        mkdir -p "$INSTALL_DIR" || {
            print_status "fail" "无法创建目录: $INSTALL_DIR"
            exit 1
        }
        print_status "ok" "目录已创建"
    fi

    if [ ! -w "$INSTALL_DIR" ]; then
        print_status "fail" "目录不可写: $INSTALL_DIR"
        print_status "info" "尝试使用 sudo 或创建 ~/.local/bin"
        exit 1
    fi

    # 检查是否在PATH中
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) 
            print_status "ok" "目录已在 PATH 中"
            ;;
        *)
            print_status "warn" "目录不在 PATH 中"
            echo -e "         安装后请执行:"
            echo -e "         ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${RESET}"
            echo -e "         或添加到 ~/.bashrc"
            ;;
    esac
}

check_existing() {
    print_status "info" "检查已存在的工具..."
    local existing=0
    local tool_name

    for entry in "${TOOLS[@]}"; do
        IFS='|' read -r src tool_name <<< "$entry"
        if [ -f "${INSTALL_DIR}/${tool_name}" ]; then
            existing=$((existing+1))
        fi
    done

    if [ $existing -gt 0 ]; then
        print_status "warn" "发现 ${existing} 个已存在的工具"
        if [ $FORCE -eq 0 ]; then
            echo -en "\n  ${YELLOW}是否覆盖已存在的工具? [y/N]: ${RESET}"
            read -r answer
            if [[ ! "$answer" =~ ^[Yy]$ ]]; then
                print_status "info" "保留已存在的工具"
                return 1
            fi
        fi
    else
        print_status "ok" "没有已存在的工具"
    fi
    return 0
}

install_tool() {
    local src="$1"
    local tool_name="$2"
    local src_path="${SCRIPT_DIR}/${src}"
    local dst_path="${INSTALL_DIR}/${tool_name}"

    # 检查源文件
    if [ ! -f "$src_path" ]; then
        print_status "fail" "${tool_name}: 源文件不存在 (${src})"
        FAILED=$((FAILED+1))
        return 1
    fi

    # 检查目标是否已存在
    if [ -f "$dst_path" ] && [ $FORCE -eq 0 ]; then
        # 询问是否替换
        echo -en "\n  ${YELLOW}${tool_name}${RESET} 已存在，替换? [y/N]: "
        read -r answer
        if [[ ! "$answer" =~ ^[Yy]$ ]]; then
            print_status "skip" "${tool_name}: 保留已存在版本"
            SKIPPED=$((SKIPPED+1))
            return 0
        fi
    fi

    # 复制并设置权限
    if cp "$src_path" "$dst_path" 2>/dev/null && chmod +x "$dst_path" 2>/dev/null; then
        SUCCESS=$((SUCCESS+1))
        return 0
    else
        print_status "fail" "${tool_name}: 安装失败"
        FAILED=$((FAILED+1))
        return 1
    fi
}

do_install() {
    echo ""
    print_status "info" "开始安装 ${TOTAL} 个工具...\n"

    local i=0
    local installed_names=()

    for entry in "${TOOLS[@]}"; do
        IFS='|' read -r src tool_name <<< "$entry"
        i=$((i+1))

        # 显示进度
        show_progress $i $TOTAL

        # 安装
        if install_tool "$src" "$tool_name"; then
            installed_names+=("$tool_name")
        fi

        # 稍微延迟让用户能看到进度
        sleep 0.05
    done

    echo ""  # 换行

    # 显示安装的工具
    if [ ${#installed_names[@]} -gt 0 ]; then
        echo ""
        print_status "ok" "已安装工具:"
        for name in "${installed_names[@]}"; do
            echo -e "         ${GREEN}• ${name}${RESET}"
        done
    fi
}

do_uninstall() {
    echo ""
    print_status "info" "卸载 ${TOTAL} 个工具...\n"

    local i=0
    for entry in "${TOOLS[@]}"; do
        IFS='|' read -r src tool_name <<< "$entry"
        i=$((i+1))

        show_progress $i $TOTAL

        local dst_path="${INSTALL_DIR}/${tool_name}"
        if [ -f "$dst_path" ]; then
            rm -f "$dst_path"
            SUCCESS=$((SUCCESS+1))
        else
            SKIPPED=$((SKIPPED+1))
        fi

        sleep 0.02
    done
    echo ""
}

show_summary() {
    echo ""
    echo -e "${BOLD}========================================${RESET}"
    if [ $UNINSTALL -eq 1 ]; then
        echo -e "${BOLD}${GREEN}卸载完成${RESET}"
    else
        echo -e "${BOLD}${GREEN}安装完成${RESET}"
    fi
    echo -e "  成功: ${GREEN}${SUCCESS}${RESET}  跳过: ${YELLOW}${SKIPPED}${RESET}  失败: ${RED}${FAILED}${RESET}"
    echo -e "  目录: ${CYAN}${INSTALL_DIR}${RESET}"
    echo -e "${BOLD}========================================${RESET}"

    if [ $UNINSTALL -eq 0 ] && [ $SUCCESS -gt 0 ]; then
        echo ""
        echo -e "${DIM}使用方法:${RESET}"
        echo -e "  1. 加载环境: ${CYAN}source ${SCRIPT_DIR}/setup.sh${RESET}"
        echo -e "  2. 或直接使用: ${CYAN}${INSTALL_DIR}/checksec${RESET}"
        echo -e "  3. 查看工具: ${CYAN}ctfhelp${RESET}"
        echo ""
    fi
}

show_usage() {
    echo -e "用法: $0 [选项]"
    echo ""
    echo -e "选项:"
    echo -e "  --prefix <目录>     安装目录 (默认: ~/.local/bin)"
    echo -e "  --force             跳过确认，直接覆盖"
    echo -e "  --uninstall         卸载所有工具"
    echo -e "  --help              显示此帮助"
}

# ==================== 参数解析 ====================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --uninstall)
            UNINSTALL=1
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo -e "${RED}未知参数: $1${RESET}"
            show_usage
            exit 1
            ;;
    esac
done

# ==================== 主流程 ====================
show_banner

if [ $UNINSTALL -eq 1 ]; then
    echo -e "${YELLOW}  即将卸载 ${TOTAL} 个工具${RESET}"
    echo -e "${DIM}  目标目录: ${INSTALL_DIR}${RESET}"
    echo ""
    echo -en "  确认卸载? [y/N]: "
    read -r answer
    if [[ ! "$answer" =~ ^[Yy]$ ]]; then
        echo -e "\n  ${DIM}已取消${RESET}"
        exit 0
    fi
    do_uninstall
else
    check_deps
    check_install_dir
    check_existing || true
    do_install
fi

show_summary
