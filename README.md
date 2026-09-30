# hackingtools

自研安全工具集。**全部为 Rust 编译的独立二进制**, 零运行时依赖(python3/bash 不再需要), 启动 ~1ms, 支持 `--json` 机器可读输出。

## 快速开始

```bash
source setup.sh    # 加载 PATH, 之后直接使用所有工具
ctfhelp            # 查看工具树
ctfhelp --search sql   # 搜索工具
```

安装到系统(可选):

```bash
./install.sh                   # 安装到 ~/.local/bin
./install.sh --prefix /usr/local/bin
./install.sh --uninstall       # 卸载
```

## 统一约定

| 项目 | 约定 |
|------|------|
| 退出码 | `0`=成功/命中, `1`=无结果, `2`=用法错误, `3`=运行错误 |
| 输出 | 默认人类可读(彩色); `--json` 输出结构化 JSON 到 stdout |
| HTTP参数 | 网络工具统一支持 `--timeout` `--proxy` `--insecure` `--ua` `--cookie` |
| 帮助 | 所有工具 `--help` 可查看用法 |

## 目录结构

```
web/                    Web安全 (15个工具)
  信息泄露/               trav dumpvcs gitdump githack hgdump svndump dsstore
  爆破/                   brute
  注入/                   sqli lfi ssti cmdi
  认证绕过/               jwt
  杂项/                   encdec xssserv

pwn/                    二进制漏洞利用 (11个工具)
  保护检测/               checksec libc-sym
  ELF分析/                elf
  堆利用/                 heap one
  格式串攻击/             got fmt offset
  漏洞利用/               shell gdb-gen seccomp

misc/                   CTF杂项 (11个工具)
  文件分析/               analyze filetype
  隐写检测/               stego
  数据可视化/             entropy visual
  密码分析/               xor
  文件恢复/               carve
  压缩解压/               extract
  二维码/                 qr
  流量分析/               pcap
  音频分析/               spectro

ctfhelp                 工具导航(树形/搜索/列表)
bin/                    所有工具的符号链接(统一入口)
源代码/rust/            Rust workspace (单一cargo工程, 全部源码)
源代码/archive/         旧 bash/python 实现归档(参考用)
```

## 工具速查

### Web
| 工具 | 说明 |
|------|------|
| trav | 目录遍历: 字典/生成器/递归/wildcard过滤/限速/多线程 |
| dumpvcs | VCS泄露恢复: auto探测 + git(含pack)/hg(含zstd)/svn + flag扫描 |
| gitdump | .git泄露恢复: index/logs/stash/loose+pack对象 |
| githack | GitHack风格.git利用: 全历史恢复 + flag扫描 |
| hgdump | .hg泄露利用: revlog解析 + store路径编码 |
| svndump | .svn泄露利用: wc.db解析 + pristine恢复 |
| dsstore | .DS_Store解析: B-tree解析 + 递归URL模式 |
| brute | 登录爆破: 验证码闸门/会话轮换/用户枚举/代理/REPL |
| sqli | SQL注入自动化: 五步方法论 + union/布尔盲注/时间盲注 + 7种tamper |
| lfi | 文件包含: 路径穿越/php://filter/日志投毒 |
| ssti | 模板注入检测 + payload字典 |
| cmdi | 命令注入payload + 反弹shell + TCP监听 |
| jwt | JWT解码/伪造(none/HS256)/公钥混淆/弱密钥爆破 |
| encdec | 编码转换: url/base64/hex/rot13/html/unicode/gzip/zlib/hash |
| xssserv | XSS回调服务器: cookie/路径/来源捕获 |

### PWN
| 工具 | 说明 |
|------|------|
| checksec | ELF保护检测: NX/PIE/RELRO/Canary/FORTIFY/RWX |
| libc-sym | libc符号偏移查询(--all/--search) |
| elf | ELF解析: 段/节/GOT/PLT/符号/保护 |
| heap | 堆元数据解析: chunks/bins/tcache |
| one | one_gadget查找: libc中execve /bin/sh |
| got | GOT覆写计算器 + 格式串payload |
| fmt | 格式串payload生成: %p扫描/%n写入/%s泄露 |
| offset | 溢出偏移计算器: cyclic/ret2libc |
| shell | shellcode/反弹shell生成(x86/x64) |
| gdb-gen | GDB exploit脚本生成 |
| seccomp | seccomp BPF规则分析 |

### MISC
| 工具 | 说明 |
|------|------|
| analyze | 文件综合分析: magic/熵/元数据/隐藏数据 |
| filetype | 快速文件类型检测(magic number) |
| stego | 图片隐写检测: LSB/通道/PNG chunk/附加数据 |
| entropy | 熵可视化: PNG热力图 + ASCII art + 异常检测 |
| visual | 二进制数据可视化 |
| xor | XOR分析: 单字节爆破/多字节Kasiski/已知明文 |
| carve | 文件雕刻: 16种magic签名扫描恢复 |
| extract | 嵌套压缩包自动解压(zip/tar/gz/bz2/xz/7z/rar) |
| qr | QR码生成/读取(ASCII art + PNG) |
| pcap | PCAP解析: HTTP/DNS/文件提取 |
| spectro | 频谱图生成(ffmpeg/sox wrapper) |

## 开发

```bash
# 构建全部并部署二进制到功能目录
./build.sh

# 或手动
cd 源代码/rust
cargo build --release --workspace
cargo build --release -p sqli     # 单个工具
cargo test -p <tool>
```

- 单一 cargo workspace: `源代码/rust/`, 共享 `common` 库(HTTP/输出/退出码/flag扫描)
- 每个工具一个 crate, 二进制名与工具名一致
- 修改源码后运行 `./build.sh` 重新部署

## 推荐外部工具(可选)

以下场景需外部程序(工具本身零依赖):
- `spectro` 需要 `ffmpeg` (或 `sox`)
- `extract` 的 7z/rar 格式需要 `7z`/`unrar`
- 深度利用建议配合: pwntools, ROPgadget, one_gadget, pwndbg/gef, radare2
