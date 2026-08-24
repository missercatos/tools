# hackingtools

自研安全工具集。单文件脚本零依赖(bash/python3 stdlib)，Rust工具编译为独立二进制。

## 快速开始

```bash
source setup.sh    # 加载环境变量，之后可直接使用所有工具
```

## 目录结构

```
web/                    Web安全工具
  信息泄露/              信息泄露方向
    trav                目录遍历(内置字典/wildcard过滤/限速)
    dumpvcs             VCS泄露恢复(git/hg/svn自动识别+flag扫描)
    gitdump             .git目录泄露恢复
    githack             GitHack风格.git泄露利用+flag扫描
    hgdump              .hg泄露利用
    svndump             .svn泄露利用
    dsstore             .DS_Store解析(支持递归URL)
  爆破/
    brute               Web登录爆破终端(Rust，支持验证码/会话轮换/用户枚举/代理)
  注入/
    sqli                SQL注入检测(布尔/时间盲注+数据提取)
    lfi                 文件包含探测(php://filter/日志投毒)
    ssti                模板注入检测+payload字典
    cmdi                命令注入payload+反弹shell生成+TCP监听
  认证绕过/
    jwt                 JWT解码/伪造(alg none/HS256)/公钥混淆/弱密钥爆破
  杂项/
    encdec              编码转换(url/base64/hex/rot13/html/unicode/gzip)
    xssserv             XSS回调服务器(cookie/路径捕获)
  源代码/
    brute/              Rust源码(cargo项目)

pwn/                    二进制漏洞利用工具
  保护检测/
    checksec            纯bash ELF保护检测(NX/PIE/canary/RELRO/FORTIFY)
    libc-sym            libc符号偏移查询
  ELF分析/
    elf                 ELF解析+保护检测(Rust，goblin crate)
  堆利用/
    heap                堆块元数据解析(Rust)
    one                 one_gadget查找(libc中execve /bin/sh)
  格式串攻击/
    got                 GOT覆写计算器(格式串攻击辅助)
    fmt                 格式串payload生成器(%p扫描/%n写入/%s泄露)
    offset              溢出偏移计算器(ret/canary/ret2libc)
  漏洞利用/
    shell               shellcode/反弹shell生成器(x86/x64)
    gdb-gen             GDB exploit脚本生成器
    seccomp             seccomp BPF规则分析器
  源代码/
    rust/               Rust源码(pwn-elf/pwn-one/pwn-heap)
    python/             Python源码
    bash/               Bash源码

misc/                   CTF杂项工具
  文件分析/
    analyze             文件综合分析(magic/熵/元数据/隐藏数据检测)
    filetype            快速文件类型检测(magic number)
  隐写检测/
    stego               图片隐写检测(LSB/通道/metadata/附加数据)
  数据可视化/
    entropy             熵可视化(PNG热力图+ASCII art+异常检测)
    visual              二进制数据可视化(发现数据规律)
  密码分析/
    xor                 XOR分析/爆破(单字节/多字节Kasiski/已知明文)
  文件恢复/
    carve               文件雕刻(扫描magic恢复文件，支持16种格式)
  压缩解压/
    extract             嵌套压缩包自动解压(zip/tar/gz/bz2/xz/7z/rar)
  二维码/
    qr                  QR码生成(ASCII art+PNG)
  流量分析/
    pcap                PCAP解析(提取HTTP/DNS/文件)
  音频分析/
    spectro             频谱图生成(sox/ffmpeg wrapper)
  源代码/
    rust/               Rust源码(8个项目)
    bash/               Bash源码

ctf/                    字典文件
  10_million_password_list_top_100.txt
  wordlists/            dirs.txt backup.txt flag.txt endpoints.txt users.txt
```

## 推荐外部工具

```bash
# PWN
pip install pwntools ROPgadget
gem install one_gadget seccomp-tools
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh

# MISC
pacman -S exiftool steghide binwalk foremost sox wireshark-cli
pip install zsteg volatility3
```

## 注意事项

- `source setup.sh` 后可直接使用所有工具(如 checksec、analyze、sqli)
- Rust源码编译: `cd 源代码/rust/xxx && cargo build --release`
- 源代码/目录存放可修改的源码，功能目录/下是编译好的可执行文件
- ctf/wordlists/ 供 trav 使用(--dict 或 @file)
