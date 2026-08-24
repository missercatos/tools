# hackingtools

Self-made security tool collection. Single-file scripts are zero-dependency
(bash / python3 stdlib). Project-style tools each carry their own git repo.

## Layout

- web/信息泄露/ - info disclosure tools
  - dumpvcs - unified VCS leak recovery with auto-detect (git/hg/svn), flag scan, git config hints
  - gitdump - .git directory leak recovery
  - githack - GitHack-style .git leak exploit, auto flag scan
  - hgdump - .hg leak exploit
  - svndump - .svn leak exploit
  - dsstore - .DS_Store parser, recursive URL mode
  - trav - value-space traversal: dicts, generators, recurse, wildcard filter, rate limit, built-in wordlists
- web/爆破/brute/ - Web brute-force terminal (Rust): login brute, captcha gate, session rotation, user enum, mangle, proxy, JSON report, authenticated REPL
- web/注入/ - injection tools
  - sqli - boolean/time-based blind SQLi detection and data extraction
  - lfi - LFI probe: traversal, php://filter chains, log poisoning
  - ssti - template injection detection + payload dictionary
  - cmdi - command injection payloads, reverse shell generator, TCP listener
- web/认证绕过/ - auth bypass tools
  - jwt - JWT decode, forge (alg none / HS256), public-key confusion, weak-secret brute
- web/杂项/ - misc web tools
  - encdec - encoding kitchen: url/base64/hex/rot13/html/unicode/gzip
  - xssserv - XSS callback server, cookie/path capture
- pwn/ - binary exploitation tools
  - bash/ - lightweight tools
    - pwn-checksec - pure-bash ELF protection checker (NX/PIE/canary/RELRO/FORTIFY)
    - pwn-libc-sym - libc symbol offset lookup
  - python/ - exploit helpers
    - pwn-got - GOT overwrite calculator (format string to GOT)
    - pwn-fmt - format string payload generator (%p scan, %n write, %s leak)
    - pwn-seccomp - seccomp BPF rule analyzer
    - pwn-offset - overflow offset calculator (ret/canary/ret2libc)
    - pwn-gdb - GDB exploit script generator
    - pwn-shell - shellcode/reverse shell generator (x86/x64)
  - rust/ - high-performance core
    - pwn-elf - ELF parser + protection detector (goblin crate)
    - pwn-one - one_gadget finder (execve /bin/sh in libc)
    - pwn-heap - heap chunk metadata parser
- ctf/ - weak-password dictionary, wordlists (dirs/backup/flag/endpoints/users)
- VulnClaw/ - AI-driven pentest CLI
- misseros-iso/ - custom Arch ISO build

## PWN Tools - Recommended External Tools

For comprehensive PWN workflows, install these alongside our tools:

```bash
# Python PWN framework (essential)
pip install pwntools

# ROP gadget finder
pip install ROPgadget
# or: pip install ropper

# one_gadget (find one-shot RCE gadgets in libc)
gem install one_gadget

# seccomp rule analyzer
gem install seccomp-tools

# GDB plugins for exploit development
# pwndbg (recommended):
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh
# or gef:
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Binary analysis framework
# radare2 / rizin
pacman -S radare2  # or: pacman -S rizin
```

## Notes

- ctf/wordlists/ is used by trav via --dict or @file
- pwn/rust/ tools require `cargo build --release` in each subdirectory
- pwn-checksec requires `xxd` (from vim) and `readelf` (from binutils)
- pwn-seccomp BPF parser works standalone; pwntools output parsing included