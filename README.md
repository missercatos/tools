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
- ctf/ - weak-password dictionary, wordlists (dirs/backup/flag/endpoints/users)
- VulnClaw/ - AI-driven pentest CLI
- misseros-iso/ - custom Arch ISO build

## Notes

- ctf/wordlists/ is used by trav via --dict or @file
- misseros-out/ and RootStack/ stay in place