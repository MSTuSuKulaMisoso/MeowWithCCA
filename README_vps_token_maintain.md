# VPS Token Maintain 一键脚本

本项目提供一个 **VPS 端一键脚本**（不包含 cron/systemd 配置），用于你自己设置定时任务执行以下流程。

仓库内文件：
- `vps_token_maintain.sh`：VPS 端主脚本（同步 + 全量检查 + 删除401 + TG 汇报）
- `.env.example`：VPS 环境变量模板（复制为 `/etc/vps_token_maintain.env`）
- `README_vps_token_maintain.md`：使用说明
- `.github/workflows/regi+release.yml`：GitHub Actions（跑 task_runner → 打包 →（可选）age 加密 → 上传 Release）
- `.github/workflows/cleanup-token-releases.yml`：GitHub Actions（清理 6 小时前的 tokens-* release）

1. 搜寻 GitHub Releases（tag 以 `tokens-` 开头）
2. 只下载新增部分（增量，按 `published_at` 维护 state）
3. 下载 `manifest.json` + `tokens.zip.age`（或 `tokens.zip`）并校验 sha256
4. 解密（可选）→ 解压缩 `codex/*.json`
5. 只追加写入到 token 库目录（默认 CPA：`/opt/cli-proxy-plus/auths`，可改）
6. 对 token 库做 **全量可用性/额度检查**（调用 `https://chatgpt.com/backend-api/wham/usage`）
7. 对返回 **401** 的 token **直接删除**
8. 通过 Telegram Bot 汇报统计（可选，不配置则跳过）
9. 删除/清理同步产生的 zip、解压目录、下载文件

---

## 1) 依赖

Debian/Ubuntu 示例：

```bash
apt-get update -y
apt-get install -y curl jq unzip age coreutils
```

要求存在命令：
- `curl jq unzip sha256sum find cp rm mktemp date`
- 如果 `USE_AGE=1`（默认），还需要 `age`

---

## 2) 运行方式（脚本放哪都能跑）

你可以**不安装**，把 `vps_token_maintain.sh` 放在任意目录直接运行：

```bash
# 方式 A：在脚本所在目录运行
chmod +x ./vps_token_maintain.sh
./vps_token_maintain.sh

# 方式 B：从任意目录运行（推荐写绝对路径）
bash /path/to/vps_token_maintain.sh

# 指定 env 文件（可选）
ENV_FILE=/etc/vps_token_maintain.env bash /path/to/vps_token_maintain.sh
```

如果你想把它当作系统命令用（可选），再安装到 PATH：

```bash
install -m 755 vps_token_maintain.sh /usr/local/bin/vps_token_maintain

# 之后即可直接运行（/usr/local/bin 通常在 PATH 里）
/usr/local/bin/vps_token_maintain
```

---

## 3) 配置 .env（最少化）

我们提供示例文件：`.env.example`。

推荐：

```bash
install -m 600 .env.example /etc/vps_token_maintain.env
nano /etc/vps_token_maintain.env
```

关键字段说明：
- `REPO` / `REPO_LIST`（必填）
  - 单仓库用 `REPO="owner/repo"`
  - 多仓库用 `REPO_LIST="owner1/repo1,owner2/repo2"`
- `AUTH_DIR`（必填/可改）
  - token 库位置；默认 CPA 可用：`/opt/cli-proxy-plus/auths`
- `USE_AGE`（可选，但必须与 Release 资产对齐）
  - 默认 `USE_AGE=1`：下载 `tokens.zip.age` 并解密
  - `USE_AGE=0`：下载 `tokens.zip`，**跳过解密**
- `AGE_IDENTITY`（仅当 `USE_AGE=1` 时必填）
  - age 私钥路径（敏感）
- `TG_BOT_TOKEN` / `TG_CHAT_ID`（可选）
  - 不填 `TG_BOT_TOKEN` 则自动跳过通知

### 3.1 与 GitHub Actions Release 资产对齐（必须看）

本脚本的 `USE_AGE` 取值，必须与 Actions 上传到 Release 的资产文件名一致：

- **加密发布（推荐）**
  - Actions 侧设置：`AGE_RECIPIENT`（age 公钥）
  - Release 资产：`tokens.zip.age` + `manifest.json`
  - VPS 侧设置：`USE_AGE=1` + `AGE_IDENTITY=/etc/age/xxx.key`

- **不加密发布（强烈不推荐用于 public repo）**
  - Actions 侧不设置 `AGE_RECIPIENT` 时，默认会**跳过上传 Release**；
  - 只有显式设置 `ALLOW_PLAINTEXT_RELEASE=true` 才会上传明文 `tokens.zip`；
  - 此时 VPS 侧设置：`USE_AGE=0`（跳过解密）。

> 建议：即使走 systemd，也把私钥放在 `/etc/age/` 下（权限 600），比放在 `/root/.config/age/` 更不容易遇到 `ProtectHome` 读不到的坑。

---

## 4) age 安装与密钥生成（仅 USE_AGE=1 需要）

安装：

```bash
apt-get update -y
apt-get install -y age
```

生成密钥：

```bash
install -d -m 700 /etc/age
age-keygen -o /etc/age/token-sync.key
chmod 600 /etc/age/token-sync.key

# 输出公钥（给 GitHub Action 用）
age-keygen -y /etc/age/token-sync.key
```

然后在 `/etc/vps_token_maintain.env` 设置：

```bash
AGE_IDENTITY="/etc/age/token-sync.key"
```

---

## 5) 手动运行（验证）

脚本默认会尝试读取：`/etc/vps_token_maintain.env`（如果存在）。

最直接的验证方式（脚本放哪都行）：

```bash
chmod +x ./vps_token_maintain.sh
./vps_token_maintain.sh
```

从任意目录运行：

```bash
bash /path/to/vps_token_maintain.sh
```

指定 env：

```bash
ENV_FILE=/etc/vps_token_maintain.env bash /path/to/vps_token_maintain.sh
```

运行后会输出 summary JSON，并打印 report/log 的绝对路径。

---

## 6) 设置定时任务（你必须选一种）

### 方案 A：cron（最短）

每小时跑一次：

```bash
crontab -e
```

添加（注意把脚本路径改成你实际放的位置）：

```cron
0 * * * * ENV_FILE=/etc/vps_token_maintain.env bash /path/to/vps_token_maintain.sh >/dev/null 2>&1
```

### 方案 B：systemd timer（更稳，推荐）

创建 service：

```bash
cat >/etc/systemd/system/vps-token-maintain.service <<'EOF'
[Unit]
Description=VPS token maintain (sync + scan + delete 401 + tg)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
Environment=ENV_FILE=/etc/vps_token_maintain.env
ExecStart=/bin/bash /path/to/vps_token_maintain.sh
EOF
```

创建 timer：

```bash
cat >/etc/systemd/system/vps-token-maintain.timer <<'EOF'
[Unit]
Description=Run vps token maintain hourly

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
```

启用：

```bash
systemctl daemon-reload
systemctl enable --now vps-token-maintain.timer
systemctl list-timers --all | grep vps-token-maintain
```

查看日志：

```bash
journalctl -u vps-token-maintain.service -n 200 --no-pager
```

## 7) 输出文件（绝对路径）

- token 库目录（落地 token）：
  - `$AUTH_DIR`（默认 `/opt/cli-proxy-plus/auths/`）
- 同步状态与临时目录：
  - `/opt/cli-proxy-plus/token-sync/`
- 全量检查报告：
  - `/opt/cli-proxy-plus/auth-check/reports/report-<RUN_ID>.json`
- 脚本运行日志：
  - `/opt/cli-proxy-plus/token-maintain/logs/run-<RUN_ID>.log`

---

## 7) 安全说明

- 脚本不会在日志中输出 `TG_BOT_TOKEN`、age 私钥、token 明文。
- wham/usage 检测使用临时 curl config 文件写入 `Authorization` 和 `Chatgpt-Account-Id` header，避免 token 出现在进程 argv。
- 建议：
  - 私钥文件 `chmod 600`
  - env 文件 `chmod 600`
  - 运行用户使用 root 或具备写入 `/opt/cli-proxy-plus/*` 权限
