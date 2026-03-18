# Action-task（Fork 即用版：Actions 生成 Token + VPS 自动维护）

这个仓库包含两条链路：

- **GitHub Actions（产出端）**：定时运行你的 `task_runner.py`，生成 `codex/*.json`，打包后发布到 GitHub Releases（可选 age 加密）。
- **VPS（维护端，可选）**：用 `vps_token_maintain.sh` 定时拉取 release、校验、解密/解压、落盘、全量 wham/usage 检测、删除 401、Telegram 汇报。

> 只想用 Actions：看「README_repo_root.md」。
> 还想 VPS 自动维护：看「README_vps_token_maintain.md」。

---

## 仓库文件结构

- `.github/workflows/regi+release.yml`：Actions（跑 task_runner → 打包 →（可选）age 加密 → 上传 Release）
- `.github/workflows/cleanup-token-releases.yml`：Actions（清理 6 小时前的 `tokens-*` release）
- `vps_token_maintain.sh`：VPS 一键脚本（同步 + 全量检查 + 删除401 + TG 汇报）
- `.env.example`：VPS 环境变量模板（复制为 `/etc/vps_token_maintain.env`）

---

## A) GitHub Actions（生成 + 发布 Release）

### 1) 你需要提供的业务脚本

仓库中需要包含：

- `task_runner.py`（或你自己的脚本入口）
- `requirements.txt`

要求：脚本运行后产出 `codex/*.json`。

### 2) Actions Secrets（按需配置）

#### 强烈推荐：加密发布

- `AGE_RECIPIENT`（推荐）：age 公钥（形如 `age1...`）
  - 设置后：Release 上传 `tokens.zip.age` + `manifest.json`。

#### 不加密发布（危险，不推荐 public repo）

- 如果 **未设置** `AGE_RECIPIENT`：workflow 默认**跳过 Release 上传**（避免误把明文 token 公开）。
- 只有你显式设置 `ALLOW_PLAINTEXT_RELEASE=true`（Secret），才允许上传明文 `tokens.zip`。

#### Telegram 通知（可选）

- `TG_BOT_TOKEN` / `TG_CHAT_ID`：有则发轻量通知；没配就自动跳过。

### 3) permissions

workflow 已包含：

```yaml
permissions:
  contents: write
```

因此使用 `${{ github.token }}` 即可创建/更新 release，无需 PAT。

---

## B) VPS（可选：自动同步 + 全量检查 + 清理失效）

### 1) 依赖

Debian/Ubuntu：

```bash
apt-get update -y
apt-get install -y curl jq unzip coreutils
# USE_AGE=1 时需要：
apt-get install -y age
```
**安装age后会得到公钥和私钥，公钥存Action的secret，名字叫`AGE_RECIPIENT`。私钥存VPS本地，路径填入`.env`文件的`AGE_IDENTITY="/etc/age/xxx.key"`。**

### 2) 放置脚本（放哪都能跑）

```bash
chmod +x ./vps_token_maintain.sh
./vps_token_maintain.sh

# 或从任意目录运行
bash /path/to/vps_token_maintain.sh

# 指定 env（可选）
ENV_FILE=/etc/vps_token_maintain.env bash /path/to/vps_token_maintain.sh
```

### 3) 配置 env
> 先填好`.env.example`里的环境设置再安装
```bash
install -m 600 .env.example /etc/vps_token_maintain.env
nano /etc/vps_token_maintain.env
```

关键参数：
- `REPO` 或 `REPO_LIST`：要拉取的 GitHub 仓库
- `AUTH_DIR`：token 落地目录（默认示例：`/opt/cli-proxy-plus/auths`）
- `USE_AGE`：必须与 Release 资产对齐
  - `USE_AGE=1`：拉 `tokens.zip.age`（需要 `AGE_IDENTITY` 私钥）
  - `USE_AGE=0`：拉 `tokens.zip`（不解密）

### 4) 设置定时任务（二选一）

#### 方案 A：cron（最短）

```bash
crontab -e
```

加一行（把脚本路径改成实际位置）：

```cron
0 * * * * ENV_FILE=/etc/vps_token_maintain.env bash /path/to/vps_token_maintain.sh >/dev/null 2>&1
```

#### 方案 B：systemd timer（推荐）

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

systemctl daemon-reload
systemctl enable --now vps-token-maintain.timer
systemctl list-timers --all | grep vps-token-maintain
```

查看日志：

```bash
journalctl -u vps-token-maintain.service -n 200 --no-pager
```
