# daily-task（Fork 即用版）

这个仓库包含两件事：

1) **GitHub Actions 端**：定时运行 `task_runner.py` 产出 `codex/*.json`，并将其打包发布到 GitHub Releases（可选 age 加密）。
2) **VPS 端**：可选使用 `vps_token_maintain.sh` 定时拉取 release、解密/解压、落盘、全量 wham/usage 检测、删除 401、Telegram 汇报。

> 你只想用 Actions 生成并发布 token：只看「A. GitHub Actions」。
> 你也想让 VPS 自动同步维护：再看「B. VPS」。

---

## A. GitHub Actions（生成 + 发布 Release）

### 目录结构（必须）

把 workflow 放在：

- `.github/workflows/regi+release.yml`
- `.github/workflows/cleanup-token-releases.yml`

### Secrets（按需）

- `AGE_RECIPIENT`（可选，但**强烈推荐**）：age 公钥（形如 `age1...`）。
  - 有它：发布 `tokens.zip.age`（加密）。
  - 没有它：默认 **跳过 Release 上传**（避免 public repo 明文泄露）。

- `ALLOW_PLAINTEXT_RELEASE`（可选，危险）：设置为 `true` 时，允许在没有 `AGE_RECIPIENT` 的情况下发布明文 `tokens.zip`（不推荐）。

- `TG_BOT_TOKEN` / `TG_CHAT_ID`（可选）：Actions 侧轻量通知。未设置会自动跳过。

### 你需要提供的业务脚本

- `task_runner.py`（或你自己的脚本）
- `requirements.txt`

要求：脚本运行后产生 `codex/*.json`。

---

## B. VPS（可选：自动同步 + 全量检查 + 清理失效）

仓库内提供：

- `vps_token_maintain.sh`
- `.env.example`（复制到 `/etc/vps_token_maintain.env`）
- `README_vps_token_maintain.md`

VPS 的定时任务可以选 cron 或 systemd timer，具体命令见 `README_vps_token_maintain.md`。
