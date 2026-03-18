#!/usr/bin/env bash
set -euo pipefail

##############################################
# VPS 一键脚本：Release 拉取 → 解密解压 → 全量检查 → 删除401 → TG通知 → 清理
#
# 说明：
# - 不负责安装/配置 systemd/cron；你自己把本脚本加入定时任务即可。
# - 全程使用绝对路径，和脚本放置位置无关。
# - 不在日志中输出任何 token/密钥。
#
# 依赖命令：curl jq unzip age sha256sum find cp rm mktemp date
##############################################

############### 用户需要配置的环境变量（尽量少） ###############
# 本脚本支持从 .env 文件读取（推荐）：
#   - 默认读取：/etc/vps_token_maintain.env（若存在）
#   - 或者你可以设置：ENV_FILE="/path/to/your.env"
# .env 文件里写：KEY="VALUE" 这种 bash 兼容格式。

# 1) GitHub 仓库（单仓库二选一：REPO 或 REPO_LIST）
# export REPO="owner/repo"
# export REPO_LIST="owner1/repo1,owner2/repo2"

# 2) age 私钥路径（敏感：只放本机，chmod 600；建议放到 /etc/age 下，避免 systemd ProtectHome 读不到）
# export AGE_IDENTITY="/etc/age/xxx.key"

# 3) Telegram Bot（可选；不配置则不通知）
# export TG_BOT_TOKEN="123456:AA..."
# export TG_CHAT_ID="<你的chat_id>"

############### 可选参数（一般不需要改） ###############
MAX_PER_RUN="${MAX_PER_RUN:-20}"          # 每个 repo 单次最多处理多少个新 release
SLEEP_SEC="${SLEEP_SEC:-0.2}"             # 全量检查时每个 token 的 sleep（避免风控）
TIMEOUT_SEC="${TIMEOUT_SEC:-12}"          # 单次 wham/usage 请求超时

# 固定 UA（尽量贴近 codex_cli）
UA="${UA:-codex_cli_rs/universal (Windows)}"
USAGE_URL="${USAGE_URL:-https://chatgpt.com/backend-api/wham/usage}"

############### 读取 .env（推荐） ###############
# 说明：为了让读者无需 export 一堆变量，本脚本会尝试读取 .env。
# - 优先读取 $ENV_FILE
# - 否则读取 /etc/vps_token_maintain.env（如果存在）
ENV_FILE="${ENV_FILE:-}"
if [ -n "$ENV_FILE" ] && [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
elif [ -f "/etc/vps_token_maintain.env" ]; then
  # shellcheck disable=SC1090
  source "/etc/vps_token_maintain.env"
fi

############### 固定目录（绝对路径） ###############
# 说明：
# - 默认按 CPA 的目录结构（/opt/cli-proxy-plus/*）
# - 你可以通过 .env 覆盖 AUTH_DIR（token 库路径）
BASE_DIR="/opt/cli-proxy-plus"
AUTH_DIR="${AUTH_DIR:-$BASE_DIR/auths}"
SYNC_DIR="$BASE_DIR/token-sync"
INBOX_DIR="$SYNC_DIR/inbox"
WORK_DIR="$SYNC_DIR/work"
SYNC_LOG="$SYNC_DIR/logs/sync.log"
CHECK_DIR="$BASE_DIR/auth-check"
REPORT_DIR="$CHECK_DIR/reports"
CHECK_LOG_DIR="$CHECK_DIR/logs"
MAINTAIN_DIR="$BASE_DIR/token-maintain"
MAINTAIN_LOG_DIR="$MAINTAIN_DIR/logs"

mkdir -p "$AUTH_DIR" \
  "$SYNC_DIR/logs" "$INBOX_DIR" "$WORK_DIR" \
  "$REPORT_DIR" "$CHECK_LOG_DIR" \
  "$MAINTAIN_LOG_DIR"
chmod 700 "$SYNC_DIR" "$CHECK_DIR" "$MAINTAIN_DIR" 2>/dev/null || true

RUN_ID="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="$MAINTAIN_LOG_DIR/run-$RUN_ID.log"

log(){ echo "[$(date -Is)] $*" >>"$LOG_FILE"; }
die(){ log "ERROR: $*"; exit 1; }
need(){ command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令：$1"; }

need curl
need jq
need unzip
need sha256sum

# 是否使用 age 解密：
# - 默认 USE_AGE=1（即需要 tokens.zip.age + AGE_IDENTITY）
# - 如果 release 没加密，设置 USE_AGE=0，脚本会尝试下载 tokens.zip 并跳过解密
USE_AGE="${USE_AGE:-1}"
if [ "$USE_AGE" != "0" ]; then
  need age
fi
need find
need cp
need rm
need mktemp
need date

# 读取仓库配置
REPOS_CSV="${REPO_LIST:-${REPO:-}}"
[ -n "$REPOS_CSV" ] || die "请设置 REPO 或 REPO_LIST"
IFS=',' read -r -a REPOS <<<"$REPOS_CSV"

# age 私钥（仅当 USE_AGE=1 时需要）
if [ "$USE_AGE" != "0" ]; then
  : "${AGE_IDENTITY:?请设置 AGE_IDENTITY（age 私钥路径），或设置 USE_AGE=0 跳过解密}"
  [ -f "$AGE_IDENTITY" ] || die "AGE_IDENTITY 文件不存在：$AGE_IDENTITY"
  chmod 600 "$AGE_IDENTITY" 2>/dev/null || true
fi

count_auths(){ find "$AUTH_DIR" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' '; }

pre_auths="$(count_auths)"
log "pre_auths=$pre_auths"

##############################################
# Step 1) 同步 GitHub Releases（增量）
##############################################
log "step1: sync releases"

for REPO_ITEM in "${REPOS[@]}"; do
  REPO_ITEM="$(echo "$REPO_ITEM" | xargs)"
  [ -n "$REPO_ITEM" ] || continue

  # 每个 repo 独立 state，避免互相覆盖
  STATE_FILE="$SYNC_DIR/state-${REPO_ITEM//\//_}.json"
  LAST_PROCESSED=""
  if [ -f "$STATE_FILE" ]; then
    LAST_PROCESSED=$(jq -r '.last_processed_published_at // ""' "$STATE_FILE" 2>/dev/null || true)
  fi

  log "sync repo=$REPO_ITEM last_processed_published_at=${LAST_PROCESSED:-<none>} state=$STATE_FILE"

  RELEASES_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO_ITEM}/releases?per_page=50")

  # 关键：用 published_at（优先）做增量，避免 created_at 相同导致漏拉
  CANDIDATES=$(echo "$RELEASES_JSON" | jq -c '[.[]
    | select(.tag_name|startswith("tokens-"))
    | {tag: .tag_name, ts: (.published_at // .created_at)}
  ] | sort_by(.ts)')

  TOTAL=$(echo "$CANDIDATES" | jq 'length')
  if [ "$TOTAL" -le 0 ]; then
    log "repo=$REPO_ITEM no tokens-* releases"
    continue
  fi

  processed=0

  for i in $(seq 0 $((TOTAL-1))); do
    TAG=$(echo "$CANDIDATES" | jq -r ".[${i}].tag")
    TS=$(echo "$CANDIDATES" | jq -r ".[${i}].ts")

    if [ -n "$LAST_PROCESSED" ]; then
      if [[ "$TS" < "$LAST_PROCESSED" || "$TS" == "$LAST_PROCESSED" ]]; then
        continue
      fi
    fi

    log "download repo=$REPO_ITEM tag=$TAG ts=$TS"

    # 资产命名约定：
    # - 加密模式（USE_AGE=1）：tokens.zip.age + manifest.json
    # - 非加密模式（USE_AGE=0）：tokens.zip + manifest.json
    if [ "$USE_AGE" != "0" ]; then
      ASSET_URL="https://github.com/${REPO_ITEM}/releases/download/${TAG}/tokens.zip.age"
    else
      ASSET_URL="https://github.com/${REPO_ITEM}/releases/download/${TAG}/tokens.zip"
    fi
    MANIFEST_URL="https://github.com/${REPO_ITEM}/releases/download/${TAG}/manifest.json"

    MANIFEST_PATH="$INBOX_DIR/manifest-${REPO_ITEM//\//_}-${TAG}.json"
    if [ "$USE_AGE" != "0" ]; then
      ASSET_PATH="$INBOX_DIR/tokens-${REPO_ITEM//\//_}-${TAG}.zip.age"
    else
      ASSET_PATH="$INBOX_DIR/tokens-${REPO_ITEM//\//_}-${TAG}.zip"
    fi

    curl -fsSL "$MANIFEST_URL" -o "$MANIFEST_PATH"
    EXPECTED_SHA=$(jq -r '.sha256' "$MANIFEST_PATH")
    COUNT=$(jq -r '.count' "$MANIFEST_PATH" 2>/dev/null || echo "?")
    [ -n "$EXPECTED_SHA" ] && [ "$EXPECTED_SHA" != "null" ] || die "manifest 缺少 sha256（repo=$REPO_ITEM tag=$TAG）"

    curl -fL "$ASSET_URL" -o "$ASSET_PATH"

    GOT_SHA=$(sha256sum "$ASSET_PATH" | awk '{print $1}')
    if [ "$GOT_SHA" != "$EXPECTED_SHA" ]; then
      die "sha256 不匹配（repo=$REPO_ITEM tag=$TAG expected=$EXPECTED_SHA got=$GOT_SHA）"
    fi
    log "sha256 ok repo=$REPO_ITEM tag=$TAG count=$COUNT"

    ZIP_PATH="$WORK_DIR/tokens-${REPO_ITEM//\//_}-${TAG}.zip"
    rm -f "$ZIP_PATH"

    # 解密 .age → zip（或直接使用 tokens.zip）
    if [ "$USE_AGE" != "0" ]; then
      age -d -i "$AGE_IDENTITY" -o "$ZIP_PATH" "$ASSET_PATH"
    else
      cp -f "$ASSET_PATH" "$ZIP_PATH"
    fi

    UNZIP_DIR="$WORK_DIR/unzipped-${REPO_ITEM//\//_}-${TAG}"
    rm -rf "$UNZIP_DIR"
    mkdir -p "$UNZIP_DIR"

    unzip -o "$ZIP_PATH" -d "$UNZIP_DIR" >/dev/null

    SRC_DIR="$UNZIP_DIR/codex"
    [ -d "$SRC_DIR" ] || die "zip 内缺少 codex/（repo=$REPO_ITEM tag=$TAG）"

    # 只追加：不覆盖同名 token
    cp -n "$SRC_DIR"/*.json "$AUTH_DIR"/ || true
    chmod 600 "$AUTH_DIR"/*.json 2>/dev/null || true

    # 清理本次临时文件（zip/解压目录/下载产物）
    rm -f "$ZIP_PATH" 2>/dev/null || true
    rm -rf "$UNZIP_DIR" 2>/dev/null || true
    rm -f "$ASSET_PATH" "$MANIFEST_PATH" 2>/dev/null || true

    # 更新 state（仅在成功追加后更新）
    tmp=$(mktemp)
    jq -n \
      --arg tag "$TAG" \
      --arg published_at "$TS" \
      --arg processed_at "$(date -Is)" \
      '{last_processed_tag:$tag,last_processed_published_at:$published_at,processed_at:$processed_at}' >"$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$STATE_FILE"
    chmod 600 "$STATE_FILE" 2>/dev/null || true

    processed=$((processed+1))
    LAST_PROCESSED="$TS"

    if [ "$processed" -ge "$MAX_PER_RUN" ]; then
      log "repo=$REPO_ITEM reached MAX_PER_RUN=$MAX_PER_RUN"
      break
    fi
  done

done

post_sync_auths="$(count_auths)"
added=$((post_sync_auths - pre_auths))
log "post_sync_auths=$post_sync_auths added=$added"

##############################################
# Step 2) 全量检查（最关键）
##############################################
log "step2: full scan wham/usage"

REPORT_JSON="$REPORT_DIR/report-$RUN_ID.json"
CHECK_LOG="$CHECK_LOG_DIR/run-$RUN_ID.log"

scan_log(){ echo "[$(date -Is)] $*" >>"$CHECK_LOG"; }

OK=0
INVALID=0
NOQUOTA=0
OTHER=0
SKIP=0

deleted=0

declare -a items_json

mapfile -t files < <(find "$AUTH_DIR" -maxdepth 1 -type f -name '*.json' -print | sort)
TOTAL=${#files[@]}

for f in "${files[@]}"; do
  name=$(basename "$f")

  # 从 token 文件读取 access_token / account_id
  access=$(jq -r '.access_token // .accessToken // empty' "$f" 2>/dev/null || true)
  acc=$(jq -r '.account_id // .chatgpt_account_id // .chatgptAccountId // empty' "$f" 2>/dev/null || true)

  if [ -z "$access" ] || [ -z "$acc" ]; then
    SKIP=$((SKIP+1))
    items_json+=("$(jq -nc --arg name "$name" --arg result "SKIP" --arg reason "missing access_token/account_id" '{name:$name,result:$result,reason:$reason}')")
    scan_log "$name -> SKIP"
    continue
  fi

  # 用 curl 临时 config 文件，避免 token 出现在 argv
  tmp_body=$(mktemp)
  cfg=$(mktemp)
  chmod 600 "$cfg" 2>/dev/null || true

  cat >"$cfg" <<EOF_CURL
silent
show-error
max-time = "$TIMEOUT_SEC"
header = "accept: application/json"
header = "user-agent: $UA"
header = "authorization: Bearer $access"
header = "chatgpt-account-id: $acc"
url = "$USAGE_URL"
output = "$tmp_body"
write-out = "%{http_code}"
EOF_CURL

  code=$(curl --config "$cfg" || true)
  rm -f "$cfg"

  result="OTHER"
  reason="http_$code"

  if [ "$code" = "200" ]; then
    result="OK"; OK=$((OK+1))
  elif [ "$code" = "401" ]; then
    result="INVALID"; INVALID=$((INVALID+1))
    # 直接删除失效 token
    rm -f "$f" || true
    deleted=$((deleted+1))
  elif [ "$code" = "402" ]; then
    result="NO_QUOTA"; NOQUOTA=$((NOQUOTA+1))
  else
    OTHER=$((OTHER+1))
    # 可选：保存少量错误 hint，避免泄露
    hint=$(head -c 120 "$tmp_body" | tr '\n' ' ' | tr '\r' ' ')
    reason="$reason:${hint}"
  fi

  rm -f "$tmp_body"

  items_json+=("$(jq -nc --arg name "$name" --arg result "$result" --arg reason "$reason" '{name:$name,result:$result,reason:$reason}')")
  scan_log "$name -> $result"

  # 节流，避免风控
  if [ "$SLEEP_SEC" != "0" ]; then
    sleep "$SLEEP_SEC" || true
  fi

done

post_delete_auths="$(count_auths)"

summary=$(jq -nc \
  --arg ts "$(date -Is)" \
  --arg total "$TOTAL" \
  --arg ok "$OK" \
  --arg invalid "$INVALID" \
  --arg noquota "$NOQUOTA" \
  --arg other "$OTHER" \
  --arg skip "$SKIP" \
  --arg deleted "$deleted" \
  --arg added "$added" \
  --arg post_sync "$post_sync_auths" \
  --arg remain "$post_delete_auths" \
  '{ts:$ts,total:($total|tonumber),ok:($ok|tonumber),invalid_401:($invalid|tonumber),no_quota:($noquota|tonumber),other:($other|tonumber),skip:($skip|tonumber),deleted_401:($deleted|tonumber),added:($added|tonumber),post_sync_total:($post_sync|tonumber),remain:($remain|tonumber)}')

jq -nc --argjson summary "$summary" --argjson items "[$(IFS=,; echo "${items_json[*]-}") ]" '{summary:$summary,items:$items}' >"$REPORT_JSON"
chmod 600 "$REPORT_JSON" "$CHECK_LOG" 2>/dev/null || true

log "scan_summary=$summary report=$REPORT_JSON"

##############################################
# Step 3) Telegram 通知
##############################################
msg=$(cat <<MSG
token-maintain hourly
新增: $added
同步后总数: $post_sync_auths
检查结果: total=$TOTAL ok=$OK invalid_401=$INVALID no_quota=$NOQUOTA other=$OTHER skip=$SKIP
已删除401: $deleted
剩余: $post_delete_auths
MSG
)

if [ -n "${TG_BOT_TOKEN:-}" ]; then
  [ -n "${TG_CHAT_ID:-}" ] || die "已设置 TG_BOT_TOKEN 但未设置 TG_CHAT_ID"

  cfg=$(mktemp)
  msg_file=$(mktemp)
  chmod 600 "$cfg" "$msg_file" 2>/dev/null || true
  printf '%s' "$msg" >"$msg_file"

  cat >"$cfg" <<EOF_CURL
silent
url = "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage"
request = POST
EOF_CURL

  if curl --config "$cfg" \
    --data-urlencode "chat_id=${TG_CHAT_ID}" \
    --data-urlencode "text@${msg_file}" \
    --data-urlencode "disable_web_page_preview=true" \
    >/dev/null 2>/dev/null; then
    log "tg sent"
  else
    log "tg send failed"
  fi

  rm -f "$cfg" "$msg_file"
else
  log "TG_BOT_TOKEN empty; skip tg send"
fi

log "done"

echo "$summary" | jq .

echo "report: $REPORT_JSON"
echo "log: $LOG_FILE"
