#www~
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict
import urllib
from urllib import error as urllib_error
from urllib import request as urllib_request

from curl_cffi import requests

# DuckMail mailbox used as the single Cloudflare relay target.
DUCKMAIL_API_BASE = os.getenv("DUCKMAIL_API_BASE", "https://api.duckmail.sbs").rstrip("/")
DUCKMAIL_MAIL = (
    os.getenv("DUCKMAIL_MAIL")
    or os.getenv("DUCKMAIL_ADDRESS")
    or "CFNANmxXrn@duckmail.sbs"
)
DUCKMAIL_PWD = (
    os.getenv("DUCKMAIL_PWD")
    or os.getenv("DUCKMAIL_PASSWORD")
    or "QjvRVuYm2MiC"
)
CLOUDFLARE_RELAY_DOMAIN = os.getenv("CLOUDFLARE_RELAY_DOMAIN", "openapi.best")
OTP_REGEX = re.compile(r"(?<!\d)(\d{6})(?!\d)")


class DuckMailClient:
    def __init__(self, address: str, password: str, *, base_url: str = DUCKMAIL_API_BASE) -> None:
        self.address = (address or "").strip()
        self.password = password or ""
        self.base_url = base_url.rstrip("/")
        self.token = ""

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        data: Dict[str, Any] | None = None,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        body = None
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode("utf-8")

        req = urllib_request.Request(
            f"{self.base_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib_request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib_error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"DuckMail request failed: {exc.code}: {raw}") from exc

    def authenticate(self) -> str:
        if self.token:
            return self.token
        if not self.address or not self.password:
            raise RuntimeError("DuckMail credentials are empty")

        resp = self._request_json(
            "POST",
            "/token",
            data={"address": self.address, "password": self.password},
        )
        token = str(resp.get("token") or "").strip()
        if not token:
            raise RuntimeError("DuckMail login did not return a token")
        self.token = token
        return token

    def list_messages(self, page: int = 1) -> list[Dict[str, Any]]:
        self.authenticate()
        resp = self._request_json("GET", f"/messages?page={page}")
        return list(resp.get("hydra:member") or [])

    def get_message(self, message_id: str) -> Dict[str, Any]:
        self.authenticate()
        return self._request_json("GET", f"/messages/{urllib.parse.quote(message_id)}")

    def get_source(self, message_id: str) -> str:
        self.authenticate()
        resp = self._request_json("GET", f"/sources/{urllib.parse.quote(message_id)}")
        return str(resp.get("data") or "")


def generate_registration_email() -> str:
    return f"{uuid.uuid4()}@{CLOUDFLARE_RELAY_DOMAIN}"


def _parse_duckmail_time(value: str) -> datetime:
    if not value:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _extract_oai_code(*parts: Any) -> str:
    for part in parts:
        if part is None:
            continue
        if isinstance(part, list):
            text = "\n".join(str(item) for item in part if item is not None)
        else:
            text = str(part)
        match = OTP_REGEX.search(text)
        if match:
            return match.group(1)
    return ""


def _is_openai_message(message: Dict[str, Any]) -> bool:
    sender = message.get("from") or {}
    sender_name = str(sender.get("name") or "")
    sender_address = str(sender.get("address") or "")
    subject = str(message.get("subject") or "")
    haystack = " ".join((sender_name, sender_address, subject)).lower()
    return "openai" in haystack


def get_oai_code(
    mailbox: DuckMailClient,
    forwarded_email: str,
    *,
    since_ts: datetime,
    attempts: int = 20,
    poll_seconds: int = 3,
) -> str:
    forwarded_email_lower = forwarded_email.lower()
    fallback_code = ""

    for _ in range(attempts):
        for item in mailbox.list_messages(page=1):
            if not _is_openai_message(item):
                continue

            created_at = _parse_duckmail_time(str(item.get("createdAt") or ""))
            updated_at = _parse_duckmail_time(str(item.get("updatedAt") or ""))
            if max(created_at, updated_at) < since_ts:
                continue

            message_id = str(item.get("id") or "").strip()
            if not message_id:
                continue

            detail = mailbox.get_message(message_id)
            detail_dump = json.dumps(detail, ensure_ascii=False).lower()
            raw_source = ""
            alias_hit = forwarded_email_lower in detail_dump
            if not alias_hit:
                raw_source = mailbox.get_source(message_id)
                alias_hit = forwarded_email_lower in raw_source.lower()

            code = _extract_oai_code(
                detail.get("subject"),
                detail.get("text"),
                detail.get("html"),
                raw_source,
            )
            if not code:
                continue
            if alias_hit:
                return code
            if not fallback_code:
                fallback_code = code

        if fallback_code:
            return fallback_code
        time.sleep(poll_seconds)

    raise RuntimeError(f"did not receive OpenAI OTP for {forwarded_email}")
# end


# oauth 
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"

DEFAULT_REDIRECT_URI = f"http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"

def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

def _sha256_b64url_no_pad(s: str) -> str:
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())

def _random_state(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)

def _pkce_verifier() -> str:
    # RFC 7636 allows 43..128 chars; urlsafe token is fine.
    return secrets.token_urlsafe(64)

def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    candidate = callback_url.strip()
    if not candidate:
        return {
            "code": "",
            "state": "",
            "error": "",
            "error_description": "",
        }

    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif any(ch in candidate for ch in "/?#") or ":" in candidate:
            candidate = f"http://{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)

    for key, values in fragment.items():
        if key not in query or not query[key] or not (query[key][0] or "").strip():
            query[key] = values

    def get1(k: str) -> str:
        v = query.get(k, [""])
        return (v[0] or "").strip()

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }

def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}

def _to_int(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0

def _post_form(url: str, data: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )
    try:
        with urllib_request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if resp.status != 200:
                raise RuntimeError(
                    f"token exchange failed: {resp.status}: {raw.decode('utf-8', 'replace')}"
                )
            return json.loads(raw.decode("utf-8"))
    except urllib_error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(
            f"token exchange failed: {exc.code}: {raw.decode('utf-8', 'replace')}"
        ) from exc


@dataclass(frozen=True)
class OAuthStart:
    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str


def generate_oauth_url(*, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE) -> OAuthStart:
    state = _random_state()
    code_verifier = _pkce_verifier()
    code_challenge = _sha256_b64url_no_pad(code_verifier)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "login",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
    )


def submit_callback_url(*, callback_url: str, expected_state: str, code_verifier: str, redirect_uri: str = DEFAULT_REDIRECT_URI) -> str:
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))
# end


def run(proxy: str) -> str:
    session_kwargs: Dict[str, Any] = {"impersonate": "chrome"}
    if proxy:
        session_kwargs["proxies"] = {
            "http": proxy,
            "https": proxy,
        }
    s = requests.Session(**session_kwargs)

    mailbox = DuckMailClient(DUCKMAIL_MAIL, DUCKMAIL_PWD)
    mailbox.authenticate()

    trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10)
    trace = trace.text
    ip_re = re.search(r"^ip=(.+)$", trace, re.MULTILINE)
    loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
    ip = ip_re.group(1) if ip_re else None
    loc = loc_re.group(1) if loc_re else None
    print(loc, ip)
    if loc == "CN" or loc == "HK":
        raise RuntimeError("检查代理哦w")
    email = generate_registration_email()
    print(email)
    oauth = generate_oauth_url()
    url = oauth.auth_url
    resp = s.get(url)
    did = s.cookies.get("oai-did")
    print(did)
    signup_body = f'{{"username":{{"value":"{email}","kind":"email"}},"screen_hint":"signup"}}'
    sen_req_body = f'{{"p":"","id":"{did}","flow":"authorize_continue"}}'
    sen_resp = s.post("https://sentinel.openai.com/backend-api/sentinel/req", headers={"origin": "https://sentinel.openai.com", "referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6", "content-type": "text/plain;charset=UTF-8"}, data=sen_req_body)
    print(sen_resp.status_code)
    sen_resp = sen_resp.json()["token"]
    sentinel = f'{{"p": "", "t": "", "c": "{sen_resp}", "id": "{did}", "flow": "authorize_continue"}}'
    signup_resp = s.post("https://auth.openai.com/api/accounts/authorize/continue", headers={"referer": "https://auth.openai.com/create-account", "accept": "application/json", "content-type": "application/json", "openai-sentinel-token": sentinel}, data=signup_body)
    print(f"signup: {signup_resp.status_code}")
    # Set password via /user/register endpoint
    password = secrets.token_urlsafe(16)
    otp_requested_at = datetime.now(timezone.utc)
    register_body = json.dumps({"password": password, "username": email})
    register_resp = s.post("https://auth.openai.com/api/accounts/user/register", headers={"referer": "https://auth.openai.com/create-account/password", "accept": "application/json", "content-type": "application/json"}, data=register_body)
    print(f"register: {register_resp.status_code}")
    if register_resp.status_code != 200:
        print(register_resp.text[:2000])
        return
    # Trigger email OTP send (register response tells us to GET this endpoint)
    otp_requested_at = datetime.now(timezone.utc)
    otp_send_resp = s.get("https://auth.openai.com/api/accounts/email-otp/send", headers={"referer": "https://auth.openai.com/create-account/password", "accept": "application/json"})
    print(f"email-otp/send: {otp_send_resp.status_code}")
    code = get_oai_code(mailbox, email, since_ts=otp_requested_at)
    print(code)
    code_body = f'{{"code":"{code}"}}'
    code_resp = s.post("https://auth.openai.com/api/accounts/email-otp/validate", headers={"referer": "https://auth.openai.com/email-verification", "accept": "application/json", "content-type": "application/json"}, data=code_body)
    print(code_resp.status_code)
    create_account_body = '{"name":"Neo","birthdate":"2000-02-20"}'
    create_account_resp = s.post("https://auth.openai.com/api/accounts/create_account", headers={"referer": "https://auth.openai.com/about-you", "accept": "application/json", "content-type": "application/json"}, data=create_account_body)
    create_account_status = create_account_resp.status_code
    print(create_account_status)
    if create_account_status != 200:
        print(create_account_resp.text)
        return 
    print(create_account_status)
    auth = s.cookies.get("oai-client-auth-session")
    auth = base64.b64decode(auth.split(".")[0])
    auth = json.loads(auth)
    workspace_id = auth["workspaces"][0]["id"]
    print(workspace_id)
    select_body = f'{{"workspace_id":"{workspace_id}"}}'
    select_resp = s.post("https://auth.openai.com/api/accounts/workspace/select", headers={"referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent", "content-type": "application/json"}, data=select_body)
    print(select_resp.status_code)
    continue_url = select_resp.json()["continue_url"]
    final_resp = s.get(continue_url, allow_redirects=False)
    final_resp = s.get(final_resp.headers.get("Location"), allow_redirects=False)
    final_resp = s.get(final_resp.headers.get("Location"), allow_redirects=False)
    cbk = final_resp.headers.get("Location")
    return submit_callback_url(callback_url=cbk, code_verifier=oauth.code_verifier, redirect_uri=oauth.redirect_uri, expected_state=oauth.state)


def _safe_name(value: str, fallback: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", (value or "").strip()).strip("._-")
    return value or fallback


def save_token_json(token_json: str, output_dir: str = "codex") -> Path:
    data = json.loads(token_json)
    email = _safe_name(str(data.get("email") or ""), "unknown")
    account_id = _safe_name(str(data.get("account_id") or ""), uuid.uuid4().hex)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"{stamp}-{email}-{account_id}.json"
    target.write_text(token_json + "\n", encoding="utf-8")
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register account and persist the generated token json.")
    parser.add_argument("--once", action="store_true", help="Workflow compatibility flag; the script always runs once.")
    parser.add_argument("--output-dir", default="~/m/api/cpa-public/auths", help="Directory used to store generated token json files.")
    parser.add_argument("--proxy", default=None, help="Optional HTTP/HTTPS proxy.")
    args = parser.parse_args(argv)

    while True:
        result = run(args.proxy)
        if not result:
            print("registration did not produce token json", file=sys.stderr)
            return 1

        output_path = save_token_json(result, args.output_dir)
        print(output_path)
        time.sleep(10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
