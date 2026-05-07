from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_TEXT_RE = re.compile(r"(?<!\w)(?:\+\d[\d\s().-]{7,}\d|\(\d{2,4}\)[\d\s.-]{6,}\d|\d{3,4}[-.\s]\d{3,4}[-.\s]\d{3,6})(?!\w)")
KEY_VALUE_RE = re.compile(r"(?i)\b(password|pass|token|secret|auth|db_pass|dbpass|gatewaytoken)\b\s*[:=]\s*[^\s,;]+")

SENSITIVE_TOKENS = {
    "email", "mail", "mobile", "phone", "password", "pass", "token", "session", "secret", "auth",
    "db", "dbpass", "db_pass", "gatewaytoken", "first", "firstname", "last", "lastname", "dob", "birth", "dateofbirth",
}
FORCE_SENSITIVE_TOKENS = {"token", "auth", "session", "password", "pass", "secret", "dbpass", "db_pass", "gatewaytoken"}
KEEP_EXACT_KEYS = {
    "ipaddress", "signupipaddress", "useragent", "deviceid", "deviceinfo", "devicehash", "devicefingerprint", "visitorid", "fingerprint",
}


@dataclass
class SanitizerStats:
    email_redactions: int = 0
    phone_redactions: int = 0
    token_redactions: int = 0
    field_redactions: int = 0


def ensure_salt(salt_path: str = "~/.agent-dump-salt") -> bytes:
    p = Path(salt_path).expanduser()
    if not p.exists():
        p.write_bytes(os.urandom(32))
        os.chmod(p, 0o600)
    mode = p.stat().st_mode & 0o777
    if mode != 0o600:
        os.chmod(p, 0o600)
    return p.read_bytes()


def split_key_tokens(key: str) -> set[str]:
    k = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    k = re.sub(r"[_\-]+", " ", k).lower()
    tokens = {t for t in k.split() if t}
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    if compact:
        tokens.add(compact)
    return tokens


def _digest(context: str, value: str, salt: bytes) -> str:
    msg = f"{context}|{value}".encode("utf-8")
    return hmac.new(salt, msg, hashlib.sha256).hexdigest()[:16]


def fake_email(value: str, context: str, salt: bytes) -> str:
    return f"user_{_digest(context, value, salt)}@example.test"


def fake_phone(value: str, context: str, salt: bytes) -> str:
    h = _digest(context, value, salt)
    digits = "".join(str(int(c, 16) % 10) for c in h)
    return "+1" + digits[:10]


def redact_by_rule(value: Any, rule: str, context: str, salt: bytes) -> Any:
    if value is None:
        return None
    text = str(value)
    if rule == "email":
        return fake_email(text, context, salt)
    if rule == "phone":
        return fake_phone(text, context, salt)
    if rule == "phone_code":
        return "+0"
    if rule == "password":
        return "[REDACTED_PASSWORD]"
    if rule in {"token", "secret"}:
        return "[REDACTED]"
    if rule == "first_name":
        return f"First_{_digest(context, text, salt)[:6]}"
    if rule == "last_name":
        return f"Last_{_digest(context, text, salt)[:6]}"
    if rule == "full_name":
        return f"Person_{_digest(context, text, salt)[:8]}"
    if rule == "address":
        return f"[REDACTED_ADDRESS_{_digest(context, text, salt)[:6]}]"
    if rule == "dob":
        return None
    if rule == "text_sanitize":
        return sanitize_maybe_json_text(text, context, salt)
    return value


def key_is_sensitive(key: str) -> bool:
    tokens = split_key_tokens(key)
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    if FORCE_SENSITIVE_TOKENS & tokens or any(t in compact for t in FORCE_SENSITIVE_TOKENS):
        return True
    if compact in KEEP_EXACT_KEYS:
        return False
    return bool(SENSITIVE_TOKENS & tokens)


def sanitize_text(text: str, context: str, salt: bytes, stats: SanitizerStats | None = None) -> str:
    out = EMAIL_RE.sub(lambda m: fake_email(m.group(0), context, salt), text)
    if stats:
        stats.email_redactions += len(EMAIL_RE.findall(text))

    def sub_phone(match: re.Match[str]) -> str:
        raw = match.group(0)
        if stats:
            stats.phone_redactions += 1
        return fake_phone(raw, context, salt)

    out = PHONE_TEXT_RE.sub(sub_phone, out)

    def sub_kv(match: re.Match[str]) -> str:
        if stats:
            stats.token_redactions += 1
        key = match.group(0).split(":", 1)[0].split("=", 1)[0]
        return f"{key}=[REDACTED]"

    return KEY_VALUE_RE.sub(sub_kv, out)


def sanitize_json_like(value: Any, context: str, salt: bytes, stats: SanitizerStats | None = None) -> Any:
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            key_context = f"{context}.{k}"
            if key_is_sensitive(str(k)):
                lk = str(k).lower()
                if "email" in lk or lk == "mail":
                    result[k] = fake_email(str(v), key_context, salt) if v is not None else None
                elif "phone" in lk or "mobile" in lk:
                    result[k] = fake_phone(str(v), key_context, salt) if v is not None else None
                elif "dob" in lk or "birth" in lk:
                    result[k] = None
                elif "first" in lk:
                    result[k] = f"First_{_digest(key_context, str(v), salt)[:6]}" if v is not None else None
                elif "last" in lk:
                    result[k] = f"Last_{_digest(key_context, str(v), salt)[:6]}" if v is not None else None
                else:
                    result[k] = "[REDACTED]" if v is not None else None
                if stats:
                    stats.field_redactions += 1
            else:
                result[k] = sanitize_json_like(v, key_context, salt, stats)
        return result
    if isinstance(value, list):
        return [sanitize_json_like(v, f"{context}[]", salt, stats) for v in value]
    if isinstance(value, str):
        return sanitize_text(value, context, salt, stats)
    return value


def sanitize_maybe_json_text(text: str, context: str, salt: bytes, stats: SanitizerStats | None = None) -> str:
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return sanitize_text(text, context, salt, stats)
    return json.dumps(sanitize_json_like(parsed, context, salt, stats), ensure_ascii=False)
