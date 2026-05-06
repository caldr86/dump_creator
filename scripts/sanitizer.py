from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)")
KEY_VALUE_RE = re.compile(r"(?i)\b(password|pass|token|secret|auth|db_pass|dbpass|gatewaytoken)\b\s*[:=]\s*[^\s,;]+")

KEEP_PATTERNS = (
    "ip",
    "ipaddress",
    "useragent",
    "user_agent",
    "device",
    "deviceid",
    "deviceinfo",
    "devicehash",
    "visitorid",
    "fingerprint",
)
SENSITIVE_PATTERNS = (
    "email",
    "mail",
    "mobile",
    "phone",
    "password",
    "pass",
    "token",
    "session",
    "secret",
    "auth",
    "db_pass",
    "dbpass",
    "gatewaytoken",
    "first_name",
    "firstname",
    "lastname",
    "last_name",
    "dob",
    "dateofbirth",
    "birth",
)


@dataclass
class SanitizerStats:
    email_redactions: int = 0
    phone_redactions: int = 0
    token_redactions: int = 0
    field_redactions: int = 0


def _digest(context: str, value: str) -> str:
    return hashlib.sha256(f"{context}|{value}".encode("utf-8")).hexdigest()[:12]


def fake_email(value: str, context: str) -> str:
    return f"user_{_digest(context, value)}@example.test"


def fake_phone(value: str, context: str) -> str:
    h = _digest(context, value)
    digits = "".join(str(int(c, 16) % 10) for c in h)
    return "+1" + digits[:10]


def redact_by_rule(value: Any, rule: str, context: str) -> Any:
    if value is None:
        return None
    text = str(value)
    if rule == "email":
        return fake_email(text, context)
    if rule == "phone":
        return fake_phone(text, context)
    if rule == "phone_code":
        return "+0"
    if rule == "password":
        return "[REDACTED_PASSWORD]"
    if rule in {"token", "secret"}:
        return "[REDACTED]"
    if rule == "first_name":
        return f"First_{_digest(context, text)[:6]}"
    if rule == "last_name":
        return f"Last_{_digest(context, text)[:6]}"
    if rule == "dob":
        return None
    return value


def looks_sensitive_key(key: str) -> bool:
    k = key.lower()
    if any(p in k for p in KEEP_PATTERNS):
        return False
    return any(p in k for p in SENSITIVE_PATTERNS)


def sanitize_text(text: str, context: str, stats: SanitizerStats | None = None) -> str:
    out = text

    def sub_email(match: re.Match[str]) -> str:
        if stats:
            stats.email_redactions += 1
        return fake_email(match.group(0), context)

    def sub_phone(match: re.Match[str]) -> str:
        raw = match.group(0)
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", raw):
            return raw
        if stats:
            stats.phone_redactions += 1
        return fake_phone(raw, context)

    out = EMAIL_RE.sub(sub_email, out)
    out = PHONE_RE.sub(sub_phone, out)

    def sub_kv(match: re.Match[str]) -> str:
        if stats:
            stats.token_redactions += 1
        key = match.group(0).split(":", 1)[0].split("=", 1)[0]
        return f"{key}=[REDACTED]"

    out = KEY_VALUE_RE.sub(sub_kv, out)
    return out


def sanitize_json_like(value: Any, context: str, stats: SanitizerStats | None = None) -> Any:
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            key_context = f"{context}.{k}"
            if looks_sensitive_key(str(k)):
                lk = str(k).lower()
                if "email" in lk or lk == "mail":
                    result[k] = fake_email(str(v), key_context) if v is not None else None
                elif "phone" in lk or "mobile" in lk:
                    result[k] = fake_phone(str(v), key_context) if v is not None else None
                elif "dob" in lk or "birth" in lk:
                    result[k] = None
                elif "first" in lk:
                    result[k] = f"First_{_digest(key_context, str(v))[:6]}" if v is not None else None
                elif "last" in lk:
                    result[k] = f"Last_{_digest(key_context, str(v))[:6]}" if v is not None else None
                else:
                    result[k] = "[REDACTED]" if v is not None else None
                if stats:
                    stats.field_redactions += 1
            else:
                result[k] = sanitize_json_like(v, key_context, stats)
        return result
    if isinstance(value, list):
        return [sanitize_json_like(v, f"{context}[]", stats) for v in value]
    if isinstance(value, str):
        return sanitize_text(value, context, stats)
    return value


def sanitize_maybe_json_text(text: str, context: str, stats: SanitizerStats | None = None) -> str:
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return sanitize_text(text, context, stats)

    cleaned = sanitize_json_like(parsed, context, stats)
    return json.dumps(cleaned, ensure_ascii=False)
