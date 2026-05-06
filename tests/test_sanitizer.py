from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scripts.sanitizer import (  # noqa: E402
    SanitizerStats,
    fake_email,
    fake_phone,
    sanitize_json_like,
    sanitize_maybe_json_text,
    sanitize_text,
)


def test_email_redaction_deterministic():
    e1 = fake_email("alice@example.com", "ig_user.Users.Email")
    e2 = fake_email("alice@example.com", "ig_user.Users.Email")
    assert e1 == e2
    assert e1.endswith("@example.test")


def test_phone_redaction_deterministic():
    p1 = fake_phone("+1 (415) 555-1212", "ig_user.Users.Mobile")
    p2 = fake_phone("+1 (415) 555-1212", "ig_user.Users.Mobile")
    assert p1 == p2
    assert p1 != "+1 (415) 555-1212"


def test_token_password_secret_redaction_in_text():
    stats = SanitizerStats()
    text = "password=abc token:xyz auth=qwe"
    cleaned = sanitize_text(text, "ctx", stats)
    assert "abc" not in cleaned
    assert "xyz" not in cleaned
    assert "qwe" not in cleaned
    assert stats.token_redactions >= 1


def test_recursive_json_sanitizer():
    payload = {
        "email": "real@site.com",
        "profile": {
            "firstName": "Alice",
            "lastName": "Doe",
            "mobile": "+1 222 333 4444",
            "nested": [{"token": "abc123"}],
        },
    }
    cleaned = sanitize_json_like(payload, "root")
    assert cleaned["email"].endswith("@example.test")
    assert cleaned["profile"]["firstName"].startswith("First_")
    assert cleaned["profile"]["lastName"].startswith("Last_")
    assert cleaned["profile"]["mobile"].startswith("+1")
    assert cleaned["profile"]["nested"][0]["token"] == "[REDACTED]"


def test_keep_ip_device_useragent_preserved():
    data = {
        "IPAddress": "203.0.113.1",
        "UserAgent": "Mozilla/5.0",
        "DeviceID": "abcdef",
        "comment": "reach me at bob@example.com",
    }
    cleaned = sanitize_json_like(data, "root")
    assert cleaned["IPAddress"] == "203.0.113.1"
    assert cleaned["UserAgent"] == "Mozilla/5.0"
    assert cleaned["DeviceID"] == "abcdef"
    assert "@example.test" in cleaned["comment"]


def test_json_text_path():
    raw = '{"email":"x@y.com", "token":"abc"}'
    out = sanitize_maybe_json_text(raw, "ctx")
    assert "@example.test" in out
    assert "abc" not in out
