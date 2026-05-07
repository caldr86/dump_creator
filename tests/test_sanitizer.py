from pathlib import Path
import sys

sys.path.append(str(Path(__file__).resolve().parents[1]))

from scripts.sanitizer import fake_email, fake_phone, key_is_sensitive, redact_by_rule, sanitize_text


def test_sensitive_key_matching_regressions():
    assert key_is_sensitive("membershipToken") is True
    assert key_is_sensitive("shippingPhone") is True
    assert key_is_sensitive("DeviceToken") is True
    assert key_is_sensitive("IPAddress") is False
    assert key_is_sensitive("SignupIPAddress") is False
    assert key_is_sensitive("UserAgent") is False
    assert key_is_sensitive("DeviceID") is False


def test_fake_values_use_salt_deterministically():
    salt = b"test-salt"
    assert fake_email("a@b.com", "c", salt) == fake_email("a@b.com", "c", salt)
    assert fake_phone("+1 555-222-3333", "c", salt) == fake_phone("+1 555-222-3333", "c", salt)


def test_text_sanitizer_preserves_plain_transaction_ids():
    salt = b"test-salt"
    raw = "transaction id 12345678901234567890 and provider 99887766"
    out = sanitize_text(raw, "ctx", salt)
    assert "12345678901234567890" in out
    assert "99887766" in out


def test_explicit_address_and_document_rules():
    salt = b"test-salt"
    assert redact_by_rule("123 Main", "address", "x", salt).startswith("[REDACTED_ADDRESS_")
    assert redact_by_rule("John Doe", "full_name", "x", salt).startswith("Person_")
    assert redact_by_rule("reject: phone +1 333-444-5555", "text_sanitize", "x", salt) != "reject: phone +1 333-444-5555"
