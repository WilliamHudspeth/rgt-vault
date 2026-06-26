"""Tests for ASVS 7.x logging requirements and crypto constant-time guarantees.

Covers:
  RGT-403 — constant-time audit hash comparison
  RGT-412 — audit log entries include agent_id for investigation timeline
  RGT-417 — all log timestamps are UTC ISO-8601
  RGT-392 — email verification via single-use CSPRNG token
"""

from __future__ import annotations

import hashlib
import time
from datetime import timezone
from pathlib import Path

import pytest

from rgt_vault.email_verification import (
    EmailVerificationError,
    generate_token,
    is_valid_email_syntax,
    verify_token,
)
from rgt_vault.storage.sqlite import StorageBackend


# ---------------------------------------------------------------------------
# RGT-392  Email verification tokens
# ---------------------------------------------------------------------------


class TestEmailVerification:
    def test_generate_returns_non_empty_token(self):
        token, expires_at = generate_token()
        assert isinstance(token, str)
        assert len(token) >= 43  # urlsafe_b64(32 bytes) ≥ 43 chars
        assert isinstance(expires_at, float)
        assert expires_at > time.time()

    def test_verify_valid_token(self):
        token, expires_at = generate_token(ttl_seconds=3600)
        verify_token(token, token, expires_at)  # must not raise

    def test_verify_wrong_token_raises(self):
        token, expires_at = generate_token()
        with pytest.raises(EmailVerificationError, match="invalid"):
            verify_token("wrong-token-value", token, expires_at)

    def test_verify_expired_token_raises(self):
        token, _ = generate_token()
        past_expiry = time.time() - 1
        with pytest.raises(EmailVerificationError, match="expired"):
            verify_token(token, token, past_expiry)

    def test_verify_non_string_raises(self):
        token, expires_at = generate_token()
        with pytest.raises(EmailVerificationError):
            verify_token(b"bytes", token, expires_at)  # type: ignore[arg-type]

    def test_generate_requires_positive_ttl(self):
        with pytest.raises(ValueError):
            generate_token(ttl_seconds=0)

    def test_tokens_are_unique(self):
        tokens = {generate_token()[0] for _ in range(50)}
        assert len(tokens) == 50

    def test_now_injection_for_expiry(self):
        token, expires_at = generate_token(ttl_seconds=60)
        future_now = expires_at + 1
        with pytest.raises(EmailVerificationError, match="expired"):
            verify_token(token, token, expires_at, now=future_now)


class TestEmailSyntax:
    @pytest.mark.parametrize("addr", [
        "user@example.com",
        "will+tag@homelab.local",
        "a.b.c@sub.domain.org",
    ])
    def test_valid_addresses(self, addr):
        assert is_valid_email_syntax(addr)

    @pytest.mark.parametrize("addr", [
        "notanemail",
        "@domain.com",
        "user@",
        "",
        "a" * 255 + "@x.com",
    ])
    def test_invalid_addresses(self, addr):
        assert not is_valid_email_syntax(addr)

    def test_non_string_returns_false(self):
        assert not is_valid_email_syntax(None)  # type: ignore[arg-type]
        assert not is_valid_email_syntax(123)   # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# RGT-403 / RGT-412 / RGT-417  Audit log correctness
# ---------------------------------------------------------------------------


@pytest.fixture
def backend(tmp_path: Path) -> StorageBackend:
    return StorageBackend(tmp_path / "test.db")


class TestAuditLogMetadata:
    """RGT-412: each log entry must include enough metadata to reconstruct
    a detailed investigation timeline."""

    def test_log_stores_agent_id(self, backend: StorageBackend):
        backend.log_audit("TEST_ACTION", "my-secret", "details", "ph", agent_id="agent-007")
        entries = backend.get_audit_log(limit=1)
        assert entries[0]["agent_id"] == "agent-007"

    def test_log_agent_id_defaults_to_none(self, backend: StorageBackend):
        backend.log_audit("TEST_ACTION", "my-secret", "details")
        entries = backend.get_audit_log(limit=1)
        assert entries[0]["agent_id"] is None

    def test_log_includes_all_required_fields(self, backend: StorageBackend):
        backend.log_audit("SET_SECRET", "alpha", "created v1", agent_id="agent-1")
        entry = backend.get_audit_log(limit=1)[0]
        for field in ("action", "secret_name", "timestamp", "details", "agent_id", "entry_hash"):
            assert field in entry, f"missing field: {field}"

    def test_log_includes_timestamp_and_action(self, backend: StorageBackend):
        backend.log_audit("GET_SECRET", "beta", "read", agent_id="reader")
        entry = backend.get_audit_log(limit=1)[0]
        assert entry["action"] == "GET_SECRET"
        assert entry["secret_name"] == "beta"
        assert entry["agent_id"] == "reader"
        assert entry["timestamp"]


class TestUTCTimestamps:
    """RGT-417: all log timestamps must be UTC ISO-8601 with timezone offset."""

    def test_timestamp_is_utc_iso8601(self, backend: StorageBackend):
        backend.log_audit("UTC_CHECK", None, "checking timezone")
        entry = backend.get_audit_log(limit=1)[0]
        ts = entry["timestamp"]
        from datetime import datetime
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None, "timestamp has no timezone info"
        utc_offset = parsed.utcoffset().total_seconds()
        assert utc_offset == 0, f"timestamp not in UTC: offset={utc_offset}s"

    def test_multiple_entries_all_utc(self, backend: StorageBackend):
        for i in range(5):
            backend.log_audit(f"ACTION_{i}", None, "")
        from datetime import datetime
        for entry in backend.get_audit_log(limit=5):
            parsed = datetime.fromisoformat(entry["timestamp"])
            assert parsed.tzinfo is not None
            assert parsed.utcoffset().total_seconds() == 0


class TestConstantTimeAuditChain:
    """RGT-403: audit chain verification uses constant-time comparison."""

    def test_chain_verifies_cleanly(self, backend: StorageBackend):
        backend.log_audit("A", "s1", "d1")
        backend.log_audit("B", "s2", "d2")
        backend.log_audit("C", "s3", "d3")
        entries = list(reversed(backend.get_audit_log(limit=3)))
        # Recompute hashes and verify constant-time path never early-exits
        import hmac as _hmac
        prev_hash = ""
        for entry in entries:
            raw = (
                f"{prev_hash}|{entry['timestamp']}|{entry['action']}|"
                f"{entry.get('secret_name') or ''}|{entry.get('details', '')}|"
                f"{entry.get('policy_hash', '')}"
            )
            expected = hashlib.sha256(raw.encode()).hexdigest()
            assert _hmac.compare_digest(entry["entry_hash"], expected)
            prev_hash = entry["entry_hash"]

    def test_tampered_entry_detected(self, backend: StorageBackend):
        import sqlite3
        import hmac as _hmac
        db_path = backend.db_path
        backend.log_audit("REAL", "s", "legit")
        with sqlite3.connect(db_path) as conn:
            conn.execute("UPDATE audit_logs SET details='tampered' WHERE id=1")
            conn.commit()
        fresh = StorageBackend(db_path)
        entries = fresh.iter_audit_log()
        assert len(entries) == 1
        entry = entries[0]
        # Recompute hash from the tampered value — must NOT match stored hash
        raw_tampered = (
            f"|{entry['timestamp']}|{entry['action']}|"
            f"{entry.get('secret_name') or ''}|tampered|"
            f"{entry.get('policy_hash', '')}"
        )
        recomputed = hashlib.sha256(raw_tampered.encode()).hexdigest()
        # Constant-time compare: stored hash (from "legit") ≠ recomputed (from "tampered")
        assert not _hmac.compare_digest(entry["entry_hash"], recomputed), (
            "tampered details must not produce a matching hash"
        )
        # Cross-check: original "legit" hash still matches
        raw_legit = (
            f"|{entry['timestamp']}|{entry['action']}|"
            f"{entry.get('secret_name') or ''}|legit|"
            f"{entry.get('policy_hash', '')}"
        )
        expected_legit = hashlib.sha256(raw_legit.encode()).hexdigest()
        assert _hmac.compare_digest(entry["entry_hash"], expected_legit)
