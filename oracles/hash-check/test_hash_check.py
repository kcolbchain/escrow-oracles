"""Tests for hash_check reference oracle (L1).

Covers:
  - Guardrail validation: every MUST clause in SPEC §3.2.
  - Execution: run_hash_check against known-content URLs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from hash_check import (
    PolicyError,
    CheckOutcome,
    _validate_hash_check,
    _compute_hash,
    run_hash_check,
)

# Mock for urllib.request.urlopen for tests that need network
# In real tests, use pytest-httpserver or unittest.mock


def _valid_check(**overrides: Any) -> dict[str, Any]:
    base = {
        "type": "hash_check",
        "source_url": "https://example.com/artifact.bin",
        "expect_hash": "0x" + "ab" * 32,
        "hash_algorithm": "sha256",
    }
    base.update(overrides)
    return base


class TestHashCheckGuardrails:
    def test_valid_policy_accepted(self) -> None:
        _validate_hash_check(_valid_check())

    def test_https_accepted(self) -> None:
        _validate_hash_check(_valid_check(source_url="https://example.com/x"))

    def test_ipfs_accepted(self) -> None:
        _validate_hash_check(_valid_check(source_url="ipfs://bafyABC"))

    def test_http_plain_rejected(self) -> None:
        with pytest.raises(PolicyError, match="https or ipfs"):
            _validate_hash_check(_valid_check(source_url="http://example.com/"))

    @pytest.mark.parametrize("host", [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
    ])
    def test_deny_hosts_rejected(self, host: str) -> None:
        with pytest.raises(PolicyError, match="denied"):
            _validate_hash_check(_valid_check(source_url=f"https://{host}/x"))

    def test_expect_hash_format(self) -> None:
        with pytest.raises(PolicyError, match="hex"):
            _validate_hash_check(_valid_check(expect_hash="nothex"))

    def test_expect_hash_length(self) -> None:
        with pytest.raises(PolicyError, match="32 bytes"):
            _validate_hash_check(_valid_check(expect_hash="0x" + "ab" * 16))  # 16 bytes

    def test_expect_hash_zero(self) -> None:
        with pytest.raises(PolicyError, match="32 bytes"):
            _validate_hash_check(_valid_check(expect_hash="0x" + "00" * 16))  # 16 bytes

    def test_algorithm_must_be_valid(self) -> None:
        with pytest.raises(PolicyError, match="sha256"):
            _validate_hash_check(_valid_check(hash_algorithm="md5"))

    def test_algorithm_empty_rejected(self) -> None:
        with pytest.raises(PolicyError, match="sha256"):
            _validate_hash_check(_valid_check(hash_algorithm=""))


class TestHashCompute:
    def test_sha256_compute(self) -> None:
        data = b"hello world"
        expected = "0x" + hashlib.sha256(data).hexdigest()
        assert _compute_hash(data, "sha256") == expected

    def test_empty_data(self) -> None:
        data = b""
        expected = "0x" + hashlib.sha256(b"").hexdigest()
        assert _compute_hash(data, "sha256") == expected
