from __future__ import annotations

import base64
import hashlib
import sys
from pathlib import Path
from typing import Callable

HASH_CHECK_DIR = Path(__file__).resolve().parents[1] / "oracles" / "hash-check"
sys.path.insert(0, str(HASH_CHECK_DIR))

from hash_check import (  # noqa: E402
    InvalidCID,
    cid_sha256_hex,
    gateway_url_for_cid,
    run_hash_check,
)


def _encode_uvarint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _cidv1_raw_sha256(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    payload = (
        _encode_uvarint(1)
        + _encode_uvarint(0x55)  # raw multicodec
        + _encode_uvarint(0x12)  # sha2-256
        + _encode_uvarint(32)
        + digest
    )
    return "b" + base64.b32encode(payload).decode("ascii").lower().rstrip("=")


def _fetcher(content: bytes) -> Callable[[str, float], bytes]:
    def fetch(_url: str, _timeout_seconds: float) -> bytes:
        return content

    return fetch


def test_valid_cid_passes_when_gateway_content_matches() -> None:
    content = b"release payment only when this file matches"
    cid = _cidv1_raw_sha256(content)

    result = run_hash_check(cid=cid, fetcher=_fetcher(content))

    assert result.passed is True
    assert result.result == "PASS"
    assert result.expected_sha256 == result.observed_sha256
    assert result.bytes_read == len(content)


def test_tampered_content_fails_with_digest_mismatch() -> None:
    cid = _cidv1_raw_sha256(b"original content")

    result = run_hash_check(cid=cid, fetcher=_fetcher(b"tampered content"))

    assert result.passed is False
    assert result.result == "FAIL"
    assert result.reason == "sha256 digest mismatch"
    assert result.expected_sha256 != result.observed_sha256


def test_gateway_timeout_fails_without_throwing() -> None:
    cid = _cidv1_raw_sha256(b"content")

    def timeout_fetcher(_url: str, _timeout_seconds: float) -> bytes:
        raise TimeoutError("simulated gateway timeout")

    result = run_hash_check(cid=cid, fetcher=timeout_fetcher)

    assert result.passed is False
    assert result.result == "FAIL"
    assert "gateway fetch failed" in result.reason


def test_invalid_cid_format_fails_cleanly() -> None:
    result = run_hash_check(cid="not-a-cid", fetcher=_fetcher(b"unused"))

    assert result.passed is False
    assert result.result == "FAIL"
    assert "invalid cid" in result.reason


def test_decode_cid_digest_matches_expected_sha256() -> None:
    content = b"cid parser digest"
    cid = _cidv1_raw_sha256(content)

    assert cid_sha256_hex(cid) == "0x" + hashlib.sha256(content).hexdigest()


def test_gateway_template_and_base_url_are_supported() -> None:
    cid = _cidv1_raw_sha256(b"gateway")

    assert gateway_url_for_cid("https://example.test/ipfs/{cid}", cid).endswith(cid)
    assert gateway_url_for_cid("https://example.test", cid) == f"https://example.test/ipfs/{cid}"


def test_unsupported_cid_raises_from_digest_helper() -> None:
    try:
        cid_sha256_hex("zbad")
    except InvalidCID as exc:
        assert str(exc)
    else:
        raise AssertionError("expected InvalidCID")
