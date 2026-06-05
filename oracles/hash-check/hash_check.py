"""hash_check reference oracle.

Verifies that bytes fetched through an IPFS gateway match the sha2-256
digest embedded in the claimed CID. The module is intentionally stdlib-only
so it can run in small oracle environments without a full IPFS stack.

Supported CIDs:
  - CIDv0 base58btc sha2-256 multihash, e.g. Qm...
  - CIDv1 base32/base32-upper/base58btc multicodec with sha2-256 multihash

CLI:
    python hash_check.py --cid <cid>
    python hash_check.py --cid <cid> --gateway-url https://ipfs.io/ipfs/{cid}
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Callable


DEFAULT_GATEWAY_URL = "https://ipfs.io/ipfs/{cid}"
MAX_CONTENT_BYTES = 100 * 1024 * 1024
SHA2_256_CODE = 0x12
SHA2_256_LENGTH = 32
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class InvalidCID(ValueError):
    """CID cannot be decoded as a supported sha2-256 IPFS content ID."""


@dataclass(frozen=True)
class HashCheckResult:
    result: str
    passed: bool
    reason: str
    cid: str
    expected_sha256: str | None = None
    observed_sha256: str | None = None
    gateway_url: str | None = None
    observed_at_unix: int = 0
    bytes_read: int = 0


Fetcher = Callable[[str, float], bytes]


def base58btc_decode(value: str) -> bytes:
    """Decode base58btc without third-party dependencies."""
    if not value:
        raise InvalidCID("empty base58 value")
    number = 0
    for char in value:
        try:
            digit = BASE58_ALPHABET.index(char)
        except ValueError as exc:
            raise InvalidCID(f"invalid base58 character {char!r}") from exc
        number = number * 58 + digit

    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeroes = len(value) - len(value.lstrip("1"))
    return (b"\x00" * leading_zeroes) + raw


def decode_uvarint(raw: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode unsigned LEB128 varint used by CIDv1/multicodec."""
    value = 0
    shift = 0
    cursor = offset
    while cursor < len(raw):
        byte = raw[cursor]
        value |= (byte & 0x7F) << shift
        cursor += 1
        if byte < 0x80:
            return value, cursor
        shift += 7
        if shift > 63:
            raise InvalidCID("varint is too large")
    raise InvalidCID("truncated varint")


def _decode_cidv1_payload(cid: str) -> bytes:
    prefix = cid[0]
    body = cid[1:]
    if prefix in {"b", "B"}:
        padded = body.upper() + "=" * ((8 - len(body) % 8) % 8)
        try:
            return base64.b32decode(padded, casefold=True)
        except Exception as exc:
            raise InvalidCID("invalid base32 CID payload") from exc
    if prefix == "z":
        return base58btc_decode(body)
    raise InvalidCID("unsupported CID multibase prefix")


def _sha256_digest_from_multihash(raw: bytes) -> bytes:
    code, offset = decode_uvarint(raw, 0)
    digest_len, offset = decode_uvarint(raw, offset)
    digest = raw[offset:]
    if code != SHA2_256_CODE:
        raise InvalidCID(f"unsupported multihash code 0x{code:x}; expected sha2-256")
    if digest_len != SHA2_256_LENGTH:
        raise InvalidCID(f"unsupported sha2-256 digest length {digest_len}")
    if len(digest) != SHA2_256_LENGTH:
        raise InvalidCID("truncated sha2-256 digest")
    return digest


def cid_sha256_digest(cid: str) -> bytes:
    """Return the sha2-256 digest embedded in a supported CID."""
    if not isinstance(cid, str) or not cid:
        raise InvalidCID("cid must be a non-empty string")

    if cid.startswith("Qm"):
        return _sha256_digest_from_multihash(base58btc_decode(cid))

    payload = _decode_cidv1_payload(cid)
    version, offset = decode_uvarint(payload, 0)
    if version != 1:
        raise InvalidCID(f"unsupported CID version {version}")

    _codec, offset = decode_uvarint(payload, offset)
    return _sha256_digest_from_multihash(payload[offset:])


def cid_sha256_hex(cid: str) -> str:
    return "0x" + cid_sha256_digest(cid).hex()


def gateway_url_for_cid(gateway_url: str, cid: str) -> str:
    if "{cid}" in gateway_url:
        return gateway_url.replace("{cid}", urllib.parse.quote(cid, safe=""))
    return gateway_url.rstrip("/") + "/ipfs/" + urllib.parse.quote(cid, safe="")


def default_fetcher(url: str, timeout_seconds: float) -> bytes:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read(MAX_CONTENT_BYTES + 1)
    return body


def run_hash_check(
    *,
    cid: str,
    gateway_url: str = DEFAULT_GATEWAY_URL,
    timeout_seconds: float = 10.0,
    fetcher: Fetcher = default_fetcher,
) -> HashCheckResult:
    observed_at = int(time.time())
    try:
        expected_digest = cid_sha256_hex(cid)
    except InvalidCID as exc:
        return HashCheckResult(
            result="FAIL",
            passed=False,
            reason=f"invalid cid: {exc}",
            cid=cid,
            observed_at_unix=observed_at,
        )

    url = gateway_url_for_cid(gateway_url, cid)
    try:
        body = fetcher(url, timeout_seconds)
    except (TimeoutError, urllib.error.URLError, OSError) as exc:
        return HashCheckResult(
            result="FAIL",
            passed=False,
            reason=f"gateway fetch failed: {exc}",
            cid=cid,
            expected_sha256=expected_digest,
            gateway_url=url,
            observed_at_unix=observed_at,
        )

    if len(body) > MAX_CONTENT_BYTES:
        return HashCheckResult(
            result="FAIL",
            passed=False,
            reason=f"gateway response exceeds {MAX_CONTENT_BYTES} byte cap",
            cid=cid,
            expected_sha256=expected_digest,
            gateway_url=url,
            observed_at_unix=observed_at,
            bytes_read=len(body),
        )

    observed_digest = "0x" + hashlib.sha256(body).hexdigest()
    passed = observed_digest == expected_digest
    return HashCheckResult(
        result="PASS" if passed else "FAIL",
        passed=passed,
        reason="ok" if passed else "sha256 digest mismatch",
        cid=cid,
        expected_sha256=expected_digest,
        observed_sha256=observed_digest,
        gateway_url=url,
        observed_at_unix=observed_at,
        bytes_read=len(body),
    )


def _cmd_attest(args: argparse.Namespace) -> int:
    result = run_hash_check(
        cid=args.cid,
        gateway_url=args.gateway_url,
        timeout_seconds=args.timeout_seconds,
    )
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0 if result.passed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="hash_check IPFS CID integrity oracle")
    parser.add_argument("--cid", required=True, help="claimed IPFS CID to verify")
    parser.add_argument(
        "--gateway-url",
        default=DEFAULT_GATEWAY_URL,
        help="gateway URL, either base URL or template containing {cid}",
    )
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    parser.set_defaults(func=_cmd_attest)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
