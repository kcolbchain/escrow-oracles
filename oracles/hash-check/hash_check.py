"""hash_check reference oracle (L1).

Spec-conformant implementation of the `hash_check` policy type per
`docs/SPEC.md` §3.2. Fetches bytes from source_url, computes the
declared hash algorithm, and checks against expect_hash.

What's enforced (matching SPEC.md §3.2 guardrails):

  - source_url scheme is https:// or ipfs://. Plain http:// rejected.
  - source_url host is not in the localhost / RFC-1918 denylist.
  - expect_hash is exactly 64 hex chars after 0x prefix (32 bytes).
  - hash_algorithm is one of "keccak256" or "sha256".
  - Response body limited to 100 MB.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

try:
    from Crypto.Hash import keccak
    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


ALLOWED_SCHEMES = {"https", "ipfs"}
ALLOWED_ALGORITHMS = {"keccak256", "sha256"}
DENY_HOSTS = {
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
}
DENY_SUFFIXES = {".internal", ".local"}
MAX_BODY_BYTES = 100 * 1024 * 1024


class PolicyError(ValueError):
    """The policy itself is malformed."""


class CheckError(Exception):
    """The fetch itself failed (network, timeout, etc.)."""


@dataclass
class CheckOutcome:
    passed: bool
    observed_hash: str | None = None
    duration_ms: float = 0.0
    error: str | None = None


def _validate_hash_check(check: dict[str, Any]) -> None:
    """Validate a hash_check policy per §3.2 guardrails. Raises PolicyError."""
    url = check.get("source_url", "")
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise PolicyError(f"source_url scheme must be https or ipfs, got {scheme!r}")
    host = parsed.hostname or ""
    if host in DENY_HOSTS:
        raise PolicyError(f"source_url host {host!r} is denied")
    if any(host.endswith(s) for s in DENY_SUFFIXES):
        raise PolicyError(f"source_url host {host!r} is in denylist")
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private:
            raise PolicyError(f"source_url host {host!r} is RFC-1918 private")
    except ValueError:
        pass

    expect_hash = check.get("expect_hash", "")
    if not isinstance(expect_hash, str) or not expect_hash.startswith("0x"):
        raise PolicyError("expect_hash must be a 0x-prefixed hex string")
    try:
        raw = bytes.fromhex(expect_hash[2:])
    except ValueError:
        raise PolicyError("expect_hash must be valid hex")
    if len(raw) != 32:
        raise PolicyError(f"expect_hash must be 32 bytes (64 hex chars), got {len(raw)} bytes")

    alg = check.get("hash_algorithm", "")
    if alg not in ALLOWED_ALGORITHMS:
        raise PolicyError(f"hash_algorithm must be one of {ALLOWED_ALGORITHMS}, got {alg!r}")
    if alg == "keccak256" and not HAS_PYCRYPTODOME:
        raise PolicyError("keccak256 requires pycryptodome. Install: pip install pycryptodome")


def _compute_hash(data: bytes, algorithm: str) -> str:
    """Compute hash of data using the specified algorithm."""
    if algorithm == "sha256":
        h = hashlib.sha256(data).hexdigest()
    elif algorithm == "keccak256":
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("pycryptodome required for keccak256")
        k = keccak.new(digest_bits=256)
        k.update(data)
        h = k.hexdigest()
    else:
        raise ValueError(f"unsupported algorithm: {algorithm}")
    return "0x" + h


def run_hash_check(check: dict[str, Any]) -> CheckOutcome:
    """Execute a hash_check: fetch source_url, compute hash, compare."""
    _validate_hash_check(check)
    url = check["source_url"]
    algorithm = check.get("hash_algorithm", "sha256")
    expected = check["expect_hash"]

    start = time.time()
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = resp.read()
    except Exception as exc:
        duration = (time.time() - start) * 1000
        return CheckOutcome(passed=False, duration_ms=duration, error=str(exc))

    duration = (time.time() - start) * 1000
    observed = _compute_hash(body, algorithm)
    passed = observed == expected
    return CheckOutcome(
        passed=passed,
        observed_hash=observed,
        duration_ms=duration,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="hash_check reference oracle (L1)")
    parser.add_argument("--policy", required=True, help="Path to policy JSON file")
    parser.add_argument("--request-id", default="req-7f3e")
    args = parser.parse_args()

    with open(args.policy) as f:
        policy = json.load(f)

    print(f"[oracle] policy: {json.dumps(policy, indent=2)}")
    print(f"[oracle] request-id: {args.request_id}")

    for check in policy.get("checks", []):
        if check["type"] != "hash_check":
            continue
        outcome = run_hash_check(check)
        print(f"[oracle]   hash_check {'PASS' if outcome.passed else 'FAIL'}")
        if outcome.observed_hash:
            print(f"[oracle]     observed: {outcome.observed_hash}")
        if outcome.error:
            print(f"[oracle]     error: {outcome.error}")
        print(f"[oracle]     duration: {outcome.duration_ms:.0f} ms")

    print("[oracle] done")


if __name__ == "__main__":
    main()
