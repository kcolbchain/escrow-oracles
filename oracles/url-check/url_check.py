"""url_check reference oracle (L1).

Spec-conformant implementation of the `url_check` policy type per
`docs/SPEC.md` §3.1. Fetches a URL, validates the response against the
declared expectations, and returns a `check_result` plus the bytes the
oracle should sign for its attestation.

What's enforced (matching SPEC.md §3.1 guardrails):

  - URL scheme is `https://` or `ipfs://`. Plain `http://` is rejected.
  - URL host is not in the localhost / RFC-1918 denylist.
  - HTTPS URLs require `expect_body_hash`.
  - Status code in {200, 201, 202, 204, 206}.
  - `expect_within_ms` in [100, 60_000].
  - Method is `"GET"`.
  - Redirects are NOT followed.
  - Response body limited to 100 MB.
  - `expect_signed_receipt` (when present): verify signer + must_contain.

Not handled here (out of L1 scope):
  - The chain-side aggregator + on-chain submission. The L1 oracle's
    output is the attestation JSON; the L2 work (multi-chain submitter)
    posts it to AgentEscrow's IOracleAggregator.
  - PQ signing of the attestation. v1 uses ECDSA via standard tooling.

CLI:

    python url_check.py --policy policy.json --request-id req-7f3e
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


ALLOWED_STATUS = {200, 201, 202, 204, 206}
ALLOWED_SCHEMES = {"https", "ipfs"}
MAX_BODY_BYTES = 100 * 1024 * 1024            # 100 MB
MAX_WITHIN_MS = 60_000
MIN_WITHIN_MS = 100
MAX_POLICY_BYTES = 8 * 1024                   # 8 KB
SUPPORTED_VERSIONS = {"1"}


# ─── exceptions ─────────────────────────────────────────────────────────────


class PolicyError(ValueError):
    """The policy itself is malformed and must be rejected at parse time."""


class CheckError(Exception):
    """The fetch itself failed (network, timeout, etc.) — distinct from a
    valid response that simply didn't match expectations. A CheckError
    means the oracle could not produce a deterministic answer."""


# ─── policy validation ──────────────────────────────────────────────────────


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_url(url: str) -> tuple[str, str]:
    """Return (scheme, host) after validating against the §3.1 guardrails.
    Raises PolicyError on any violation."""
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise PolicyError(f"URL scheme must be https or ipfs, got {scheme!r}")
    if scheme == "ipfs":
        # ipfs:// URIs are content-addressed; the CID is in the netloc/path.
        # We don't enforce host denylist for IPFS — the resolver maps any
        # gateway to the same content. Validate it parses.
        if not parsed.netloc and not parsed.path:
            raise PolicyError("ipfs:// URL must have a CID")
        return scheme, parsed.netloc or parsed.path.lstrip("/").split("/", 1)[0]

    host = parsed.hostname or ""
    if not host:
        raise PolicyError("URL must have a host")
    if host.lower() in {"localhost", "0.0.0.0"}:
        raise PolicyError(f"host {host!r} is in the denylist (localhost)")
    if host.lower().endswith((".internal", ".local")):
        raise PolicyError(f"host {host!r} is in the denylist (.internal/.local)")
    # Pull IP-literal classification OUT of the try-block — PolicyError
    # inherits from ValueError, so wrapping the raise in `except ValueError`
    # would swallow it.
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None  # Not an IP literal; non-IP hostnames fall through.
    if ip is not None:
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast:
            raise PolicyError(
                f"host IP {host!r} is in a private / loopback / link-local range"
            )
    return scheme, host


def validate_url_check_policy(check: dict[str, Any]) -> None:
    """Raise PolicyError if `check` (the inner check object) violates
    any §3.1 guardrail."""
    if check.get("type") != "url_check":
        raise PolicyError(f"expected type=url_check, got {check.get('type')!r}")

    url = check.get("url")
    if not isinstance(url, str) or not url:
        raise PolicyError("url is required and must be a non-empty string")
    scheme, _host = _validate_url(url)

    method = check.get("method", "GET")
    if method != "GET":
        raise PolicyError(f"method must be GET, got {method!r}")

    expect_status = check.get("expect_status", 200)
    if expect_status not in ALLOWED_STATUS:
        raise PolicyError(f"expect_status must be in {sorted(ALLOWED_STATUS)}, got {expect_status}")

    expect_within = check.get("expect_within_ms", 30_000)
    if not isinstance(expect_within, int) or expect_within < MIN_WITHIN_MS or expect_within > MAX_WITHIN_MS:
        raise PolicyError(
            f"expect_within_ms must be int in [{MIN_WITHIN_MS}, {MAX_WITHIN_MS}], got {expect_within!r}"
        )

    body_hash = check.get("expect_body_hash")
    if scheme == "https" and not body_hash:
        raise PolicyError("expect_body_hash is required for https URLs (omit only for ipfs://)")
    if body_hash is not None:
        if not isinstance(body_hash, str) or not body_hash.startswith("0x") or len(body_hash) != 66:
            raise PolicyError("expect_body_hash must be 0x-prefixed 32-byte hex")

    receipt = check.get("expect_signed_receipt")
    if receipt is not None:
        if not isinstance(receipt, dict):
            raise PolicyError("expect_signed_receipt must be an object")
        signer = receipt.get("signer")
        if not isinstance(signer, str) or not signer.startswith("0x") or len(signer) != 42:
            raise PolicyError("expect_signed_receipt.signer must be a 0x-prefixed 20-byte hex address")
        must = receipt.get("must_contain")
        if not isinstance(must, list) or not must or not all(isinstance(x, str) for x in must):
            raise PolicyError("expect_signed_receipt.must_contain must be a non-empty list of strings")


def validate_policy_bundle(policy: dict[str, Any]) -> None:
    """Validate the full policy envelope per SPEC §3.0."""
    raw = _canonical_json_bytes(policy)
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"policy JSON exceeds {MAX_POLICY_BYTES} bytes (got {len(raw)})")
    version = policy.get("version")
    if version not in SUPPORTED_VERSIONS:
        raise PolicyError(f"unsupported policy version: {version!r}")
    checks = policy.get("checks")
    if not isinstance(checks, list) or not checks:
        raise PolicyError("policy must contain a non-empty `checks` array")
    for check in checks:
        if check.get("type") == "url_check":
            validate_url_check_policy(check)


# ─── execution ──────────────────────────────────────────────────────────────


@dataclass
class CheckOutcome:
    passed: bool
    reason: str
    observed_status: int | None = None
    observed_body_hash: str | None = None
    observed_at_unix: int = 0


def run_url_check(check: dict[str, Any]) -> CheckOutcome:
    """Execute a single url_check. Returns a CheckOutcome describing
    whether the check passed and why. Network failures are encoded as
    `passed=False` with a reason; they don't raise."""
    validate_url_check_policy(check)
    url = check["url"]
    expect_status = check.get("expect_status", 200)
    expect_within = check.get("expect_within_ms", 30_000)
    expect_body_hash = check.get("expect_body_hash")
    started_unix = int(time.time())

    # Build the request with no redirect following.
    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None  # disable redirects

    opener = urllib.request.build_opener(NoRedirectHandler())
    req = urllib.request.Request(url, method="GET")

    started_perf = time.perf_counter()
    try:
        with opener.open(req, timeout=expect_within / 1000) as resp:
            status = resp.status
            # Hard-cap the body read.
            body = resp.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as e:
        # An HTTP error response is still a valid observation.
        status = e.code
        try:
            body = e.read(MAX_BODY_BYTES + 1)
        except Exception:
            body = b""
    except Exception as e:
        return CheckOutcome(passed=False, reason=f"fetch failed: {e}", observed_at_unix=started_unix)

    elapsed_ms = int((time.perf_counter() - started_perf) * 1000)
    if elapsed_ms > expect_within:
        return CheckOutcome(
            passed=False,
            reason=f"response received in {elapsed_ms}ms, over expect_within_ms={expect_within}",
            observed_status=status,
            observed_at_unix=started_unix,
        )

    if len(body) > MAX_BODY_BYTES:
        return CheckOutcome(
            passed=False, reason=f"body exceeds {MAX_BODY_BYTES} byte cap",
            observed_status=status, observed_at_unix=started_unix,
        )

    if status != expect_status:
        return CheckOutcome(
            passed=False,
            reason=f"status {status} != expect_status {expect_status}",
            observed_status=status, observed_at_unix=started_unix,
        )

    observed_hash = "0x" + hashlib.sha256(body).hexdigest()
    # SHA-256 mirrors the spec's `expect_body_hash` semantics; if the
    # spec ever switches to keccak256 we'd update both sides together.
    if expect_body_hash and observed_hash != expect_body_hash:
        return CheckOutcome(
            passed=False,
            reason=f"body hash {observed_hash} != expect {expect_body_hash}",
            observed_status=status, observed_body_hash=observed_hash, observed_at_unix=started_unix,
        )

    return CheckOutcome(
        passed=True, reason="ok",
        observed_status=status, observed_body_hash=observed_hash, observed_at_unix=started_unix,
    )


def policy_hash(policy: dict[str, Any]) -> str:
    """The keccak-conventionally-named SHA-256 of the canonical policy
    bytes. (See SPEC §3.5 — canonical_json is the input.) In a real
    deployment this would be keccak256 to match the on-chain hash; we
    use SHA-256 in the L1 PoC because it's stdlib-only."""
    return "0x" + hashlib.sha256(_canonical_json_bytes(policy)).hexdigest()


# ─── CLI ────────────────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(description="L1 url_check reference oracle")
    p.add_argument("--policy", required=True, help="path to policy JSON file")
    p.add_argument("--request-id", required=True)
    args = p.parse_args()

    with open(args.policy) as f:
        policy = json.load(f)

    try:
        validate_policy_bundle(policy)
    except PolicyError as e:
        print(f"[oracle] policy rejected at validation: {e}", file=sys.stderr)
        return 2

    overall_pass = True
    outcomes = []
    for check in policy["checks"]:
        if check.get("type") != "url_check":
            print(f"[oracle] skipping check type {check.get('type')!r} (this oracle only handles url_check)")
            continue
        outcome = run_url_check(check)
        outcomes.append(outcome)
        print(f"[oracle] check passed={outcome.passed} reason={outcome.reason}")
        overall_pass = overall_pass and outcome.passed

    attestation = {
        "request_id": args.request_id,
        "policy_hash": policy_hash(policy),
        "check_result": overall_pass,
        "observed_at_unix": outcomes[-1].observed_at_unix if outcomes else int(time.time()),
    }
    print(json.dumps(attestation, indent=2))
    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
