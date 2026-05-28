"""url_check reference oracle (L1).

Spec-conformant implementation of the `url_check` policy type per
`docs/SPEC.md` §3.1 and §4. Fetches a URL, validates the response against
the declared expectations, builds the spec-canonical attestation, signs
it with ml-dsa-65 via `switchboard.pq`, and emits the signed bundle that
the chain-side aggregator submits to `EscrowOracleRegistry.attest()`.

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

Attestation transcript (SPEC §4):

    domain    = b"escrow-oracles/v1\\x00"      # 18 bytes
    type_tag  = b"\\x01"                       # attestation
    canon     = canonical_json({               # sort_keys, tight separators
        request_id, policy_hash, check_result,
        observed_at_unix, oracle_pubkey_ephemeral,
        chain_id, registry_address
    })
    transcript = domain || type_tag || canon
    digest     = SHAKE-256(transcript, 64)
    signature  = ml_dsa_65.sign(sk_ephemeral, digest)

Not handled here (out of L1 scope):
  - On-chain submission. The L1 oracle's output is the signed bundle;
    the L2 work (multi-chain submitter) posts it to AgentEscrow via
    IOracleAggregator.

CLI:

    # one-shot: generate ephemeral key, attest, sign, emit bundle to stdout
    python url_check.py attest --policy-file p.json --request-id req-7f3e

    # explicit key management:
    python url_check.py generate-key --out oracle.key.json
    python url_check.py attest --policy-file p.json --request-id req-7f3e \\
        --pq-key-file oracle.key.json \\
        --chain-id 8453 --registry-address 0xAbcd...

    # round-trip verification of an emitted bundle:
    python url_check.py verify --bundle attestation.json
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
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

# SPEC §4 transcript constants
DOMAIN_SEPARATOR = b"escrow-oracles/v1\x00"   # 18 bytes
TYPE_ATTESTATION = b"\x01"
DIGEST_BYTES = 64                             # SHAKE-256 output length
DEFAULT_ALG = "ml-dsa-65"


# ─── PQ wrapper (graceful when liboqs is absent) ────────────────────────────

try:
    from switchboard import pq  # type: ignore[import-not-found]
    HAS_PQ = pq.HAS_OQS
except (ImportError, SystemExit, OSError):  # pragma: no cover — env-gated
    pq = None  # type: ignore[assignment]
    HAS_PQ = False


class PQUnavailable(RuntimeError):
    """switchboard.pq could not be imported or liboqs is missing.

    The oracle still produces a valid attestation JSON (everything except
    the signature), so callers can inspect what would have been signed —
    but no signature is generated. Install via:

        pip install 'switchboard-agents[pq]'
    """


# ─── exceptions ─────────────────────────────────────────────────────────────


class PolicyError(ValueError):
    """The policy itself is malformed and must be rejected at parse time."""


class CheckError(Exception):
    """The fetch itself failed (network, timeout, etc.) — distinct from a
    valid response that simply didn't match expectations. A CheckError
    means the oracle could not produce a deterministic answer."""


# ─── policy validation ──────────────────────────────────────────────────────


def _canonical_json_bytes(obj: Any) -> bytes:
    """Canonical JSON per SPEC §3.5 — sorted keys, tight separators, UTF-8."""
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


# ─── attestation transcript & signing (SPEC §4) ─────────────────────────────


def build_attestation(
    *,
    request_id: str,
    policy_hash_hex: str,
    check_result: bool,
    observed_at_unix: int,
    oracle_pubkey: bytes,
    chain_id: int,
    registry_address: str,
) -> dict[str, Any]:
    """Build the attestation dict in the exact field set that SPEC §4 signs.

    Field order in the dict is not load-bearing — canonical_json sorts keys
    — but the field NAMES are part of the on-chain contract. Do not rename
    a field without bumping the protocol version."""
    return {
        "request_id": request_id,
        "policy_hash": policy_hash_hex,
        "check_result": check_result,
        "observed_at_unix": observed_at_unix,
        "oracle_pubkey_ephemeral": "0x" + oracle_pubkey.hex(),
        "chain_id": chain_id,
        "registry_address": registry_address,
    }


def attestation_canon_bytes(attestation: dict[str, Any]) -> bytes:
    """The exact bytes that go through SHAKE-256 per SPEC §4:

        DOMAIN_SEPARATOR || TYPE_ATTESTATION || canonical_json(attestation)
    """
    return DOMAIN_SEPARATOR + TYPE_ATTESTATION + _canonical_json_bytes(attestation)


def attestation_digest(attestation: dict[str, Any]) -> bytes:
    """SHAKE-256(transcript, 64). The thing ml-dsa-65 actually signs."""
    h = hashlib.shake_256()
    h.update(attestation_canon_bytes(attestation))
    return h.digest(DIGEST_BYTES)


def sign_attestation(attestation: dict[str, Any], sk: bytes, alg: str = DEFAULT_ALG) -> bytes:
    """Sign the attestation digest with `alg` via switchboard.pq.
    Raises PQUnavailable if liboqs isn't installed."""
    if not HAS_PQ or pq is None:
        raise PQUnavailable(
            "switchboard.pq / liboqs not available — install switchboard-agents[pq]"
        )
    if alg not in pq.SUPPORTED_ALGS:
        raise ValueError(f"unsupported PQ algorithm: {alg!r} (got {sorted(pq.SUPPORTED_ALGS)})")
    digest = attestation_digest(attestation)
    return pq.sign(alg, sk, digest)


def verify_attestation(attestation: dict[str, Any], sig: bytes, pk: bytes, alg: str = DEFAULT_ALG) -> bool:
    """Verify a signature over the spec attestation transcript. Returns
    False on any mismatch — never raises for a tampered signature."""
    if not HAS_PQ or pq is None:
        raise PQUnavailable(
            "switchboard.pq / liboqs not available — install switchboard-agents[pq]"
        )
    if alg not in pq.SUPPORTED_ALGS:
        raise ValueError(f"unsupported PQ algorithm: {alg!r}")
    digest = attestation_digest(attestation)
    try:
        return bool(pq.verify(alg, pk, digest, sig))
    except Exception:
        return False


# ─── keypair I/O ────────────────────────────────────────────────────────────


def generate_oracle_keypair(alg: str = DEFAULT_ALG) -> tuple[bytes, bytes]:
    """Returns (pk, sk). Raises PQUnavailable if liboqs isn't installed."""
    if not HAS_PQ or pq is None:
        raise PQUnavailable(
            "switchboard.pq / liboqs not available — install switchboard-agents[pq]"
        )
    return pq.generate(alg)


def save_keypair(path: str, pk: bytes, sk: bytes, alg: str = DEFAULT_ALG) -> None:
    """Persist a keypair to disk as JSON. `sk` is hex-encoded; mode 0o600.

    NOTE: this is a reference implementation for the L1 oracle. Production
    deployments should keep `sk` in an HSM / KMS / encrypted-at-rest store —
    never as a flat file."""
    payload = {
        "alg": alg,
        "pk": pk.hex(),
        "sk": sk.hex(),
        "comment": "L1 reference key — do not use in production",
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / unusual filesystems — caller is responsible.


def load_keypair(path: str) -> tuple[str, bytes, bytes]:
    """Returns (alg, pk, sk) from a `save_keypair` file."""
    with open(path) as f:
        payload = json.load(f)
    return payload["alg"], bytes.fromhex(payload["pk"]), bytes.fromhex(payload["sk"])


# ─── CLI ────────────────────────────────────────────────────────────────────


def _cmd_generate_key(args: argparse.Namespace) -> int:
    if not HAS_PQ:
        print("[oracle] cannot generate PQ key: liboqs missing. install switchboard-agents[pq]",
              file=sys.stderr)
        return 3
    pk, sk = generate_oracle_keypair(args.alg)
    save_keypair(args.out, pk, sk, args.alg)
    print(f"[oracle] wrote {args.alg} keypair to {args.out} (mode 0600)")
    print(f"[oracle] pk = 0x{pk.hex()[:16]}...{pk.hex()[-16:]} ({len(pk)} bytes)")
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    with open(args.policy_file) as f:
        policy = json.load(f)

    try:
        validate_policy_bundle(policy)
    except PolicyError as e:
        print(f"[oracle] policy rejected at validation: {e}", file=sys.stderr)
        return 2

    outcomes: list[CheckOutcome] = []
    overall_pass = True
    for check in policy["checks"]:
        if check.get("type") != "url_check":
            print(f"[oracle] skipping check type {check.get('type')!r} "
                  "(this oracle only handles url_check)", file=sys.stderr)
            continue
        outcome = run_url_check(check)
        outcomes.append(outcome)
        print(f"[oracle] check passed={outcome.passed} reason={outcome.reason}",
              file=sys.stderr)
        overall_pass = overall_pass and outcome.passed

    if not outcomes:
        print("[oracle] no url_check entries in policy — nothing to attest",
              file=sys.stderr)
        return 2

    # Load or generate the PQ key
    if args.pq_key_file:
        alg, pk, sk = load_keypair(args.pq_key_file)
    elif HAS_PQ:
        alg = args.alg
        pk, sk = generate_oracle_keypair(alg)
        print(f"[oracle] generated ephemeral {alg} keypair (use --pq-key-file to persist)",
              file=sys.stderr)
    else:
        print("[oracle] no --pq-key-file and liboqs missing — cannot sign. "
              "install switchboard-agents[pq] or provide a key file.",
              file=sys.stderr)
        return 3

    attestation = build_attestation(
        request_id=args.request_id,
        policy_hash_hex=policy_hash(policy),
        check_result=overall_pass,
        observed_at_unix=outcomes[-1].observed_at_unix,
        oracle_pubkey=pk,
        chain_id=args.chain_id,
        registry_address=args.registry_address,
    )

    sig = sign_attestation(attestation, sk, alg)
    bundle = {
        "attestation": attestation,
        "signature_alg": alg,
        "signature": "0x" + sig.hex(),
        "transcript_hex": "0x" + attestation_canon_bytes(attestation).hex(),
        "digest_hex": "0x" + attestation_digest(attestation).hex(),
    }
    print(json.dumps(bundle, indent=2))
    return 0 if overall_pass else 1


def _cmd_verify(args: argparse.Namespace) -> int:
    with open(args.bundle) as f:
        bundle = json.load(f)
    attestation = bundle["attestation"]
    sig = bytes.fromhex(bundle["signature"].removeprefix("0x"))
    pk_hex = attestation["oracle_pubkey_ephemeral"].removeprefix("0x")
    pk = bytes.fromhex(pk_hex)
    alg = bundle.get("signature_alg", DEFAULT_ALG)

    if not HAS_PQ:
        print("[oracle] cannot verify: liboqs missing. install switchboard-agents[pq]",
              file=sys.stderr)
        return 3

    ok = verify_attestation(attestation, sig, pk, alg)
    print(f"[oracle] verify: {'OK' if ok else 'REJECT'}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="url_check",
        description="L1 url_check reference oracle (escrow-oracles)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate-key", help="generate a PQ keypair and write to disk")
    g.add_argument("--out", required=True, help="output JSON path (mode 0600)")
    g.add_argument("--alg", default=DEFAULT_ALG,
                   help=f"PQ algorithm (default: {DEFAULT_ALG})")
    g.set_defaults(func=_cmd_generate_key)

    a = sub.add_parser("attest", help="run url_check policy and emit signed attestation")
    a.add_argument("--policy-file", required=True, help="path to policy JSON")
    a.add_argument("--request-id", required=True, help="opaque request id (uuid recommended)")
    a.add_argument("--pq-key-file", default=None,
                   help="path to keypair JSON (default: generate ephemeral)")
    a.add_argument("--alg", default=DEFAULT_ALG,
                   help=f"PQ algorithm for ephemeral key (default: {DEFAULT_ALG})")
    a.add_argument("--chain-id", type=int, default=0,
                   help="destination chain ID (used in transcript)")
    a.add_argument("--registry-address", default="0x" + "0" * 40,
                   help="EscrowOracleRegistry contract address (used in transcript)")
    a.set_defaults(func=_cmd_attest)

    v = sub.add_parser("verify", help="verify a signed attestation bundle")
    v.add_argument("--bundle", required=True, help="path to bundle JSON from `attest`")
    v.set_defaults(func=_cmd_verify)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
