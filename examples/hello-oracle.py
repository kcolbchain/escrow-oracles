"""L0 — hello-world escrow oracle.

Smallest possible spec-conformant oracle. Demonstrates:
  - reading a PaymentOffer's policy (url_check)
  - running the deterministic check
  - constructing the canonical attestation transcript
  - signing with an ephemeral key derived from a master key

This file does NOT submit on-chain. The PoC stops at "here is the
signed attestation bytes" — chain adapters are L2 work (see issue #4).

Run:
    python examples/hello-oracle.py \\
      --request-id req-7f3e \\
      --policy-url https://httpbin.org/status/200

Expected output:
    [oracle] check passed: true
    [oracle] ephemeral pubkey: 0x...
    [oracle] attestation bytes: 0x...

About 80 lines of non-comment code. The point is to make the L0 ladder
rung accessible — anyone reading the spec should be able to ship
something equivalent in <15 min.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.request
from typing import Any


DOMAIN = b"escrow-oracles/v1\0"
TYPE_TAG_ATTESTATION = bytes([0x01])
EPOCH_SECONDS = 86_400


def _master_key() -> bytes:
    """Master key — in production read from a KMS / hardware wallet.
    For this PoC we use an env var or generate a fresh one."""
    raw = os.environ.get("ORACLE_MASTER_KEY_HEX")
    if raw:
        return bytes.fromhex(raw)
    print("[oracle] no ORACLE_MASTER_KEY_HEX; generating ephemeral master")
    return secrets.token_bytes(32)


def _derive_ephemeral(master: bytes, request_id: str, epoch_id: int) -> bytes:
    """Per-attestation key derivation. The spec uses HKDF; this PoC
    uses SHAKE-256 over the same inputs for simplicity."""
    h = hashlib.shake_256()
    h.update(master)
    h.update(b"|")
    h.update(request_id.encode())
    h.update(b"|")
    h.update(epoch_id.to_bytes(8, "big"))
    return h.digest(32)


def _ephemeral_pubkey(ephemeral_priv: bytes) -> bytes:
    """In v1 spec this is ml-dsa-65. PoC stub: sha256(priv) as a
    placeholder so the example runs without liboqs installed.

    Replace with switchboard.pq.generate(...) when wiring to the real
    PQ stack.
    """
    return hashlib.sha256(ephemeral_priv + b"pub").digest()


def _sign(ephemeral_priv: bytes, digest: bytes) -> bytes:
    """PoC stub. v1 spec: ml-dsa-65. Real impl uses switchboard.pq.sign."""
    h = hashlib.shake_256()
    h.update(b"sig\0")
    h.update(ephemeral_priv)
    h.update(digest)
    return h.digest(64)


def run_url_check(policy: dict[str, Any]) -> bool:
    """Deterministic url_check per SPEC.md §3.1."""
    req = urllib.request.Request(policy["url"], method=policy.get("method", "GET"))
    deadline_ms = policy.get("max_latency_ms", 30_000)
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=deadline_ms / 1000) as resp:
            status = resp.status
            body = resp.read()
    except Exception as exc:
        print(f"[oracle] fetch failed: {exc}")
        return False
    elapsed_ms = int((time.time() - started) * 1000)
    if elapsed_ms > deadline_ms:
        print(f"[oracle] over latency budget ({elapsed_ms}ms > {deadline_ms}ms)")
        return False
    if status != policy.get("expect_status", 200):
        print(f"[oracle] status mismatch ({status} != {policy.get('expect_status', 200)})")
        return False
    expect_hash = policy.get("expect_body_hash")
    if expect_hash:
        body_hash = "0x" + hashlib.sha256(body).hexdigest()
        if body_hash != expect_hash:
            print(f"[oracle] body hash mismatch")
            return False
    return True


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def attest(request_id: str, policy: dict, master: bytes, registry_address: str, chain_id: int) -> dict:
    """Build a v1-conformant attestation per SPEC.md §4."""
    epoch_id = int(time.time()) // EPOCH_SECONDS
    ephemeral_priv = _derive_ephemeral(master, request_id, epoch_id)
    ephemeral_pub = _ephemeral_pubkey(ephemeral_priv)

    check_result = run_url_check(policy["checks"][0])
    policy_hash = "0x" + hashlib.sha256(canonical_json(policy)).hexdigest()

    canon_dict = {
        "request_id": request_id,
        "policy_hash": policy_hash,
        "check_result": check_result,
        "observed_at_unix": int(time.time()),
        "oracle_pubkey_ephemeral": "0x" + ephemeral_pub.hex(),
        "chain_id": chain_id,
        "registry_address": registry_address,
    }
    canon = canonical_json(canon_dict)

    transcript = DOMAIN + TYPE_TAG_ATTESTATION + canon
    digest = hashlib.shake_256(transcript).digest(64)
    signature = _sign(ephemeral_priv, digest)

    return {
        "request_id": request_id,
        "policy_hash": policy_hash,
        "check_result": check_result,
        "observed_at": canon_dict["observed_at_unix"],
        "oracle_pubkey": "0x" + ephemeral_pub.hex(),
        "signature": "0x" + signature.hex(),
    }


def main() -> int:
    p = argparse.ArgumentParser(description="L0 hello-world escrow oracle")
    p.add_argument("--request-id", required=True)
    p.add_argument("--policy-url", required=True, help="URL to fetch as the deliverable check")
    p.add_argument("--registry", default="0x" + "0" * 40)
    p.add_argument("--chain-id", type=int, default=8453)
    args = p.parse_args()

    policy = {
        "checks": [{
            "type": "url_check",
            "url": args.policy_url,
            "method": "GET",
            "expect_status": 200,
            "max_latency_ms": 30_000,
        }]
    }

    master = _master_key()
    att = attest(args.request_id, policy, master,
                 registry_address=args.registry, chain_id=args.chain_id)

    print(f"[oracle] check passed: {att['check_result']}")
    print(f"[oracle] ephemeral pubkey: {att['oracle_pubkey']}")
    print(f"[oracle] attestation: {json.dumps(att, indent=2)}")
    return 0 if att["check_result"] else 1


if __name__ == "__main__":
    sys.exit(main())
