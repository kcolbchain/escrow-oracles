# `url_check` reference oracle (L1)

Spec-conformant Python implementation of the `url_check` policy type from
[`docs/SPEC.md`](../../docs/SPEC.md) §3.1 and §4 — fetches a URL, validates
the response against the declared expectations, builds the canonical
attestation transcript, signs it with **ml-dsa-65** via
[`switchboard.pq`](https://github.com/kcolbchain/switchboard/blob/main/switchboard/pq.py),
and emits the signed bundle that the chain-side aggregator submits to
`EscrowOracleRegistry.attest()`.

This is the **L1 reference**. Other-language ports (L0) and chain
adapters (L2) pin their behavior against this implementation's output.

---

## Install

```bash
pip install 'switchboard-agents[pq]'
```

The `[pq]` extra pulls [`liboqs-python`](https://github.com/open-quantum-safe/liboqs-python),
which builds the `liboqs` C library on first install. Without it, the
oracle still parses policies and runs fetches — but `attest` will refuse
to sign and exit with code `3`.

No other runtime dependencies — only Python ≥ 3.11 stdlib.

---

## Quick start

```bash
# 1. generate an ephemeral oracle keypair (one-time, persistent)
python url_check.py generate-key --out oracle.key.json

# 2. write a policy file (see SPEC §3.1 for the schema)
cat > policy.json <<'EOF'
{
  "version": "1",
  "checks": [
    {
      "type": "url_check",
      "url": "https://api.example.com/delivery/req-7f3e",
      "method": "GET",
      "expect_status": 200,
      "expect_body_hash": "0xabababababababababababababababababababababababababababababababab",
      "expect_within_ms": 5000
    }
  ]
}
EOF

# 3. run the check, sign the attestation, emit the bundle to stdout
python url_check.py attest \
  --policy-file  policy.json \
  --request-id   req-7f3e \
  --pq-key-file  oracle.key.json \
  --chain-id     8453 \
  --registry-address 0xYourEscrowOracleRegistry... \
  > attestation.json

# 4. round-trip verify (no chain needed)
python url_check.py verify --bundle attestation.json
```

The emitted `attestation.json` looks like:

```jsonc
{
  "attestation": {
    "chain_id": 8453,
    "check_result": true,
    "observed_at_unix": 1716816000,
    "oracle_pubkey_ephemeral": "0x<hex pk>",
    "policy_hash": "0x<sha256 of canonical policy>",
    "registry_address": "0x...",
    "request_id": "req-7f3e"
  },
  "signature_alg": "ml-dsa-65",
  "signature":     "0x<ml-dsa-65 sig bytes>",
  "transcript_hex": "0x<the bytes that were SHAKE-256'd>",
  "digest_hex":     "0x<64-byte SHAKE-256 digest>"
}
```

`transcript_hex` and `digest_hex` are diagnostic — they let any other-language
implementation recompute the digest and verify the signature without trusting
this oracle's serializer.

---

## CLI reference

```
url_check generate-key --out PATH [--alg ALG]
url_check attest       --policy-file P --request-id R
                       [--pq-key-file K] [--alg ALG]
                       [--chain-id N] [--registry-address ADDR]
url_check verify       --bundle B
```

Defaults:

- `--alg` is `ml-dsa-65` (FIPS 204 level 3). Supported: `ml-dsa-44/65/87`,
  `slh-dsa-128s/128f`. Use `ml-dsa-65` unless you have a specific reason.
- `--chain-id` defaults to `0`, `--registry-address` to the zero address.
  Both fields are signed — set them to the real values for any attestation
  you intend to submit on-chain.
- Without `--pq-key-file`, the oracle generates an ephemeral key for the
  attest invocation. Useful for one-shot checks; not what you want in
  production (the public key is the only way to verify, and an ephemeral
  one disappears after the process exits).

Exit codes:

| code | meaning                                  |
|------|------------------------------------------|
| `0`  | all checks passed and attestation signed |
| `1`  | check failed (signed attestation still emitted, `check_result: false`) |
| `2`  | policy rejected at validation            |
| `3`  | liboqs / `switchboard.pq` unavailable     |

---

## What this oracle enforces (SPEC §3.0 + §3.1)

Every constraint is rejected at policy-parse time — an oracle MUST refuse
to attest against a malformed policy even if it somehow got on-chain.

| Rule | Enforced |
|------|----------|
| `version == "1"` | ✅ |
| `checks` is a non-empty array | ✅ |
| Total policy JSON ≤ 8 KB | ✅ |
| URL scheme is `https://` or `ipfs://` (no plain `http://`) | ✅ |
| URL host is not `localhost` / RFC-1918 private / `*.internal` / `*.local` | ✅ |
| HTTPS URLs MUST set `expect_body_hash` (IPFS is exempt — the CID is the hash) | ✅ |
| `expect_status` in `{200, 201, 202, 204, 206}` | ✅ |
| `expect_within_ms` in `[100, 60_000]` | ✅ |
| `method == "GET"` | ✅ |
| Oracle MUST NOT follow HTTP redirects | ✅ |
| Response body ≤ 100 MB | ✅ |

---

## Attestation transcript (SPEC §4)

The bytes that go through SHAKE-256:

```
DOMAIN_SEPARATOR  = b"escrow-oracles/v1\x00"       # 18 bytes
TYPE_ATTESTATION  = b"\x01"
canon             = canonical_json({                # sort_keys, tight separators
    request_id, policy_hash, check_result,
    observed_at_unix, oracle_pubkey_ephemeral,
    chain_id, registry_address,
})
transcript        = DOMAIN_SEPARATOR || TYPE_ATTESTATION || canon
digest            = SHAKE-256(transcript, 64)
signature         = ml_dsa_65.sign(sk_ephemeral, digest)
```

`canonical_json` follows the same rule as switchboard's payment protocol —
`sort_keys=True`, tight separators (`","` `":"`), UTF-8.

`TestAttestationCanon` in [`test_url_check.py`](./test_url_check.py) pins
this byte-for-byte against a golden vector. Any future protocol change
that touches the field set, ordering, or prefix bytes MUST update that
test in lockstep — and bump SPEC's protocol version.

---

## Tests

```bash
pip install pytest
cd oracles/url-check
pytest -v
```

What's covered:

| Class | Asserts |
|-------|---------|
| `TestPolicyGuardrails`         | every SPEC §3.0 MUST clause has positive + negative |
| `TestUrlSchemeGuardrails`      | `https://` accepted, `ipfs://` accepted, `http://` / `ftp://` / denylist hosts rejected |
| `TestRequiredFields`           | `expect_body_hash` required for HTTPS; status / method / within bounds enforced |
| `TestSignedReceiptValidation`  | `expect_signed_receipt` shape rules |
| `TestExecution`                | happy / status-mismatch / body-hash-mismatch / timeout against a local HTTP server |
| `TestPolicyHash`               | deterministic + canonical-JSON-equivalence |
| `TestAttestationCanon`         | **conformance**: transcript bytes match SPEC §4 byte-for-byte |
| `TestBuildAttestation`         | attestation field set matches SPEC §4 exactly |
| `TestSignVerifyRoundtrip`      | end-to-end ml-dsa-65 sign → verify works |
| `TestTamper`                   | signature byte-flip, signature truncation, signed-field mutation, wrong pubkey — **every tamper path returns False** |
| `TestCLI`                      | `attest` / `generate-key` / `verify` subcommands accept the DoD flag set |

PQ-dependent tests `pytest.skip` when `liboqs` isn't installed, so the
suite stays green in environments without it. The conformance tests
(`TestAttestationCanon`, `TestBuildAttestation`) always run — they don't
need liboqs, only `hashlib`.

---

## Layering note

- **L0** — reference stub in [`examples/hello-oracle.py`](../../examples/hello-oracle.py).
  Educational; does not enforce guardrails, does not PQ-sign.
- **L1** — this directory. Spec-conformant, real PQ signing, full test
  matrix. Other-language ports pin against the conformance vectors here.
- **L2** — chain adapters (forthcoming). Take an L1 bundle, submit it
  to `EscrowOracleRegistry.attest()` on the target chain.

---

## Production guidance

This is a **reference implementation**. For a real oracle deployment:

- Replace the flat `oracle.key.json` keystore with an HSM / KMS / encrypted
  vault. The L1 keystore exists so the conformance harness has something
  reproducible to test against, not as a production posture.
- Run on hardware that can keep the ephemeral key off disk entirely —
  generate, sign, exit.
- Submit the bundle to the L2 chain adapter; never trust your own oracle's
  output through any other path.
- Rotate the signing key on every attestation. The `oracle_pubkey_ephemeral`
  field is in the transcript precisely to allow this — each attestation
  carries its own public key.

Closes [#3](https://github.com/kcolbchain/escrow-oracles/issues/3).
