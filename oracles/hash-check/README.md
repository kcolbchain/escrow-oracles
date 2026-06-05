# `hash_check` reference oracle

Stdlib-only reference oracle for verifying that content fetched through an IPFS gateway matches the SHA-256 multihash embedded in a claimed CID.

## What It Checks

- Decodes CIDv0 base58btc and CIDv1 base32/base58btc CIDs.
- Requires the CID multihash to be `sha2-256` with a 32-byte digest.
- Fetches bytes from a configurable IPFS gateway.
- Computes `sha256(content)` and returns a `PASS` or `FAIL` attestation object.
- Handles invalid CIDs, gateway timeouts, tampered content, and oversized gateway responses without throwing from the main check path.

## Quick Start

```bash
python hash_check.py --cid bafkre...
python hash_check.py --cid bafkre... --gateway-url https://ipfs.io/ipfs/{cid}
```

The JSON output includes:

- `result`: `PASS` or `FAIL`
- `expected_sha256`: digest decoded from the CID
- `observed_sha256`: digest computed from fetched bytes
- `gateway_url`
- `observed_at_unix`
- `bytes_read`

## Tests

```bash
pytest tests/test_hash_check.py -q
```

The tests use mocked gateway fetchers, so they do not require network access or a live IPFS gateway.
