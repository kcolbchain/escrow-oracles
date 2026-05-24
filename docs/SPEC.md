# escrow-oracles — Protocol Specification

**Status:** Draft v0.1
**Maintainers:** [@abhicris](https://github.com/abhicris) · [@Pattermesh](https://github.com/Pattermesh)
**Tracks meta:** [#1](https://github.com/kcolbchain/escrow-oracles/issues/1)

> Open standard for autonomous, anonymized agents that attest delivery conditions for switchboard escrows. K-of-N threshold attestation, lottery-based rewards, chain-agnostic.

---

## 1. Goal

Let two AI agents settle an escrow against a quantitatively-verifiable delivery condition, with no human in the loop and no trust in any single oracle operator.

The protocol must satisfy seven properties (matching the `README` design principles):

1. **Transparent** — release condition is declared in the offer; any party re-checks independently.
2. **Quantitative** — only deterministic check types in v1; no LLM grading.
3. **Operator-agnostic** — any agent with a keypair can attest.
4. **Lossless** — oracles never custody funds.
5. **Anonymized** — no long-term identity in on-chain trace.
6. **Lottery-rewarded** — probabilistic per-epoch payouts.
7. **Health-adaptive** — protocol parameters auto-adjust.

## 2. Roles

| Role | Holds | Does |
|---|---|---|
| **Payer** | Funds, master key | Locks escrow, declares delivery condition (`policy`) in the `PaymentOffer`. |
| **Payee** | Deliverable | Produces the off-chain artifact described by the policy. |
| **Oracle (attester)** | Master key + ephemeral derivation function | Observes the deliverable, runs the policy's check function, signs an attestation with a per-attestation ephemeral key. |
| **EscrowOracleRegistry** | — | On-chain aggregator that accepts threshold-signed attestations and triggers `AgentEscrow.release()`. |

## 3. Delivery condition (policy)

The `PaymentOffer` gains a `policy` field carrying the full JSON object below. The on-chain escrow contract stores only `policyHash = keccak256(canonical_json(policy))`; the JSON itself travels off-chain in the offer and is optionally pinned to IPFS for permanence.

```json
{
  "version": "1",
  "checks": [
    { "type": "url_check",   ... },
    { "type": "hash_check",  ... },
    { "type": "event_check", ... }
  ]
}
```

The on-chain footprint is 32 bytes per payment. The off-chain JSON is bounded at 8 KB (see §3.5).

### 3.0 Idiot-proof guardrails (MUST hold for every policy)

A conformant policy-construction library MUST refuse to serialize a policy violating any of these rules. Oracles MUST refuse to attest against a policy that violates any of these rules even if a payer somehow got it on-chain.

| Rule | Reason |
|---|---|
| `version` MUST equal `"1"` for this revision. | Forward-compat: oracles dispatch on it. |
| `checks` MUST be a non-empty array. | A policy that requires nothing trivially passes — useless. |
| Total serialized JSON MUST be ≤ 8192 bytes. | Bounds the off-chain blob; one IPFS block. |
| Each check's `type` MUST be one of `"url_check"`, `"hash_check"`, `"event_check"`. | v1 enumerates check types explicitly; future revisions add via version bump. |
| Each check MUST satisfy its per-type rules (3.1, 3.2, 3.3). | Catches malformed checks at construction, not at attestation. |

### 3.1 `url_check`

```json
{
  "type": "url_check",
  "url": "ipfs://bafy.../delivery.json",
  "method": "GET",
  "expect_status": 200,
  "expect_body_hash": "0x4a...",
  "expect_within_ms": 30000,
  "expect_signed_receipt": {
    "signer": "0xAbhi...",
    "must_contain": ["request_id", "output_hash"]
  }
}
```

Oracle fetches the URL; passes if all of: status matches `expect_status`, response received within `expect_within_ms` milliseconds, body hash matches `expect_body_hash` (when present), and `expect_signed_receipt` validates (when present).

**Per-type guardrails (MUST):**

| Rule | Reason |
|---|---|
| `url` MUST be `https://` or `ipfs://`. Plain `http://` MUST be rejected. | TLS is non-negotiable for HTTPS; IPFS is content-addressed. |
| `url` host MUST NOT be in the denylist: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`, `*.internal`, `*.local`, any RFC-1918 private range. | Prevents an oracle from "checking" its own machine; ensures the URL is publicly auditable. |
| If `url` scheme is `https://`, `expect_body_hash` MUST be present and non-zero. | Without it the rule is trivially game-able (payee serves any 200). IPFS URIs are exempt because the CID *is* the hash. |
| `expect_status` MUST be in `{200, 201, 202, 204, 206}`. | Sane success codes. 3xx redirects are out of scope (oracles MUST NOT follow redirects). |
| `expect_within_ms` MUST be in `[100, 60000]`. | Bounds oracle compute budget. |
| `method` MUST be `"GET"`. | v1 limits to GET; POST/PUT/DELETE aren't deliverable verification, they're side effects. |
| If `expect_signed_receipt` is present, `signer` MUST be a non-zero hex address, and `must_contain` MUST be a non-empty array of string field names. | Catches malformed receipt specs at construction. |
| Oracle implementations MUST NOT follow HTTP redirects. | Eliminates a class of routing-trick attacks. |

**The `expect_signed_receipt` pattern (for non-deterministic deliverables):**

When the deliverable is not known in advance (e.g., LLM inference output), the payee signs a small receipt `{request_id, output_hash, timestamp}` with a key declared in the policy. The URL check fetches the receipt, verifies the signature against `signer`, and confirms it contains the required `must_contain` fields. The actual deliverable lives wherever; the receipt is what's checked.

### 3.2 `hash_check`

```json
{
  "type": "hash_check",
  "source_url": "ipfs://bafy.../artifact.bin",
  "expect_hash": "0x4a...",
  "hash_algorithm": "keccak256"
}
```

Oracle fetches the bytes at `source_url` and computes `hash_algorithm(bytes)`; passes if the result equals `expect_hash`.

**Per-type guardrails (MUST):**

| Rule | Reason |
|---|---|
| `source_url` MUST be `https://` or `ipfs://`. | Same TLS / content-address rule as `url_check`. |
| `source_url` host MUST NOT be in the denylist (same list as 3.1). | Same rationale. |
| `expect_hash` MUST be a 32-byte hex string (`0x` + 64 hex chars). | Pinning the exact expected hash. |
| `hash_algorithm` MUST be one of `"keccak256"`, `"sha256"`. | v1 limits to these two; SHA-1 / MD5 etc. are out by construction. |
| Oracle MUST limit the response body to ≤ 100 MB. | Bounds memory; deliverables larger than 100 MB SHOULD be chunked and use a Merkle root. |

### 3.3 `event_check`

```json
{
  "type": "event_check",
  "chain_id": 8453,
  "address": "0xContract...",
  "topic0": "0xddf2...",
  "topics": ["0xddf2...", null, "0xpayer..."],
  "block_range": [25000000, 25001000]
}
```

Oracle queries an RPC node on `chain_id` for any log emitted by `address` in `[block_range[0], block_range[1]]` whose topics match `topics` (with `null` meaning wildcard for that topic slot). Passes if at least one matching log is found and the block containing it is finalized.

**Per-type guardrails (MUST):**

| Rule | Reason |
|---|---|
| `chain_id` MUST be a positive integer. | EIP-155 chain id. |
| `address` MUST be a 20-byte hex address. | Standard Solidity address shape. |
| `topic0` MUST be a 32-byte hex string. Other `topics` MAY be 32-byte hex or `null` (wildcard). | Mirror EVM log structure. |
| `block_range` MUST be a 2-element array with `block_range[1] - block_range[0] ≤ 50_000`. | Bounds oracle RPC cost. |
| `block_range[1]` MUST be ≤ (finalized head block at attestation time). | Reorg-safety: oracles MUST NOT attest events from unfinalized blocks. |
| Oracle MUST query at finality, not at inclusion. | Same rationale; finalization windows are chain-specific (Lux: 1 epoch, Ethereum: 64 blocks, Base: 1024 blocks). |

### 3.4 Composition

`checks[]` is an array; ALL checks MUST pass for the attestation to be `check_result: true`. v2 plans `any-of`, `weighted`, and threshold composition; v1 is strict AND.

If any check fails, the oracle MUST set `check_result: false` and the attestation MAY still be submitted. The aggregator counts only matching attestations (true vs. true, or false vs. false) toward the K-of-N threshold.

### 3.5 Storage and transport

| Where | What |
|---|---|
| **On-chain (escrow contract)** | 32 bytes: `policyHash = keccak256(canonical_json(policy))`. Nothing else from the policy lives on-chain. |
| **Off-chain (PaymentOffer)** | The full `policy` JSON ships in the off-chain `PaymentOffer` carried between payer and payee. |
| **Off-chain (optional IPFS pin)** | Payer MAY also pin the canonical bytes to IPFS so the policy outlives the payer's hosting. Pin cost is negligible (~$0.0001/GB-month on Filecoin). |

Oracles fetch the policy via the `PaymentOffer` first, fall back to the IPFS CID (when published in the offer's `policy_cid` sibling field) if the offer's primary endpoint is unreachable.

The **canonical JSON encoding** is per [switchboard's payment-protocol convention](https://github.com/kcolbchain/switchboard/blob/main/docs/agent-payment-protocol.md): `json.dumps(d, sort_keys=True, separators=(",", ":"))`. Same encoding everywhere keeps `keccak256` deterministic across implementations.

### 3.6 Validation requirements

| Stage | Who | What MUST happen |
|---|---|---|
| Construction (payer-side) | Policy library | Reject any policy violating §3.0 or any per-type guardrail. Compute `policyHash` and pass it to `AgentEscrow.createPaymentWithPolicy`. |
| Receipt (oracle-side) | Oracle | Re-verify `keccak256(canonical_json(received_policy)) == on_chain_policyHash`. Re-validate every guardrail. Refuse to attest if any check fails to validate. |
| Settlement (contract-side) | `AgentEscrow` + `IOracleAggregator` | The contract trusts `policyHash` as opaque. The aggregator MAY check the policy structure if it has the JSON; v1 aggregators are not required to. |

## 4. Attestation format

The bytes an oracle signs:

```
domain    = "escrow-oracles/v1\0"
type_tag  = 0x01   // attestation
canon     = canonical_json({
  request_id, policy_hash, check_result: bool,
  observed_at_unix, oracle_pubkey_ephemeral,
  chain_id, registry_address
})
transcript = domain || type_tag || canon
digest     = SHAKE-256(transcript, 64)
signature  = ml_dsa_65.sign(sk_ephemeral, digest)
```

`canonical_json` follows the same rule as switchboard's payment protocol (`sort_keys=True`, tight separators).

The on-chain submission to `EscrowOracleRegistry.attest()`:

```solidity
struct Attestation {
    bytes32 requestId;
    bytes32 policyHash;
    bool    checkResult;
    uint64  observedAt;
    bytes   oraclePubkey;      // ephemeral
    bytes   signature;         // ml-dsa-65
}

function attest(Attestation[] calldata atts) external;
```

The registry verifies each `signature` against its `oraclePubkey`, counts unique pubkeys, and if `>= K` of `N` published attestations have `checkResult == true`, calls `AgentEscrow.release(requestId)`.

## 5. K-of-N threshold

Default: **K=2, N=3** for v1. The N is *anyone* (permissionless); K is the minimum count needed for release.

Threshold logic is **synchronous**: K signatures must arrive within the `attestation_window` declared in the offer (default 5 minutes). After the window, attestations are rejected.

No equivocation tolerance: if an oracle (identified by ephemeral pubkey, which they don't repeat) submits two different attestations for the same `requestId`, both are rejected.

## 6. Anonymization & rewards

### 6.1 Per-attestation ephemeral keys

Each oracle holds a master keypair `(M, M_pub)`. For each attestation:

```
ephemeral_priv = HKDF(M_priv, request_id || epoch_id)
ephemeral_pub  = derive_pub(ephemeral_priv)
```

The attestation is signed with `ephemeral_priv` and includes `ephemeral_pub`. The on-chain trace contains *only* the ephemeral pubkey — there's no link to the master key without knowing it.

### 6.2 Reward pool

Each escrow release siphons **0.5%** of the escrow value into the `EscrowOracleRegistry.rewardPool`. Default; configurable per-deployment within bounds.

### 6.3 Per-epoch lottery

Epoch = 1 day (288 blocks on Lux's 5-min blocks; ~7,200 blocks on Base).

At epoch close:
```
seed       = blockhash(epoch_close_block) XOR vrf_output
eligible   = all attestations included in successful K-of-N releases this epoch
            where checkResult matched consensus
L          = 10 winners per epoch (default)
winners    = pseudo-random subset of `eligible` selected via `seed`
payout     = rewardPool / L per winner
```

Each winner's payout goes to a **stealth address**:

```
stealth_addr_i = derive_stealth(M_pub_winner_i, epoch_id)
```

The master-key holder can spend from `stealth_addr_i` without revealing they were the winner. Sweeping is up to the operator.

### 6.4 Why the lottery

- **Adversary can't game which attestation pays.** With deterministic per-attestation rewards, an adversary buys/bribes specifically the most lucrative ones. With a lottery, all correct attestations have equal expected value; adversary must corrupt the *whole pool*, not specific ones.
- **Anonymized.** Stealth addresses break the link between attestation submission and reward claim. On-chain observer sees attestations and stealth-address withdrawals; can't link them.
- **Cheap.** No per-attestation reward transfer; one batch transfer per epoch.

## 7. Health-adaptive parameters

### 7.1 Participation floor

If the number of unique attesters per epoch drops below `participation_floor` (default 5), the `rewardPool` siphon rate *increases* (up to 2%) for the next epoch. Higher rewards → more participation.

### 7.2 False-release detection

If multiple attestations disagree on the same `requestId` within the window (i.e., K want release but L want refund), the protocol *increases K* by 1 for the next epoch (up to `N`). Higher K → harder for an adversary to corrupt.

### 7.3 Returning to baseline

Both adjustments revert toward the configured baseline by 1 step per epoch if conditions normalize. Hysteresis prevents oscillation.

## 8. Settlement integration

`AgentEscrow.sol` gets two additions:

```solidity
// New: oracle-mediated release
function releaseByAttestation(string calldata requestId) external {
    require(msg.sender == address(escrowOracleRegistry), "only registry");
    Payment storage p = payments[requestId];
    require(p.state == State.Locked, "not locked");
    p.state = State.Released;
    (bool ok, ) = p.payee.call{value: p.amount}("");
    require(ok, "transfer failed");
    emit PaymentReleased(requestId, p.payee, p.amount);
}

// New: pre-declared policy hash (committed in createPayment)
function setPolicyHash(string calldata requestId, bytes32 policyHash) external;
```

The policy bytes themselves live off-chain (the offer contains them); only the hash binds on-chain.

## 9. Chain-local adapter pattern

v1 ships:
- **Lux** — primary deployment
- **Base** — EVM-compatible reference

Multi-chain (same attestation, multiple chains) is v2. The adapter interface:

```python
class ChainAdapter(Protocol):
    def submit_attestation(self, att: Attestation) -> tx_hash: ...
    def watch_releases(self) -> AsyncIterator[ReleaseEvent]: ...
    def claim_reward(self, stealth_addr: bytes) -> tx_hash: ...
```

Per-chain adapters live in `oracles/adapters/`. v2 cross-chain consensus is a separate spec.

## 10. Multi-level contribution

Reproduced from README for self-containment:

| Level | Time | Builds |
|---|---|---|
| **L0** | 15 min | hello-world oracle (single file) |
| **L1** | 1 hr | spec-conformant check-type implementation |
| **L2** | 1 day | multi-chain oracle node |
| **L3** | 1 week | threshold signature aggregation (FROST) |
| **L4** | 1 month | cryptoeconomic security (slashing, optimistic mode) |
| **L5** | ongoing | protocol-tuning + adversarial game |

Each level has at least one open `help wanted` issue.

## 11. Open questions

1. **Stealth address scheme.** Borrow from EIP-5564 (secp256k1 stealth) or define our own over ml-dsa-65? Likely the former for chain-friendliness.
2. **VRF source.** Use the chain's native randomness, draw from drand, or hash-prevrandao? Tradeoff: pre-disclosure vs cost.
3. **Lottery winner count `L`.** 10 per epoch tends to give thin payouts for small networks. Scale `L = max(5, eligible / 20)`?
4. **Slashing in v2.** Bond per-oracle vs bond per-master-key vs no bond + reputation only?
5. **Optimistic mode vs synchronous.** Synchronous v1; if latency / cost forces it, add optimistic challenge mode in v2.
6. **PQ vs ECDSA for the ephemeral key.** v1 picks `ml-dsa-65` for forward compat. Argued vs ECDSA's smaller sig (which is cheaper to verify on-chain). Probably worth a hybrid mode like switchboard's PQ envelope.

## 12. Non-goals (explicit)

- **Subjective grading.** "Was the work good?" is not v1. v1 is "did the deliverable match the committed hash / URL response / on-chain event?" Quality assessment is an application-level concern outside the protocol.
- **Bridges.** Cross-chain release (attestation on chain A triggers release on chain B) is v2.
- **Full BFT consensus.** Synchronous K-of-N threshold is enough for v1 economic security; full Tendermint/HotStuff is overkill.
- **Identity / reputation.** Oracles are anonymous by design. v2 may add an opt-in reputation layer; v1 is purely operator-agnostic.

---

**This document is the source of truth for the v1 protocol.** Implementations MUST conform. Open a PR to amend.
