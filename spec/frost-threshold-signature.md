# FROST Threshold Signature Aggregation

> Specification for integrating the FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme into escrow-oracles v1.

**Status:** Draft v0.1  
**Depends on:** L1 (at least one check type producing attestations)  
**Replaces:** Naive K-independent signature submission pattern  

## 1. Overview

In the base protocol (SPEC §5), K oracles each submit an independent ml-dsa-65 signature on-chain. At K=2 this costs ~6.6 KB of calldata; at K=5 it exceeds 16 KB. **FROST** compresses these K signatures into a **single threshold signature** verifiable against one aggregated public key — calldata drops from O(K × sig) to O(1).

### 1.1 Why FROST over alternatives

| Scheme | Sig size | Pairing-free | Active security | Suitability |
|--------|----------|-------------|-----------------|-------------|
| **FROST** | 64 B (Schnorr) | ✅ | ✅ | Excellent — small sigs, well-studied, implemented |
| BLS | 48 B (BLS12-381) | ❌ | ✅ | Slightly cheaper sig, but pairing ops burden on-chain |
| CGGMP21 | ~120 B | ✅ | ✅ | 2-round, but designed for ECDSA, heavier than needed |
| MuSig2 | 64 B | ✅ | ✅ | Simpler than FROST but requires 3-round signing |

**Decision:** FROST (Schnorr-based, K-of-N non-interactive signing after one preprocessing round).

### 1.2 Protocol flow

```
┌─────────────────────────────────────────────────────────┐
│  Phase 1: Distributed Key Generation (DKG)             │
│  - N oracles run FROST DKG to produce:                 │
│    - Group public key PK (stored on-chain)               │
│    - Each oracle i gets secret share sk_i               │
│  - Output: group_pk, individual shares, verification    │
│    vectors for each participant                         │
├─────────────────────────────────────────────────────────┤
│  Phase 2: Signing (per attestation)                    │
│  - K oracles are selected for round                     │
│  - Each oracle produces a partial signature σ_i         │
│  - Coordinator collects K partial sigs                  │
│  - Coordinator runs FROST aggregation → single σ        │
│  - Contract verifies σ against group_pk                │
├─────────────────────────────────────────────────────────┤
│  Phase 3: Key refresh (per epoch, optional)            │
│  - New DKG to rotate group key                          │
│  - Old PK frozen; new PK activated                      │
└─────────────────────────────────────────────────────────┘
```

## 2. Distributed Key Generation (DKG)

### 2.1 Participants

A set of N oracle operators registered in EscrowOracleRegistry. Each has:
- A master keypair (M_i, M_pub_i) for identity
- A DKG commitment stored on-chain

### 2.2 Protocol (FROST Round 1)

1. Each participant P_i generates a secret polynomial f_i(x) of degree t-1:
   - f_i(x) = a_{i,0} + a_{i,1}·x + ... + a_{i,t-1}·x^{t-1}
   - where a_{i,0} is P_i's secret coefficient, a_{i,1}...a_{i,t-1} are random

2. Each P_i computes commitments C_i = { φ_{i,0} = a_{i,0}·G, φ_{i,1} = a_{i,1}·G, ... }
   and broadcasts C_i to all other participants.

3. Each P_i computes secret shares s_{i,j} = f_i(j) for j = 1..N, j ≠ i,
   and sends s_{i,j} encrypted to P_j using the recipient's master public key.

4. Each P_j receives s_{i,j} from all i ≠ j and verifies each share:
   - s_{i,j}·G == Σ_{k=0}^{t-1} j^k · φ_{i,k}
   - If verification fails, P_j broadcasts a complaint against P_i.

5. Each participant computes their final secret share:
   - sk_j = Σ_{i=1}^{N} s_{i,j}
   - The group public key: PK = Σ_{i=1}^{N} φ_{i,0}

### 2.3 On-chain storage

```solidity
struct DKGState {
    bytes32  sessionId;       // keccak256(participants || block.number)
    address[] participants;
    bytes     groupPublicKey;  // 32 bytes (Schnorr point compressed)
    uint256   threshold;      // K
    uint256   total;          // N
    uint256   completedAt;    // block number
    bool      active;
}
```

## 3. Partial Signature Generation (FROST Round 2)

### 3.1 Per-attestation signing

For a given attestation with message m (the canonical JSON from SPEC §4):

1. Each selected oracle i computes the binding value:
   - ρ_i = H(i || m || group_pk || current_epoch)
   - R_i = ρ_i · G

2. Oracle i computes their partial signature:
   - λ_i = Lagrange coefficient for participant i over the signing set S (|S| = K)
   - z_i = ρ_i + λ_i · sk_i · H(m || R_agg)
   - where R_agg = Σ_{i∈S} R_i

3. Oracle i outputs partial signature σ_i = (R_i, z_i)

### 3.2 Coordinator aggregation

The coordinator (any participant, or a separate relayer):

1. Computes R_agg = Σ_{i∈S} R_i
2. Computes c = H(m || R_agg)
3. Aggregates: z_agg = Σ_{i∈S} z_i
4. Outputs: σ = (R_agg, z_agg)

## 4. Verification

### 4.1 On-chain Verifier

```solidity
contract FrostVerifier {
    // Verify a FROST threshold signature
    function verify(
        bytes32 message,
        bytes calldata signature,   // (R_agg, z_agg) — 64 bytes
        bytes calldata groupPubKey   // 32 bytes
    ) external pure returns (bool) {
        // Parse R_agg (32 bytes) and z_agg (32 bytes)
        // Compute c = hash(message || R_agg)
        // Check: z_agg * G == R_agg + c * groupPubKey
        // This is a standard Schnorr verification
    }
}
```

### 4.2 Gas cost

| Operation | Gas estimate |
|-----------|-------------|
| Parse signature (2 × MLOAD) | ~6 |
| Hash message || R_agg (SHA-256) | ~90 per 32 bytes |
| EC_MUL (z_agg * G) | ~6,500 (precompile) |
| EC_MUL (c * PK) | ~6,500 (precompile) |
| EC_ADD (R_agg + c·PK) | ~500 |
| Comparison | ~50 |
| **Total** | **~13,650 gas** |

Compare: verifying two independent ml-dsa-65 signatures at ~85,000 gas each → 170,000 gas. FROST saves ~92%.

## 5. Integration with escrow-oracles

### 5.1 Coordinator module

Located at `oracles/aggregator/coordinator.js`:

```
coordinator/
  dkg.js          — DKG round management
  signing.js      — Partial sig collection + aggregation
  onchain.js      — Submit aggregated sig to FrostVerifier
  state.js        — In-memory DKG/signing state machine
```

### 5.2 API

```
POST /dkg/initiate          — Start DKG round (specify N, K)
POST /dkg/contribute        — Submit individual contribution
GET  /dkg/status           — Current DKG progress
POST /sign/initiate         — Start signing round (specify message, K signers)
POST /sign/contribute       — Submit partial signature
GET  /sign/aggregate        — Get aggregated signature
```

### 5.3 Per-epoch ephemeral key derivation

Per SPEC §6.1, each oracle derives ephemeral_priv = HKDF(M_priv, request_id || epoch_id). With FROST:

1. DKG runs once per epoch
2. Group public key stored on-chain for that epoch
3. Each signing round uses the DKG-derived secret share sk_i
4. Coordinator aggregates and submits single sig

### 5.4 Error handling

| Scenario | Behavior |
|----------|----------|
| Partial sig received after timeout | Exclude signer, fall to different K-subset |
| Incorrect partial sig (z_i·G ≠ R_i + c·λ_i·commit_i) | Discard, report participant |
| DKG participant goes offline mid-round | After timeout, restart DKG with reduced N |
| Coordinator is malicious | Any participant can detect bad aggregation; submit via fallback contract |

## 6. Security Considerations

### 6.1 Rogue key attacks

Mitigated by DKG's commitment phase: each participant's coefficient commitments are verified by all others before secret sharing begins. The group public key PK = Σ φ_{i,0} is a sum of individual commitments, each provably bound to its creator.

### 6.2 Replay attacks

Each message includes request_id and a nonce (block timestamp). The on-chain verifier stores used (R_agg, message) pairs to prevent double-use.

### 6.3 Threshold security

With parameters (K, N):
- Security threshold: K-1 compromised participants cannot forge signatures
- Availability: N-K drops tolerated
- v1 default: K=2, N=3 (tolerates 1 drop-out, needs 2 honest)

### 6.4 Post-quantum consideration

FROST (Schnorr) is not quantum-resistant. For post-quantum safety, migrate to FROST over a PQ signature scheme (see switchboard PQ envelope RFC). The contract architecture at §4.1 supports swapping the verifier.

## 7. Testing

### 7.1 Test cases

| Test | Description |
|------|-------------|
| 2-of-3 happy path | DKG with 3 participants, sign with 2, verify |
| 3-of-5 happy path | DKG with 5, sign with 3, verify |
| Drop-out mid-DKG | One participant disconnects; DKG restarts with 4 |
| Drop-out mid-signing | One signer times out; coordinator picks alternative K-subset |
| Incorrect partial sig | Byzantine signer sends bad σ_i; coordinator discards |
| DKG complaint | One participant complains; protocol resolves |
| Key refresh | New epoch triggers DKG; old PK deactivated |
| Replay prevention | Re-using same (R_agg, message) rejected |

### 7.2 Test harness

Located at `tests/test_frost.py` with pytest fixtures:

```python
@pytest.fixture
async def frost_2_3():
    """2-of-3 FROST group with simulated participants."""
    participants = [SimOracle(i) for i in range(3)]
    dkg = await DKGCoordinator(participants, K=2).run()
    yield dkg

async def test_2_of_3_happy(frost_2_3):
    sig = await frost_2_3.sign(b"test message", signers=[0, 1])
    assert frost_2_3.verify(sig, b"test message")

async def test_bad_partial_sig(frost_2_3):
    sig = await frost_2_3.sign(b"test", signers=[0, 1], corrupt={1})
    assert not frost_2_3.verify(sig, b"test")
```

## 8. Implementation plan

| Step | Component | Effort |
|------|-----------|--------|
| 1 | Schnorr math + FROST primitives | 2 days |
| 2 | DKG coordinator | 2 days |
| 3 | Signing coordinator + aggregation | 2 days |
| 4 | `FrostVerifier.sol` contract | 1 day |
| 5 | Integration tests | 1 day |
| 6 | Documentation + spec | 0.5 day |
| | **Total** | **~8 days** |

## References

1. Komlo, C., Goldberg, I. "FROST: Flexible Round-Optimized Schnorr Threshold Signatures." (2020)
2. Boneh, D., Lynn, B., Shacham, H. "Short Signatures from the Weil Pairing." (2001) — BLS comparison
3. Lindell, Y. "Fast Secure Two-Party ECDSA Signing." (2017) — CGGMP background
4. Nick, J., Ruffing, T., Seurin, Y. "MuSig2: Simple Two-Round Schnorr Multisignatures." (2021)
