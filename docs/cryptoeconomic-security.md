# Cryptoeconomic Security Design

> Slashing conditions, bond mechanics, and optimistic verification mode for escrow-oracles v1.

**Status:** Draft v0.1  
**Depends on:** L3 (FROST threshold signature aggregation)  

## 1. Motivation

The base protocol (SPEC §6) incentivizes correct attestation solely through the per-epoch lottery — honest attestations have `L/total` chance of earning the reward pool share. This is sufficient for benign participation but provides no deterrent against active adversaries who submit false attestations to trigger fraudulent releases.

This document adds a cryptoeconomic security layer: **bonds, slashing, and optimistic verification mode**.

## 2. Bonded Operators (Optional)

### 2.1 Bond lifecycle

An oracle operator may opt into bonding by depositing ETH (or ERC-20) into a bond contract. The bond binds to the operator's master public key.

```
                          ┌──────────────┐
                          │  Operator    │
                          │  deposits    │
                          │  bond        │
                          └──────┬───────┘
                                 │
                                 ▼
                     ┌─────────────────────┐
                     │  Bond Locked        │
                     │  7-day unbonding    │
                     │  timer starts on    │
                     │  unbond request     │
                     └─────────────────────┘
                           │           │
                           ▼           ▼
                    ┌──────────┐  ┌──────────┐
                    │ Active   │  │ Slashed  │
                    │ (bond +  │  │ (part or │
                    │  weight) │  │  all)    │
                    └──────────┘  └──────────┘
```

### 2.2 Bond parameters

| Parameter | Default | Details |
|-----------|---------|---------|
| `minBond` | 0.1 ETH | Minimum stake to register as bonded |
| `maxBond` | 10 ETH | Maximum per operator |
| `unbondingPeriod` | 7 days | Prevents grab-bond-then-attack |
| `rewardMultiplier` | 1.5× | Bonded operators weighted higher in lottery |

### 2.3 Reward multiplier effect

In the per-epoch lottery (SPEC §6.3), bonded operators receive a weight multiplier:

```
effective_weight = base_weight × (1 + (rewardMultiplier - 1) × min(bond / minBond, 1))

Example: bond = 0.1 ETH, minBond = 0.1 ETH → weight × 1.5
Example: bond = 0.5 ETH, minBond = 0.1 ETH → weight × 1.5 (capped at minBond)
Example: bond = 0 ETH → weight × 1.0 (unbonded)
```

The multiplier is capped so it incentivizes bonding without creating a winner-take-all dynamic.

## 3. Slashing Conditions

### 3.1 Equivocation (double-signing)

**Condition:** An oracle signs two conflicting attestations for the same `request_id` with check results that would lead to different release decisions.

| Attestation | check_result |
|-------------|-------------|
| `attest(..., request_id=X, check_result=true, ...)` | true |
| `attest(..., request_id=X, check_result=false, ...)` | false |

**Slashing penalty:** Full bond minus a 10% bounty to the reporter.

**Proof submission:**

```solidity
function slashEquivocation(
    bytes calldata attestation1,  // raw attestation bytes
    bytes calldata attestation2,  // conflicting attestation
    bytes calldata pubKey          // oracle's master pub key
) external {
    // 1. Verify both signatures against pubKey
    // 2. Verify requestId matches
    // 3. Verify checkResult differs
    // 4. Verify both are within attestation window
    // 5. Transfer bond - bounty to reporter
}
```

### 3.2 False attestation (proven by dispute)

**Condition:** An attestation is proven false after an optimistic challenge (see §5). The original attester's check result disagrees with the consensus result established after dispute resolution.

**Slashing penalty:** 50% of bond.

### 3.3 DKG misbehavior

| Behavior | Slashing fraction |
|----------|------------------|
| Sending invalid secret share during DKG | 25% |
| Filing false complaint against honest participant | 25% |
| Participating in DKG but never signing | No slash, but excluded from epoch eligibility |

### 3.4 Slashing constraints

Per DKG-aware slashing principle: only the key that signed both equivocating attestations may be slashed. The group public key must not be slashed — individual participants are responsible for their own derived secret shares.

## 4. Bond Contract

### 4.1 Interface

```solidity
interface IBondManager {
    /// @notice Deposit bond for a master public key
    function depositBond(bytes calldata masterPubKey) external payable;

    /// @notice Initiate unbonding period (7-day timer starts)
    function requestUnbond(bytes calldata masterPubKey) external;

    /// @notice Withdraw bond after unbonding period expires
    function withdrawBond(bytes calldata masterPubKey) external;

    /// @notice Slice bond for proven misbehavior
    function slash(bytes calldata masterPubKey, uint256 amount, address beneficiary) external;

    /// @notice Get bond status
    function getBondInfo(bytes calldata masterPubKey)
        external view returns (BondInfo memory);
}

struct BondInfo {
    uint256  amount;
    uint256  requestedAt;    // unbonding start, 0 if not requested
    bool     slashed;
    uint256  rewardWeight;   // weight multiplier for lottery
}
```

### 4.2 Bond pool accounting

All bonded ETH lives in the BondManager contract. Slashed amounts are split:

- **90%** → bond pool (returned to future slashing victims or redistributed)
- **10%** → reporter bounty (paid immediately to the submitter of slashing proof)

## 5. Optimistic Verification Mode

### 5.1 Motivation

Synchronous K-of-N (SPEC §5) requires all K attestations to be submitted on-chain within the attestation window. This is simple but expensive: every attestation pays calldata gas, regardless of whether a dispute arises.

Optimistic mode reduces steady-state cost: attestations are submitted optimistically, and disputes are resolved only when challenged.

### 5.2 State machine

```
                    ┌──────────────────┐
                    │   Contract       │
                    │   receives ≥K    │
                    │   attestations   │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
               ┌───│  Challenge       │◄──── Dispute submitted
               │   │  Window (5 min)  │       within window
               │   └──────────────────┘
               │         │
               │  Window expires with no challenge
               │         │
               │         ▼
               │   ┌──────────────────┐
               │   │  Release Fires   │
               │   │  Funds sent to   │
               │   │  payee           │
               │   └──────────────────┘
               │
               │   ┌──────────────────┐
               └──►│  Dispute Phase   │
                   │  Challenger      │
                   │  re-runs check,  │
                   │  posts counter-  │
                   │  attestation     │
                   └────────┬─────────┘
                            │
                            ▼
                    ┌──────────────────┐
                    │  Verdict         │
                    │  (by re-running  │
                    │  check or        │
                    │  2nd round of    │
                    │  attestation)    │
                    └──────────────────┘
                         │         │
                         ▼         ▼
                 ┌──────────┐ ┌──────────┐
                 │ Dispute  │ │ Dispute  │
                 │ Upheld   │ │Rejected  │
                 │ Bond     │ │ No slash │
                 │ slashed  │ │ Release  │
                 └──────────┘ └──────────┘
```

### 5.3 Parameters

| Parameter | Default | Details |
|-----------|---------|---------|
| `challengeWindow` | 300 blocks (~5 min on Lux) | Window after K attestations received |
| `disputeBond` | 0.05 ETH | Bond required to submit a dispute (prevents spam) |
| `disputeResolutionPeriod` | 100 blocks | Max time for second-round attestation |
| `challengeReward` | 10% of slashed bond | Paid to successful challenger |

### 5.4 Dispute flow

1. **Submit attestations:** K oracles submit their attestations normally. Challenge window starts.

2. **Challenge:** Within `challengeWindow`, anyone may dispute by:
   - Posting `disputeBond`
   - Running the deterministic check from the policy themselves
   - Submitting a counter-attestation with evidence

3. **Resolution:** During `disputeResolutionPeriod`, other oracles re-attest. If ≥K oracles support the challenger's side:
   - Original attestors are slashed (50% of bond)
   - Challenger earns `challengeReward`
   - Escrow is NOT released

4. **Failed dispute:** If fewer than K oracles support the challenger:
   - Challenger's bond is forfeited
   - Escrow proceeds to release
   - Forfeited bond distributed to original attesters

### 5.5 Gas comparison

| Scenario | Synchronous | Optimistic (no dispute) | Optimistic (dispute) |
|----------|-------------|------------------------|----------------------|
| K=2, N=3 | ~170,000 | ~30,000 (aggregated sig) | ~300,000 (dispute resolution) |
| K=5, N=10 | ~425,000 | ~30,000 | ~500,000 |
| K-of-N general | O(K × sig_gas) | O(1) | O(K × sig_gas + bond) |

Optimistic mode saves ~85% gas in the common case (no dispute).

## 6. Adaptive K Based on Conflict History

### 6.1 Motivation

Static K=2 is appropriate for low-value escrows (<0.1 ETH). For higher values, or when one or more oracles are compromised, adaptive K provides automatic security scaling.

### 6.2 Tracking

Per-policy-type and per-payee conflict rate:

```solidity
struct ConflictMetrics {
    uint256 totalReleases;
    uint256 disputedReleases;       // resolved by dispute
    uint256 equivocationEvents;     // proven equivocations
    uint256 lastUpdateEpoch;
    bool    hysteresisLock;         // prevents rapid oscillation
}
```

### 6.3 Rules

```
// Each epoch:
false_release_rate = disputedReleases / max(totalReleases, 1)

if false_release_rate > 0.01 and currentK < maxK:
    K += 1
    hysteresisLock = true

if false_release_rate < 0.005 and currentK > minK and not hysteresisLock:
    K -= 1

// Hysteresis clears after 1 full epoch with no triggers
if hysteresisLock and (current false_release_rate < 0.005):
    hysteresisLock = false  // ready to revert next epoch
```

### 6.4 Bounds

| Parameter | Default | Range |
|-----------|---------|-------|
| `minK` | 2 | [1, N] |
| `maxK` | N | [minK, N] |
| `falseReleaseThreshold` | 1% (0.01) | [0.001, 0.1] |
| `hysteresisEpochs` | 1 | [1, 10] |

## 7. Integration with EscrowOracleRegistry

### 7.1 Contract extension: V2

```solidity
contract EscrowOracleRegistryV2 is EscrowOracleRegistry {
    using BondManager for BondManager.State;

    // Bond Management
    BondManager.State bonds;

    function bondDeposit(bytes calldata masterPubKey) external payable;
    function bondRequestUnbond(bytes calldata masterPubKey) external;
    function bondWithdraw(bytes calldata masterPubKey) external;

    // Slashing
    function slashEquivocation(
        Attestation calldata a1,
        Attestation calldata a2,
        bytes calldata masterPubKey
    ) external;

    // Optimistic Mode
    struct OptimisticChallenge {
        bytes32 requestId;
        address challenger;
        bytes32 challengerAttestation;
        uint256 challengedAt;
        uint256 resolvedAt;
        bool    disputeUpheld;
    }

    // Adaptive K
    mapping(bytes32 => ConflictMetrics) policyTypeMetrics;
    mapping(address => ConflictMetrics) payeeMetrics;

    uint256 public currentK;
    uint256 public minK;
    uint256 public maxK;
}
```

### 7.2 Fee model

| Action | Fee |
|--------|-----|
| Bond deposit | 0 |
| Bond withdraw | 0 |
| Slashing proof | 0 (gas only) |
| Optimistic challenge | `disputeBond` (returned if upheld) |
| Adaptive K adjustment | 0 (automatic) |

### 7.3 Lottery integration

Bonded operators have weighted entries in the lottery (§6.3):

```
weight_i = 1 + bonds[i].rewardMultiplier if bonded else 1
eligible_weight = sum of all eligible_i's weights
P(win_i) = weight_i / eligible_weight
```

## 8. Testing

### 8.1 Test cases

| Test | Category |
|------|----------|
| Deposit bond, verify weight multiplier | Bond lifecycle |
| Request unbond, try to withdraw before 7 days (revert) | Bond lifecycle |
| Request unbond, wait 7 days, withdraw success | Bond lifecycle |
| Equivocation: same pubkey, same requestId, different result → slash | Slashing |
| Equivocation: same pubkey, different requestId → no slash | Slashing |
| False attestation via optimistic challenge → slash 50% | Slashing |
| Bad DKG share → slash 25% | Slashing |
| K attestations, window expires → release fires | Optimistic |
| K attestations, challenge within window → dispute phase | Optimistic |
| Dispute upheld → original attesters slashed | Optimistic |
| Dispute rejected → challenger bond forfeited | Optimistic |
| False release rate > 1% → K increases | Adaptive K |
| Rate recovers → K decreases after hysteresis | Adaptive K |
| Max K hit → K stays at max | Adaptive K |

### 8.2 Adversarial test fixtures

```python
@pytest.fixture
def byzantine_oracle():
    """An oracle that equivocates on every attestation."""
    oracle = SimOracle(equivocate=True)
    return oracle

@pytest.fixture
def drop_out_oracle():
    """An oracle that disappears mid-round."""
    oracle = SimOracle(drop_out_after="first_attestation")
    return oracle

@pytest.fixture
def censoring_relayer():
    """A relayer that drops attestations from specific oracles."""
    ...

async def test_byzantine_gets_slashed(byzantine_oracle):
    """Equivocating oracle gets slashed on proof submission."""
    ...
```

## 9. Security Analysis

### 9.1 Threat model

| Adversary | Power | Damage | Mitigation |
|-----------|-------|--------|------------|
| Byzantine oracle | 1/N of signing power | Can equivocate | Slashing via proof submission |
| Censoring relayer | Network position | Can delay attestations | Multiple relayers; direct contract submission |
| Sybil attacker | Many oracle keys | Can outvote honest set | Bond requirement; adaptive K |
| Flash loan attacker | Short-term bond | Deposit, equivocate, withdraw | 7-day unbonding period |

### 9.2 Economic security guarantees

For an adversary controlling M out of N oracle keys with total bond pool B:

- **Cost to cause a false release:** M must ≥ K, AND attacker must forfeit ≥ M × minBond (if slashed)
- **Cost to prevent a release (censor):** Need to prevent K honest attestations; if N-M < K, bond-free
- **Profitability threshold:** False release only profitable if escrow value > sum(slashed bonds)

### 9.3 Bond sizing recommendation

```
// For escrows up to 10 ETH:
minBond = 0.1 ETH  // 10 false releases = 1 ETH cost
// false release unprofitable if escrow < minBond × K / profit_ratio
```

## 10. Implementation Plan

| Step | Component | Effort |
|------|-----------|--------|
| 1 | BondManager contract | 2 days |
| 2 | Equivocation slashing logic | 1 day |
| 3 | Optimistic challenge state machine | 3 days |
| 4 | Adaptive K tracker + adjustment | 1 day |
| 5 | Integration with FROST verifier | 1 day |
| 6 | Lottery weight for bonded operators | 1 day |
| 7 | Adversarial test fixtures | 2 days |
| 8 | Spec extension (this document) | 0.5 day |
| | **Total** | **~11.5 days** |
