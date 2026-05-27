# escrow-oracles v0.1 Roadmap

> **Autonomous, anonymized attestation network** — a decentralized oracle network for switchboard escrows.

**Meta-issue:** [#1](https://github.com/kcolbchain/escrow-oracles/issues/1)

---

## Milestones

### M0: Foundation (L0–L1)
**Target: Complete**

| Issue | Status | Deliverable |
|-------|--------|-------------|
| #2 L0: Hello-world oracle | ✅ Done | `examples/hello-oracle.py` — single-file Python oracle (~80 lines) |
| #3 L1: First check type | ✅ Done | `oracles/url-check/url_check.py` — full `url_check` implementation with tests |
| Spec | ✅ Done | `docs/SPEC.md` — protocol specification v0.1 draft |

### M1: Multi-chain Node (L2)
**Target: In progress**

| Issue | Status | Deliverable |
|-------|--------|-------------|
| #4 Multi-chain oracle node | 🔄 In progress | `oracles/multi-chain/node.py` — Lux + Base dual-chain oracle |
| Chain adapters | 🔄 In progress | `oracles/adapters/` — LuxAdapter, BaseAdapter |
| Integration tests | ⬜ Pending | Cross-chain attestation submission + verification |
| CI pipeline | ⬜ Pending | GitHub Actions for contract tests, oracle tests |

### M2: Threshold Signatures (L3)
**Target: Next**

| Issue | Status | Deliverable |
|-------|--------|-------------|
| #5 FROST threshold aggregation | ⬜ Pending | `spec/frost-threshold-signature.md` — spec document |
| FROST coordinator | ⬜ Pending | `oracles/aggregator/` — DKG + partial sig aggregation |
| FrostVerifier.sol | ⬜ Pending | On-chain FROST verifier contract |
| DKG integration | ⬜ Pending | Per-epoch key generation + key refresh |
| Test suite | ⬜ Pending | 2-of-3, 3-of-5, edge case tests |

### M3: Cryptoeconomic Security (L4)
**Target: Planned**

| Issue | Status | Deliverable |
|-------|--------|-------------|
| #6 Economic security | ⬜ Pending | `docs/cryptoeconomic-security.md` — design document |
| BondManager contract | ⬜ Pending | Bond deposit, unbonding, withdrawal |
| Slashing logic | ⬜ Pending | Equivocation, false attestation, DKG misbehavior |
| Optimistic challenge mode | ⬜ Pending | Challenge window, dispute resolution, bond forfeiture |
| Adaptive K | ⬜ Pending | Automatic K adjustment based on conflict history |
| Adversarial tests | ⬜ Pending | Byzantine oracle, drop-out, censoring relayer fixtures |

### M4: Protocol Tuning + Game (L5)
**Target: Ongoing**

| Issue | Status | Deliverable |
|-------|--------|-------------|
| #7 Protocol game | ⬜ Pending | `game/` — simulator + adversarial game |
| Parameter optimization | ⬜ Pending | Economic modeling, simulation results |
| Formal verification | ⬜ Pending | Key contract invariants |
| Final audit | ⬜ Pending | Third-party security review |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │ url_check   │  │ hash_check  │  │ event_check │  ... more    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
└─────────┼─────────────────┼─────────────────┼────────────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Oracle Node (L2)                           │
│  ┌──────────┐  ┌──────────────────┐  ┌──────────────────┐       │
│  │ Check    │  │ Attestation      │  │ FROST Aggregator │       │
│  │ Runner   │  │ Builder          │  │ (L3)             │       │
│  └──────────┘  └──────────────────┘  └──────────────────┘       │
│  ┌──────────────────────────────────────────────────────┐        │
│  │            Chain Adapters                             │        │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐        │        │
│  │  │ LuxAdapter│  │BaseAdapter│  │ OpAdapter │        │        │
│  │  └───────────┘  └───────────┘  └───────────┘        │        │
│  └──────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Smart Contracts                            │
│  ┌──────────────────────┐  ┌──────────────────┐                 │
│  │ EscrowOracleRegistry │  │ FrostVerifier    │                 │
│  │ (attest aggregator,  │  │ (threshold sig   │                 │
│  │  K-of-N logic)       │  │  verification)   │                 │
│  └──────────┬───────────┘  └──────────────────┘                 │
│             │                                                    │
│  ┌──────────▼───────────┐  ┌──────────────────┐                 │
│  │ BondManager          │  │ EscrowOracle     │                 │
│  │ (bond + slashing)    │  │ RegistryV2       │                 │
│  │                      │  │ (optimistic mode,│                 │
│  │                      │  │  adaptive K)     │                 │
│  └──────────────────────┘  └──────────────────┘                 │
│                                                                  │
│  ┌──────────────────────────────────────────────────────┐        │
│  │              AgentEscrow.sol (switchboard)            │        │
│  │  releaseByAttestation() | setPolicyHash()             │        │
│  └──────────────────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│                          Reward Layer                             │
│  ┌──────────────────────┐  ┌──────────────────┐                 │
│  │ Reward Pool          │  │ VRF Lottery      │                 │
│  │ (0.5% siphon per     │  │ 10 winners/epoch  │                 │
│  │  release)            │  │ stealth addresses │                 │
│  └──────────────────────┘  └──────────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

## Component Breakdown

### Core Smart Contracts

| Contract | Role | Status |
|----------|------|--------|
| `EscrowOracleRegistry.sol` | On-chain attestation aggregator; K-of-N logic | ⬜ Not started |
| `FrostVerifier.sol` | FROST threshold signature verification | ⬜ L3 deliverable |
| `BondManager.sol` | Bond deposit, unbonding, slashing | ⬜ L4 deliverable |
| `EscrowOracleRegistryV2.sol` | Optimistic mode, adaptive K, slashing integration | ⬜ L4 deliverable |

### Oracle Node Components

| Component | Role | Status |
|-----------|------|--------|
| Check runner | Executes policy checks (url/hash/event) | ✅ L1 complete |
| Attestation builder | Builds canonical JSON, signs with ephemeral key | 🔄 L2 integration |
| FROST aggregator | DKG + partial sig collection + aggregation | ⬜ L3 |
| Chain adapters | Per-chain submission interface | 🔄 L2 partial (Lux + Base) |

### Supporting Infrastructure

| Component | Role | Status |
|-----------|------|--------|
| Policy library | Constructs and validates PaymentOffer policies | ⬜ Not started |
| VRF lottery | Per-epoch winner selection | ⬜ L4 bundled |
| Stealth address derivation | EIP-5564 inspired | ⬜ TBD |
| Prototyping game | Agent-based simulation for parameter tuning | 🔄 L5 in `game/` |

## Dependency Graph

```
L0 ───► L1 ───► L2 ───► L3 ───► L4 ───► L5
│                 │         │         │
└──── Spec ───────┘         │         │
                             ▼         │
                       FROST math ◄────┘
                                        ▼
                                  Economic model
```

Each level depends on all previous levels. The spec (SPEC.md) is the common foundation for L1+.

## Key Design Decisions

### v1 Scope
- **Included:** K-of-N threshold attestation, lottery rewards, stealth payouts, health-adaptive parameters
- **Deferred:** Cross-chain release (v2), subjective grading (never), full BFT consensus (overkill), identity/reputation layer (v2)

### Signature scheme
- **L1–L2:** Individual ml-dsa-65 signatures (post-quantum, ~3.3 KB each)
- **L3+:** FROST-threshold Schnorr signatures (64 bytes aggregated)
- **Long-term:** PQ-FROST hybrid (when PQ Schnorr primitives mature)

### Economic model
- **L1–L3:** Pure lottery rewards (no economic security)
- **L4+:** Optional bonds + slashing + optimistic verification

### Multi-chain
- **v1:** Independent per-chain deployment (same attestation format, separate registries)
- **v2:** Cross-chain attestation verification (same K-of-N, any chain triggers release)

## Open Questions

1. **Stealth address scheme** — EIP-5564 (secp256k1) vs custom over ml-dsa-65? EIP-5564 preferred for chain compatibility.
2. **VRF source** — chain randomness (prevrandao) vs drand vs native VRF? Tradeoff: cost vs verifiability.
3. **Lottery scaling** — L=10 fixed vs L = max(5, eligible/20)? Fixed is simpler but rewards thin for small pools.
4. **Optimistic vs synchronous** — Add optimistic mode in L4? Yes, as an optional deployment mode.
5. **PQ vs hybrid** — Full PQ now vs ECDSA+PQ hybrid? v1 picks ml-dsa-65 for forward compatibility.
6. **Governance** — Who sets parameters (K, window, reward rate)? Multi-sig + time-lock in v1; DAO in v2.

## Contributing

See `CONTRIBUTING.md` for process. The L0–L5 ladder in each issue provides clear entry points:

| Level | Time | Skill |
|-------|------|-------|
| L0 | 15 min | Any (hello-world oracle) |
| L1 | 1 hr | Python/JS scripting |
| L2 | 1 day | Multi-chain development |
| L3 | 1 week | Cryptography implementation |
| L4 | 1 month | Solidity + economic design |
| L5 | ongoing | Game theory + simulation |
