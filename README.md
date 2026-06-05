# escrow-oracles

> Open standard + reference implementation for **autonomous, anonymized agents that attest delivery conditions** for [switchboard](https://github.com/kcolbchain/switchboard) escrows.

[![status](https://img.shields.io/badge/status-alpha-orange)](https://github.com/kcolbchain/escrow-oracles) [![org](https://img.shields.io/badge/org-kcolbchain-7c3aed)](https://kcolbchain.com)

---

## What this is

Agent-to-agent payments need a way to settle escrow **without a human in the loop and without trusting any single oracle operator**. `switchboard`'s `AgentEscrow.sol` today releases on a human's `confirmPayment()` call. For agentic flows where there's no human to click, we need objective, verifiable proof of delivery — and we need it cheap, fast, and operator-independent.

**`escrow-oracles` is the spec** for how that works, plus reference oracles you can run.

## Design principles

1. **Transparent settlements.** The release condition lives in the `PaymentOffer`. Any party — including the payer's wallet UI — can independently re-check it. No black boxes.
2. **Quantitative outcomes only.** v1 supports three deterministic check types: `url_check`, `hash_check`, `event_check`. No LLM grading, no subjective "work quality" judgments.
3. **Operator-agnostic.** An oracle is a role, not a runtime. A bash script with a keypair, a Rust daemon on someone's NAS, a Lambda function, all participate equally — the spec is what matters.
4. **Lossless.** Oracles never custody funds. They only sign attestations. The escrow contract releases on K-of-N agreement; the oracle has no path to steal.
5. **Anonymized.** Each attestation is signed with a fresh ephemeral key derived from the oracle's master key. There's no long-term identity in the on-chain trace.
6. **Lottery-rewarded.** Correct attestations enter a per-epoch VRF lottery; payouts go to stealth addresses derived from the master key. Probabilistic, not deterministic, so adversaries can't game which attestation gets paid.
7. **Health-adaptive.** Protocol parameters (K, attestation window, reward rate) adjust automatically when the network's participation or false-release rate drifts.

## Architecture (v1)

```
                    PaymentOffer.policy declares the check
                       (url_check / hash_check / event_check)
                                       │
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                        ▼
         Oracle 1                Oracle 2                Oracle 3
        (ephemeral key)         (ephemeral key)         (ephemeral key)
              │                        │                        │
              │  observes off-chain;   │  PQ-signs the          │
              │  computes deterministic│  canonical attestation │
              │  result                │  hash                  │
              ▼                        ▼                        ▼
                  ┌──────────────────────────────────┐
                  │  AgentEscrow.attest(             │
                  │    requestId,                    │
                  │    attestationHash,              │
                  │    signatures[K]                 │
                  │  )                               │
                  └──────────────┬───────────────────┘
                                 │
                                 │  K-of-N threshold met →
                                 │  release funds + earmark
                                 │  release-fee for reward pool
                                 ▼
                  ┌──────────────────────────────────┐
                  │  Per-epoch lottery distributes   │
                  │  pool to stealth addresses of    │
                  │  randomly-selected correct       │
                  │  attesters                       │
                  └──────────────────────────────────┘
```

## What's in this repo (planned)

| Path | What |
|---|---|
| `docs/SPEC.md` | Full protocol specification — message formats, threshold rules, reward mechanics, adaptive parameters |
| `contracts/EscrowOracleRegistry.sol` | On-chain attestation aggregator. Adds `attest()` to switchboard's `AgentEscrow.sol`. |
| `examples/hello-oracle.py` | L0 — single-file Python oracle, ~80 lines. Fetch URL, sign attestation, post. |
| `oracles/url-check/` | Reference oracle implementing `url_check` end-to-end |
| `oracles/hash-check/` | Reference oracle for `hash_check`: verify fetched IPFS content against the SHA-256 multihash embedded in a CID |
| `oracles/event-check/` | Reference oracle for on-chain `event_check` |
| `game/` | The protocol-tuning + adversarial + compose game (see issue #6) |

## Contribution ladder

| Level | Time | What you build |
|---|---|---|
| **L0** | 15 min | A single-file hello-world oracle: fetch a URL, sign, post. |
| **L1** | 1 hour | A spec-conformant implementation of one check type (`url_check` / `hash_check` / `event_check`). |
| **L2** | 1 day | A multi-chain oracle node — same logic posting attestations to Lux + Base + OP. |
| **L3** | 1 week | Threshold signature aggregation (FROST / BLS) so K signatures compress to one on-chain. |
| **L4** | 1 month | Cryptoeconomic security — adaptive K, optimistic challenge mode, slashing-on-conflicting-sig. |
| **L5** | ongoing | Build the protocol simulator + adversarial game (issue #6). |

See [open issues](https://github.com/kcolbchain/escrow-oracles/issues) — every level has at least one `help wanted` issue with a checklist.

## How this composes

- **switchboard's `AgentEscrow.sol`** gains an `attest()` entry point so K-of-N attestations release the escrow without a human's `confirmPayment()`.
- **switchboard's [composable refund policies](https://github.com/kcolbchain/switchboard/issues/46)** can use this network as their evidence source (`OracleSLAPolicy` → `EscrowOracleRegistry`).
- **switchboard's [PQ envelope RFC](https://github.com/kcolbchain/switchboard/issues/33)** sets the signature algorithm registry; attestations use `ml-dsa-65` by default.

## Why a new repo (and not a switchboard subdir)

- **Independent contribution loop.** Oracle operators don't need to track every switchboard PR.
- **Cleaner versioning.** The spec evolves on its own clock; switchboard consumes a pinned version.
- **Lower barrier to entry.** A new contributor can grok this repo in 30 minutes without wading through switchboard's full stack.

## Status

**Alpha.** Spec is in active design (see [#1 meta-issue](https://github.com/kcolbchain/escrow-oracles/issues/1)). Contracts and reference oracles to follow.

Want to contribute? Open an issue, comment on the [L0–L5 ladder](https://github.com/kcolbchain/escrow-oracles/issues/1), or just send a PR. Built by [kcolbchain](https://kcolbchain.com) — MIT.
