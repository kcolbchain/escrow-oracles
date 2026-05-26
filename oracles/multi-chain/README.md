# Multi-Chain Oracle Node

L2 reference implementation for attesting single deliverables across multiple chains (Lux + Base v1).

## Architecture

```
Off-chain deliverable
       |
MultiChainNode.observe_and_attest()
       |
  +----+----+
  |         |
Lux       Base
```

Each `ChainAdapter` abstracts chain-specific posting logic. The node produces one `Observation` per chain.

## Usage

```python
from oracles.multi_chain import MultiChainNode, LuxChainAdapter, EvmChainAdapter

node = MultiChainNode([
    LuxChainAdapter("https://rpc.lux.com"),
    EvmChainAdapter("https://base-rpc.com", "base:0xContract"),
])
results = node.observe_and_attest("req-001", "delivered", {"url": "https://..."})
```

## Adding a chain

Subclass `ChainAdapter`, implement `chain_name()` and `post_attestation()`, then add to the adapter list.
