import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

@dataclass
class Observation:
    deliverable_id: str
    status: str
    payload: dict
    chain: str
    tx_hash: Optional[str] = None

class ChainAdapter(ABC):
    @abstractmethod
    def post_attestation(self, observation: Observation) -> Optional[str]:
        ...
    @abstractmethod
    def chain_name(self) -> str:
        ...

class EvmChainAdapter(ChainAdapter):
    def __init__(self, rpc_url: str, contract_address: str):
        self._rpc = rpc_url
        self._contract = contract_address
    def chain_name(self) -> str:
        return self._contract.split(":")[0] if ":" in self._contract else "evm"
    def post_attestation(self, observation: Observation) -> Optional[str]:
        logger.info(f"Posting attestation to {self.chain_name()}: {observation.deliverable_id}")
        return f"0x{observation.deliverable_id.encode('utf-8').hex()[:64]}"

class LuxChainAdapter(ChainAdapter):
    def __init__(self, endpoint: str):
        self._endpoint = endpoint
    def chain_name(self) -> str:
        return "lux"
    def post_attestation(self, observation: Observation) -> Optional[str]:
        logger.info(f"Posting attestation to Lux: {observation.deliverable_id}")
        return f"lux:{observation.deliverable_id}"

class MultiChainNode:
    def __init__(self, adapters: list[ChainAdapter]):
        self._adapters = adapters
    def observe_and_attest(self, deliverable_id: str, status: str, payload: dict) -> list[Observation]:
        results = []
        base = Observation(deliverable_id=deliverable_id, status=status, payload=payload, chain="")
        for adapter in self._adapters:
            obs = Observation(deliverable_id=deliverable_id, status=status, payload=payload, chain=adapter.chain_name())
            tx = adapter.post_attestation(obs)
            obs.tx_hash = tx
            results.append(obs)
        return results
