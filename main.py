#!/usr/bin/env python3
"""
AgeofChan — gangster strategy CLI for DopeModa.

This app is an offline helper plus an on-chain command runner:
  - Reads contract ABI from a Hardhat artifact JSON (if available)
  - Provides deterministic helper hashing matching the DopeModa contract
  - Sends transactions with signed raw tx (via web3 account signing) when PRIVATE_KEY is provided
  - Falls back to eth_sendTransaction when PRIVATE_KEY is not provided (requires unlocked sender)

The vibe: alley crews, territory claims, training lines, and raids settled by reveal salt.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple

from web3 import Web3
from web3.exceptions import TransactionNotFound


DEFAULT_RPC = "https://eth.llamarpc.com"


def _norm_addr(a: str) -> str:
    a = a.strip()
    if a.startswith("0X"):
        a = "0x" + a[2:]
    if not a.startswith("0x"):
        a = "0x" + a
    return Web3.to_checksum_address(a)


def _keccak_hex(data: bytes) -> str:
    return Web3.keccak(data).hex()


def _try_load_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_default_artifact(project_root: str = ".") -> Optional[str]:
    """
    Search for a likely Hardhat artifact path for DopeModa.
    """
    candidates = [
        os.path.join(project_root, "artifacts", "contracts", "DopeModa.sol", "DopeModa.json"),
        os.path.join(project_root, "artifacts", "contracts", "DopeModa.json"),
        os.path.join(project_root, "artifacts", "DopeModa.json"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


@dataclass
class ChainConfig:
    rpc_url: str
    contract: str
    artifact: Optional[str]
    private_key: Optional[str]


class AgeofChan:
    def __init__(self, cfg: ChainConfig):
        self.cfg = cfg
        self.w3 = Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": 60}))
        if not self.w3.is_connected():
            raise RuntimeError(f"RPC not connected: {cfg.rpc_url}")

        self.contract_addr = _norm_addr(cfg.contract)

        artifact_path = cfg.artifact
        if artifact_path is None:
            artifact_path = find_default_artifact(os.path.dirname(os.path.dirname(__file__)))
        if artifact_path is None:
            raise RuntimeError(
                "ABI artifact not found. Provide --artifact pointing to DopeModa.json"
            )
        art = _try_load_json(artifact_path)
        if not art:
            raise RuntimeError(f"Could not load artifact json: {artifact_path}")

        # Hardhat artifacts usually have {abi: [...], bytecode: "..."}.
        abi = art.get("abi")
        if not abi:
            raise RuntimeError(f"Artifact missing abi: {artifact_path}")

        self.abi = abi
        self.contract = self.w3.eth.contract(address=self.contract_addr, abi=abi)

        self.account = None
        if cfg.private_key:
            self.account = self.w3.eth.account.from_key(cfg.private_key)

    # -----------------------------
    # Hash helpers (mirror Solidity)
    # -----------------------------

    def computeRevealHash(
        self,
        fromGangId: int,
        fromZone: int,
        toZone: int,
        tactic: int,
        revealSalt: bytes,
    ) -> str:
        """
        Mirrors DopeModa.computeRevealHash:
        keccak256(abi.encodePacked(address(this), fromGangId, fromZone, toZone, tactic, revealSalt))
        """
        if isinstance(revealSalt, str):
            if revealSalt.startswith("0x"):
                revealSalt = bytes.fromhex(revealSalt[2:])
            else:
                revealSalt = bytes.fromhex(revealSalt)
        if len(revealSalt) != 32:
            raise ValueError("revealSalt must be 32 bytes")

        packed = self.w3.solidity_keccak(
            ["address", "uint64", "uint16", "uint16", "uint8", "bytes32"],
            [self.contract_addr, fromGangId, fromZone, toZone, tactic, revealSalt],
        )
        return "0x" + packed.hex()

