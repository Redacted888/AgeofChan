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

    def encode_bytes32(self, s: str) -> bytes:
        """
        Convert an input to 32-byte value.
        - If s looks like 0x<64hex>, treat as bytes32.
        - Else treat as UTF-8 and keccak into 32 bytes (deterministic).
        """
        s = s.strip()
        if s.startswith("0x") and len(s) == 66:
            return bytes.fromhex(s[2:])
        # Deterministic from string
        return self.w3.keccak(text=s)

    # -----------------------------
    # Read helpers
    # -----------------------------

    def view_pause(self) -> bool:
        return bool(self.contract.functions.paused().call())

    def view_zone(self, zone_id: int) -> Dict[str, Any]:
        z = self.contract.functions.zoneView(zone_id).call()
        return {
            "gangId": int(z[0]),
            "level": int(z[1]),
            "defense": int(z[2]),
            "lastClaimAt": int(z[3]),
            "emblemHash": "0x" + z[4].hex(),
        }

    def view_raid(self, raid_id: int) -> Dict[str, Any]:
        r = self.contract.functions.raidView(raid_id).call()
        return {
            "raider": r[0],
            "fromGangId": int(r[1]),
            "fromZone": int(r[2]),
            "toZone": int(r[3]),
            "tactic": int(r[4]),
            "committedAt": int(r[5]),
            "sealed": "0x" + r[6].hex(),
            "potWei": int(r[7]),
            "revealed": bool(r[8]),
            "settled": bool(r[9]),
        }

    def view_gang(self, gang_id: int) -> Dict[str, Any]:
        g = self.contract.functions.getGang(gang_id).call()
        return {
            "founder": g[0],
            "handleHash": "0x" + g[1].hex(),
            "sloganHash": "0x" + g[2].hex(),
            "createdAt": int(g[3]),
            "stashWei": int(g[4]),
            "power": int(g[5]),
            "wins": int(g[6]),
            "losses": int(g[7]),
            "lastZoneActionAt": int(g[8]),
            "active": bool(g[9]),
        }

    # -----------------------------
    # Tx helpers
    # -----------------------------

    def _get_nonce(self, sender: str) -> int:
        return int(self.w3.eth.get_transaction_count(_norm_addr(sender)))

    def _estimate_gas(self, tx: Dict[str, Any]) -> int:
        try:
