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
            return int(self.w3.eth.estimate_gas(tx))
        except Exception:
            # Fallback: use a safe-ish default.
            return 400_000

    def _sign_and_send(self, tx: Dict[str, Any]) -> str:
        if not self.account:
            raise RuntimeError("No PRIVATE_KEY provided; can't sign raw tx.")

        # Ensure sender matches account
        tx_sender = tx.get("from")
        if tx_sender and _norm_addr(tx_sender) != _norm_addr(self.account.address):
            raise RuntimeError("tx 'from' doesn't match PRIVATE_KEY sender.")

        tx["from"] = self.account.address
        tx.setdefault("nonce", self._get_nonce(self.account.address))
        tx.setdefault("gas", self._estimate_gas(tx))
        tx.setdefault("gasPrice", int(self.w3.eth.gas_price))
        if "chainId" not in tx:
            tx["chainId"] = int(self.w3.eth.chain_id)

        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.rawTransaction)
        return tx_hash.hex()

    def _send_unlocked(self, tx: Dict[str, Any]) -> str:
        # Nodes that support eth_sendTransaction will fill nonce/gas.
        # This mode requires unlocked account on the node.
        payload = {k: v for k, v in tx.items() if k in ("from", "to", "data", "value", "gas")}
        # Convert ints to hex quantities for JSON-RPC
        for k in ["value", "gas"]:
            if k in payload and isinstance(payload[k], int):
                payload[k] = hex(payload[k])
        tx_hash = self.w3.provider.make_request("eth_sendTransaction", [payload]).get("result")
        if not tx_hash:
            raise RuntimeError("eth_sendTransaction failed")
        return tx_hash

    def _transact(self, fn, value_wei: int = 0) -> str:
        tx_data = fn.build_transaction({"value": value_wei})
        tx_sender = tx_data.get("from") or self.account.address if self.account else None
        tx_data["from"] = tx_sender

        if self.account:
            tx_data.pop("from", None)  # signing sets correct from
            return self._sign_and_send(tx_data)
        return self._send_unlocked(tx_data)

    # -----------------------------
    # Gameplay commands
    # -----------------------------

    def register_gang(self, handle: str, emblem_hex: str, send_value_wei: int) -> str:
        emblem = self.encode_bytes32(emblem_hex)
        tx_fn = self.contract.functions.registerGang(handle, emblem)
        return self._transact(tx_fn, value_wei=send_value_wei)

    def fund_stash(self, gang_id: int, amount_wei: int) -> str:
        tx_fn = self.contract.functions.fundStash(gang_id)
        return self._transact(tx_fn, value_wei=amount_wei)

    def set_slogan(self, gang_id: int, slogan: str) -> str:
        tx_fn = self.contract.functions.setSlogan(gang_id, slogan)
        return self._transact(tx_fn, value_wei=0)

    def train(self, gang_id: int, training_line: int, spent_wei: int) -> str:
        tx_fn = self.contract.functions.train(gang_id, training_line, spent_wei)
        return self._transact(tx_fn, value_wei=0)

    def claim_zone(self, gang_id: int, zone_id: int, emblem_hex: str, value_wei: int) -> str:
        emblem = self.encode_bytes32(emblem_hex)
        tx_fn = self.contract.functions.claimZone(gang_id, zone_id, emblem)
        return self._transact(tx_fn, value_wei=value_wei)

    def commit_raid(
        self,
        fromGangId: int,
        fromZone: int,
        toZone: int,
        tactic: int,
        reveal_salt_hex: str,
        pot_wei: int,
    ) -> Tuple[str, str]:
        """
        Commit requires `sealed` which must match computeRevealHash() later.
        We compute sealed from the given reveal salt (bytes32).
        """
        reveal_salt = bytes.fromhex(reveal_salt_hex[2:] if reveal_salt_hex.startswith("0x") else reveal_salt_hex)
        if len(reveal_salt) != 32:
            raise ValueError("reveal_salt_hex must be 32 bytes (0x + 64 hex chars)")

        sealed = self.computeRevealHash(fromGangId, fromZone, toZone, tactic, reveal_salt)
        tx_fn = self.contract.functions.commitRaid(fromGangId, fromZone, toZone, tactic, sealed, pot_wei)
        tx_hash = self._transact(tx_fn, value_wei=pot_wei)
        return tx_hash, sealed

    def reveal_raid(self, raid_id: int, reveal_salt_hex: str) -> str:
        salt_bytes = bytes.fromhex(reveal_salt_hex[2:] if reveal_salt_hex.startswith("0x") else reveal_salt_hex)
        if len(salt_bytes) != 32:
            raise ValueError("reveal_salt_hex must be 32 bytes (0x + 64 hex chars)")
        tx_fn = self.contract.functions.revealRaid(raid_id, salt_bytes)
        return self._transact(tx_fn, value_wei=0)

    def withdraw(self, gang_id: int) -> str:
        tx_fn = self.contract.functions.withdrawGang(gang_id)
        return self._transact(tx_fn, value_wei=0)

    # -----------------------------
    # CLI layer
    # -----------------------------

    def run(self, argv: Optional[List[str]] = None) -> int:
        argv = argv if argv is not None else sys.argv[1:]

        p = argparse.ArgumentParser(prog="AgeofChan", description="Gang CLI for DopeModa")
        p.add_argument("--rpc", default=os.environ.get("RPC_URL", DEFAULT_RPC))
        p.add_argument("--contract", required=True, help="DopeModa deployed contract address")
        p.add_argument("--artifact", default=None, help="Hardhat artifact path with abi")
        p.add_argument("--pk", default=os.environ.get("PRIVATE_KEY"), help="Private key for signing (optional)")

        sub = p.add_subparsers(dest="cmd", required=True)

        sub.add_parser("pause", help="Show paused state")

        sp = sub.add_parser("view-zone")
        sp.add_argument("--zone", type=int, required=True)

        sp = sub.add_parser("view-raid")
        sp.add_argument("--raid", type=int, required=True)

        sp = sub.add_parser("view-gang")
        sp.add_argument("--gang", type=int, required=True)

        sp = sub.add_parser("register")
        sp.add_argument("--handle", required=True)
        sp.add_argument("--emblem", required=True, help="bytes32 hex (0x..64hex) or any string seed")
        sp.add_argument("--value-wei", type=int, required=True)

        sp = sub.add_parser("fund")
        sp.add_argument("--gang", type=int, required=True)
        sp.add_argument("--amount-wei", type=int, required=True)

        sp = sub.add_parser("slogan")
        sp.add_argument("--gang", type=int, required=True)
        sp.add_argument("--text", required=True)

        sp = sub.add_parser("train")
        sp.add_argument("--gang", type=int, required=True)
        sp.add_argument("--line", type=int, required=True)
        sp.add_argument("--spent-wei", type=int, required=True)

        sp = sub.add_parser("claim")
        sp.add_argument("--gang", type=int, required=True)
        sp.add_argument("--zone", type=int, required=True)
        sp.add_argument("--emblem", required=True)
        sp.add_argument("--value-wei", type=int, required=True)

        sp = sub.add_parser("commit-raid")
        sp.add_argument("--from-gang", type=int, required=True)
        sp.add_argument("--from-zone", type=int, required=True)
        sp.add_argument("--to-zone", type=int, required=True)
        sp.add_argument("--tactic", type=int, required=True)
        sp.add_argument("--salt-hex", required=True, help="0x + 64 hex chars (bytes32)")
        sp.add_argument("--pot-wei", type=int, required=True)

        sp = sub.add_parser("reveal-raid")
        sp.add_argument("--raid", type=int, required=True)
        sp.add_argument("--salt-hex", required=True, help="0x + 64 hex chars (bytes32)")

        sp = sub.add_parser("withdraw")
        sp.add_argument("--gang", type=int, required=True)

        # -----------------------------
        # Offline simulation commands
        # -----------------------------
        sp = sub.add_parser("sim-demo")
        sp.add_argument("--seed", type=int, default=1337)
        sp.add_argument("--turns", type=int, default=10)
        sp.add_argument("--from-zone", type=int, default=10)
        sp.add_argument("--to-zone", type=int, default=11)
        sp.add_argument("--pot-wei", type=int, default=10**15)
        sp.add_argument("--attacker-power-seed", type=int, default=7)
        sp.add_argument("--defender-power-seed", type=int, default=13)
        sp.add_argument("--attacker-stash-wei", type=int, default=10**18)
        sp.add_argument("--defender-stash-wei", type=int, default=10**18)

        sp = sub.add_parser("sim-route")
        sp.add_argument("--from-zone", type=int, required=True)
        sp.add_argument("--to-zone", type=int, required=True)
        sp.add_argument("--max-hops", type=int, default=16)

        sp = sub.add_parser("sim-plan-raid")
        sp.add_argument("--seed", type=int, default=2026)
        sp.add_argument("--from-zone", type=int, default=12)
        sp.add_argument("--to-zone", type=int, default=13)
        sp.add_argument("--pot-wei", type=int, default=10**15)
        sp.add_argument("--attacker-power-seed", type=int, default=9)
        sp.add_argument("--defender-power-seed", type=int, default=17)
        sp.add_argument("--attacker-stash-wei", type=int, default=10**18)
        sp.add_argument("--defender-stash-wei", type=int, default=10**18)

        args = p.parse_args(argv)

        # Commands
