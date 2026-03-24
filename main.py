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
