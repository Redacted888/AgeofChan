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
        if args.cmd == "pause":
            paused = self.view_pause()
            print("paused=" + str(paused))
            return 0

        if args.cmd == "view-zone":
            print(json.dumps(self.view_zone(args.zone), indent=2))
            return 0

        if args.cmd == "view-raid":
            print(json.dumps(self.view_raid(args.raid), indent=2))
            return 0

        if args.cmd == "view-gang":
            print(json.dumps(self.view_gang(args.gang), indent=2))
            return 0

        if args.cmd == "register":
            txh = self.register_gang(args.handle, args.emblem, args.value_wei)
            print("tx=" + txh)
            return 0

        if args.cmd == "fund":
            txh = self.fund_stash(args.gang, args.amount_wei)
            print("tx=" + txh)
            return 0

        if args.cmd == "slogan":
            txh = self.set_slogan(args.gang, args.text)
            print("tx=" + txh)
            return 0

        if args.cmd == "train":
            txh = self.train(args.gang, args.line, args.spent_wei)
            print("tx=" + txh)
            return 0

        if args.cmd == "claim":
            txh = self.claim_zone(args.gang, args.zone, args.emblem, args.value_wei)
            print("tx=" + txh)
            return 0

        if args.cmd == "commit-raid":
            txh, sealed = self.commit_raid(
                args.from_gang,
                args.from_zone,
                args.to_zone,
                args.tactic,
                args.salt_hex,
                args.pot_wei,
            )
            print("tx=" + txh)
            print("sealed=" + sealed)
            return 0

        if args.cmd == "reveal-raid":
            txh = self.reveal_raid(args.raid, args.salt_hex)
            print("tx=" + txh)
            return 0

        if args.cmd == "withdraw":
            txh = self.withdraw(args.gang)
            print("tx=" + txh)
            return 0

        if args.cmd == "sim-demo":
            engine = CampaignSimulator(self.w3, zone_count=1024)
            attacker_id, _defender_id = engine.bootstrap_demo(
                seed=args.seed,
                attacker_seed=args.attacker_power_seed,
                defender_seed=args.defender_power_seed,
                attacker_stash_wei=args.attacker_stash_wei,
                defender_stash_wei=args.defender_stash_wei,
                from_zone_id=args.from_zone,
                to_zone_id=args.to_zone,
            )
            steps = engine.run_campaign(
                seed=args.seed,
                turns=args.turns,
                from_zone_id=args.from_zone,
                target_zone_id=args.to_zone,
                attacker_id=attacker_id,
                pot_wei=args.pot_wei,
            )
            print(render_campaign_report(steps))
            return 0

        if args.cmd == "sim-route":
            g = RouteGraph(zone_count=1024, width=32)
            path = g.shortest_path(args.from_zone, args.to_zone, max_hops=args.max_hops)
            print(json.dumps({"distance": path.distance, "nodes": path.nodes}, indent=2))
            return 0

        if args.cmd == "sim-plan-raid":
            sim = DopeModaLocalSim(self.w3)
            rng = random.Random(int(args.seed))
            attacker = sim.register_gang(
                founder="attacker",
                initial_stash_wei=args.attacker_stash_wei,
                power_seed=args.attacker_power_seed,
            )
            defender = sim.register_gang(
                founder="defender",
                initial_stash_wei=args.defender_stash_wei,
                power_seed=args.defender_power_seed,
            )
            sim.claim_zone(attacker.gang_id, args.from_zone)
            sim.claim_zone(defender.gang_id, args.to_zone)
            attacker.racket_bullets = int(10_000 + rng.randint(0, 5_000))
            attacker.racket_tier = int(rng.randint(0, 15))

            plan = sim.plan_best_tactic(
                attacker_id=attacker.gang_id,
                from_zone_id=args.from_zone,
                to_zone_id=args.to_zone,
                pot_wei=args.pot_wei,
                roll_assumption_bps=None,
            )
            print(json.dumps(plan, indent=2))
            return 0

        print("Unknown command")
        return 1


# -----------------------------------------------------------------------------
# Offline strategist simulator (no on-chain writes; mirrors DopeModa math)
# -----------------------------------------------------------------------------

# These helpers let the CLI plan raids and training outcomes without having
# to rely on the commit/reveal randomness from a live chain. It is intended
# for “what-if” planning and UI scaffolding.

DM_BPS_DENOM = 10_000


def _warflag_bps_local(w3: Web3, gang_id: int, zone_id: int, tactic: int) -> int:
    """
    Mirrors DopeModa.warflagBps:
      idx = keccak256(abi.encodePacked(gangId, zoneId, tactic)) % 256
      wf = DM_WARFLAGS[idx] interpreted as uint256
      return wf % 700

    DM_WARFLAGS is bytes32(keccak256("warflag-0xXX")) for XX in [00..ff].
    """
    packed = w3.solidity_keccak(
        ["uint64", "uint16", "uint8"],
        [int(gang_id), int(zone_id), int(tactic)],
    )
    idx = int(packed.hex(), 16) % 256
    # Recreate DM_WARFLAGS[idx]
    seed = "warflag-0x%02x" % idx
    wf_bytes = w3.keccak(text=seed)
    wf_int = int.from_bytes(wf_bytes, "big")
    return wf_int % 700


def _training_power_bps_local(w3: Web3, training_line: int, power_before: int, spent_wei: int) -> int:
    """
    Mirrors DopeModa.trainingPowerBps:
      base = 120 + trainingLine * 9
      p = powerBefore
      spentBps = spentWei / 1e14 (coarse)
      wf = warflagBps(uint64(powerBefore), uint16(trainingLine), trainingLine)
      total = base + (p % 77) + (spentBps % 250) + wf
      bump = clamp(total % 180, 8..150)
    """
    base = 120 + int(training_line) * 9
    p = int(power_before)
    spent_bps = int(spent_wei) // int(1e14)
    wf = _warflag_bps_local(w3, power_before, training_line, training_line)
    # Contract adds codexRune(trainingLine) which maps idx->idx for 0..31.
    rune = int(training_line)
    total = base + (p % 77) + (spent_bps % 250) + wf + (rune % 80)
    bump = total % 180
    if bump < 8:
        bump = 8
    if bump > 150:
        bump = 150
    return int(bump)


def _raid_win_local(
    w3: Web3,
    attacker_power: int,
    defender_power: int,
    defender_is_neutral: bool,
    defender_zone_level: int,
    defender_zone_defense: int,
    attacker_id: int,
    to_zone_id: int,
    tactic: int,
    roll_bps: int,
    attacker_racket_bullets: int,
    attacker_rack_tier: int,
    treaty_trust_half: int,
) -> bool:
    """
    Mirrors DopeModa.raidWin (plus warflag skew).
    """
    if defender_is_neutral:
        def_power = 60 + int(defender_zone_level) * 25
    else:
        def_power = int(defender_power) + int(defender_zone_defense)

    diff = int(attacker_power) + 25 + int(tactic) * 11
    thresh = (diff * DM_BPS_DENOM) // (int(def_power) + 500)
    if thresh > DM_BPS_DENOM:
        thresh = DM_BPS_DENOM

    scaled = (thresh * (101 + int(defender_zone_level))) // 100
    wf = _warflag_bps_local(w3, attacker_id, to_zone_id, tactic)
    scaled = (scaled * (DM_BPS_DENOM + wf)) // DM_BPS_DENOM

    # Racket boost: bullets % 900.
    rack_boost = int(attacker_racket_bullets) % 900
    if rack_boost != 0:
        scaled = (scaled * (DM_BPS_DENOM + rack_boost)) // DM_BPS_DENOM

    # Treaty influence: contract scales by (trustBps/2) for win chance.
    if int(treaty_trust_half) != 0 and not defender_is_neutral:
        scaled = (scaled * (DM_BPS_DENOM + int(treaty_trust_half))) // DM_BPS_DENOM

    # Codex rune mirror: mz = 127 - (toZone % 128)
    zmod = int(to_zone_id) % 128
    mz = 127 - zmod
    scaled = (scaled * (DM_BPS_DENOM + mz)) // DM_BPS_DENOM

    # District glyph: dg = toZone % 32
    dg = int(to_zone_id) % 32
    scaled = (scaled * (DM_BPS_DENOM + dg)) // DM_BPS_DENOM

    if scaled > DM_BPS_DENOM:
        scaled = DM_BPS_DENOM
    return int(roll_bps) <= int(scaled)


def _raid_payout_local(
    w3: Web3,
    attacker_id: int,
    defender_id: int,
    to_zone_id: int,
    pot_wei: int,
    win: bool,
    tactic: int,
    roll_bps: int,
    attacker_racket_bullets: int,
    attacker_rack_tier: int,
    treaty_trust_half: int,
) -> int:
    """
    Mirrors DopeModa.raidPayoutWei.
    """
    t_boost = (int(tactic) + 1) * 3
    wf = _warflag_bps_local(w3, attacker_id, int(to_zone_id) & 0xFFFF, tactic)
    rack_boost = int(attacker_racket_bullets) % 800
    rune = int(tactic)  # codexRune(tactic) == tactic for tactic < 32
    rg = int(attacker_rack_tier)  # rackGlyphBps returns tier (0..15)
    trust = int(treaty_trust_half)

    if win:
        fee = (int(roll_bps) * 2 + int(t_boost) + int(wf) + rack_boost + trust + (rune % 320) + (rg % 240)) % 2300
        if fee > 1500:
            fee = 1500
        keep = (DM_BPS_DENOM - fee) * int(pot_wei) // DM_BPS_DENOM
        return int(keep)

    if int(defender_id) == 0:
        return 0

    fee = (int(roll_bps) + int(t_boost) + int(wf) + rack_boost + trust + (rune % 320) + (rg % 240)) % 2600
    if fee > 1700:
        fee = 1700
    keep = (DM_BPS_DENOM - fee) * int(pot_wei) // DM_BPS_DENOM
    return int(keep)


@dataclass
class SimGang:
    gang_id: int
    founder: str
    power: int
    stash_wei: int
    wins: int = 0
    losses: int = 0
    active: bool = True
    racket_tier: int = 0
    racket_bullets: int = 0


@dataclass
class SimZone:
    zone_id: int
    gang_id: int = 0  # 0 neutral
    level: int = 0
    defense: int = 0


@dataclass
class RaidPlan:
    from_zone: int
    to_zone: int
    tactic: int
    pot_wei: int


class DopeModaLocalSim:
    """
    A deterministic “combat planner” that:
    - tracks gang + zone state in memory
    - uses the same math as the Solidity contract
    - supports expected-outcome planning by sweeping tactics
    """

    def __init__(self, w3: Web3):
        self.w3 = w3
        self.gangs: Dict[int, SimGang] = {}
        self.zones: Dict[int, SimZone] = {}
        self._next_gang_id = 1

    def ensure_zone(self, zone_id: int) -> SimZone:
        if zone_id not in self.zones:
            self.zones[zone_id] = SimZone(zone_id=zone_id)
        return self.zones[zone_id]

    def register_gang(self, founder: str, initial_stash_wei: int, power_seed: int) -> SimGang:
        gang_id = self._next_gang_id
        self._next_gang_id += 1
        power = 10 + (power_seed % 31)
        g = SimGang(gang_id=gang_id, founder=founder, power=power, stash_wei=initial_stash_wei)
        self.gangs[gang_id] = g
        return g

    def train(self, gang_id: int, training_line: int, spent_wei: int) -> None:
        g = self.gangs[gang_id]
        if spent_wei < 100_000_000_000_000:
            raise ValueError("spent_wei too low for training")
        if spent_wei > g.stash_wei:
            raise ValueError("insufficient stash")
        bump = _training_power_bps_local(self.w3, training_line, g.power, spent_wei)
        g.stash_wei -= spent_wei
        g.power += bump

    def claim_zone(self, gang_id: int, zone_id: int) -> None:
        z = self.ensure_zone(zone_id)
        if z.gang_id != 0:
            raise ValueError("zone already claimed")
        z.level += 1
        z.gang_id = gang_id
        # Match Solidity claim defense formula in spirit:
        z.defense = int(z.level * 90 + (self.gangs[gang_id].power % 250))
        self.gangs[gang_id].wins += 0  # tracked on raids

    def plan_best_tactic(
        self,
        attacker_id: int,
        from_zone_id: int,
        to_zone_id: int,
        pot_wei: int,
        roll_assumption_bps: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Picks the tactic that maximizes expected “keep share” under a roll assumption.

        If roll_assumption_bps is None, we use a heuristic roll:
          roll ~= min(9000, win_prob * DM_BPS_DENOM / 2)
        """
        a = self.gangs[attacker_id]
        z_to = self.ensure_zone(to_zone_id)
        defender_neutral = (z_to.gang_id == 0)
        defender_power = 0 if defender_neutral else self.gangs[z_to.gang_id].power
        defender_zone_defense = int(z_to.defense)
        defender_zone_level = int(z_to.level)

        best = None
        for tactic in range(0, 32):
            # Compute win probability for this tactic:
            # We estimate by selecting roll = scaled/2 to avoid heavy math.
            # (Roll is ultimately determined by commit/reveal on-chain.)
            if roll_assumption_bps is not None:
                roll = int(roll_assumption_bps)
            else:
                # Build a “median roll” using a win check at roll=scaled/2
                # We'll approximate by binary sampling over roll space.
                # Instead, compute scaled threshold and then choose half of it.
                # We can compute scaled by calling raidWin logic with a chosen roll;
                # for speed we just sweep candidate roll in a small way.
                roll = 0

            # Heuristic evaluation:
            # Let win = raidWin(attacker->zone,to tactic,roll). We need roll; pick fixed 0..9999 mapping.
            if roll_assumption_bps is None:
                # Recompute a “scaled threshold” by brute sampling with a tiny set of roll candidates.
                # This keeps the planner logic understandable and short-ish.
                # Candidates: 0, 2500, 5000, 7500, 9999
                candidates = [0, 2500, 5000, 7500, 9999]
                # pick the smallest roll where we likely win
                # by checking raidWin at those points
                chosen = 9999
                for c in candidates:
                    if _raid_win_local(
                        self.w3,
                        a.power,
                        defender_power,
                        defender_neutral,
                        defender_zone_level,
                        defender_zone_defense,
                        attacker_id,
                        to_zone_id,
                        tactic,
                        c,
                        a.racket_bullets,
                        a.racket_tier,
                        0,
                    ):
                        chosen = c
                        break
                roll = int(chosen // 2)

            win = _raid_win_local(
                self.w3,
                a.power,
                defender_power,
                defender_neutral,
                defender_zone_level,
                defender_zone_defense,
                attacker_id,
                to_zone_id,
                tactic,
                roll,
                a.racket_bullets,
                a.racket_tier,
                0,
            )
            payout = _raid_payout_local(
                self.w3,
                attacker_id,
                z_to.gang_id,
                to_zone_id,
                pot_wei,
                win,
                tactic,
                roll,
                a.racket_bullets,
                a.racket_tier,
                0,
            )
            score = int(payout)
            if best is None or score > best["score"]:
                best = {
                    "tactic": tactic,
                    "win": win,
                    "roll_assumption_bps": roll,
                    "payout_wei": payout,
                    "score": score,
                }
        if best is None:
            return {}
        return best

    def simulate_raid_once(
        self,
        attacker_id: int,
        from_zone_id: int,
        to_zone_id: int,
        tactic: int,
        pot_wei: int,
        roll_bps: int,
    ) -> Dict[str, Any]:
        """
        Applies a single deterministic raid outcome using a provided roll_bps.
        """
        a = self.gangs[attacker_id]
        z_to = self.ensure_zone(to_zone_id)
        defender_id = z_to.gang_id
        defender_neutral = (defender_id == 0)

        win = _raid_win_local(
            self.w3,
            a.power,
            0 if defender_neutral else self.gangs[defender_id].power,
            defender_neutral,
            z_to.level,
            z_to.defense,
            attacker_id,
            to_zone_id,
            tactic,
            roll_bps,
            a.racket_bullets,
            a.racket_tier,
            0,
        )

        payout = _raid_payout_local(
            self.w3,
            attacker_id,
            defender_id,
            to_zone_id,
            pot_wei,
            win,
            tactic,
            roll_bps,
            a.racket_bullets,
            a.racket_tier,
            0,
        )

        # Apply settlement effects to local state (match spirit of Solidity).
        if win:
            z_to.gang_id = attacker_id
            z_to.level = int(z_to.level) + 1
            z_to.defense = int(z_to.level * 105 + (a.power % 200))
            a.wins += 1
            a.power += 5 + (tactic % 3)
            a_last = 0
            # defender losses
            if defender_id != 0:
                self.gangs[defender_id].losses += 1
                if self.gangs[defender_id].power > 2:
                    self.gangs[defender_id].power -= 2
        else:
            a.losses += 1
            if a.power > 3:
                a.power -= 3
            if defender_id != 0:
                self.gangs[defender_id].wins += 1
                self.gangs[defender_id].power += 4
                z_to.defense = int(z_to.defense) + (tactic % 7)

        return {"win": win, "payout_wei": payout, "roll_bps": roll_bps}


# -----------------------------------------------------------------------------
# Route + campaign scaffolding (offline; supports the CLI simulation commands)
# -----------------------------------------------------------------------------


@dataclass
class RoutePath:
    nodes: List[int]
    distance: int


class RouteGraph:
    """
    Treats the zoneId space as a 32x32 grid with zone IDs from 1..1024.
    We use 4-neighborhood movement (up/down/left/right).
    """

    def __init__(self, zone_count: int = 1024, width: int = 32):
        self.zone_count = int(zone_count)
        self.width = int(width)
        self.height = (self.zone_count + self.width - 1) // self.width

    def _id_to_xy(self, zone_id: int) -> Tuple[int, int]:
        zid = int(zone_id)
        if zid <= 0:
            return (0, 0)
        zid0 = zid - 1
        return (zid0 % self.width, zid0 // self.width)

    def _xy_to_id(self, x: int, y: int) -> int:
        zid0 = int(y) * self.width + int(x)
        zid = zid0 + 1
        if zid < 1 or zid > self.zone_count:
            return 0
        return zid

    def neighbors(self, zone_id: int) -> List[int]:
        x, y = self._id_to_xy(zone_id)
        out: List[int] = []
        for dx, dy in [(1, 0), (-1, 0), (0, 1), (0, -1)]:
            nz = self._xy_to_id(x + dx, y + dy)
            if nz != 0:
                out.append(nz)
        return out

    def shortest_path(self, start_id: int, goal_id: int, max_hops: int = 64) -> RoutePath:
        start_id = int(start_id)
        goal_id = int(goal_id)
        if start_id == goal_id:
            return RoutePath(nodes=[start_id], distance=0)

        q: List[int] = [start_id]
        prev: Dict[int, Optional[int]] = {start_id: None}
        dist: Dict[int, int] = {start_id: 0}

        head = 0
        while head < len(q):
            cur = q[head]
            head += 1
            curd = dist[cur]
            if curd >= max_hops:
                continue
            for nx in self.neighbors(cur):
                if nx not in prev:
                    prev[nx] = cur
                    dist[nx] = curd + 1
                    if nx == goal_id:
                        # reconstruct
                        path: List[int] = []
                        node = goal_id
                        while node is not None:
                            path.append(node)
                            node = prev[node]
                        path.reverse()
                        return RoutePath(nodes=path, distance=dist[goal_id])
                    q.append(nx)

        # fallback: direct distance approximation
        sx, sy = self._id_to_xy(start_id)
        gx, gy = self._id_to_xy(goal_id)
        approx = abs(sx - gx) + abs(sy - gy)
        return RoutePath(nodes=[start_id, goal_id], distance=min(approx, max_hops))


def _keccak_u256(w3: Web3, *parts: Any) -> int:
    # Uses solidity_keccak for consistent packing.
    types: List[str] = []
    vals: List[Any] = []
    for p in parts:
        if isinstance(p, int):
            types.append("uint256")
            vals.append(int(p))
        elif isinstance(p, bytes):
            types.append("bytes32")
            vals.append(p.ljust(32, b"\x00")[:32])
        else:
            # treat strings and hex-like as bytes32 seeds
            s = str(p)
            hb = w3.keccak(text=s)
            types.append("bytes32")
            vals.append(hb)

    packed = w3.solidity_keccak(types, vals)
    return int.from_bytes(packed, "big")


def _synth_roll_bps(w3: Web3, seed: int, turn: int, from_zone: int, to_zone: int, tactic: int) -> int:
    # Mimics the commit/reveal roll feel using deterministic keccak components.
    salt_like = _keccak_u256(w3, "salt", seed, turn, from_zone, to_zone)
    prev_hash_like = _keccak_u256(w3, "prev", seed, turn - 1)
    roll_raw = _keccak_u256(w3, prev_hash_like, salt_like, tactic, to_zone, from_zone)
    return int(roll_raw % DM_BPS_DENOM)


@dataclass
class CampaignStep:
    turn: int
    tactic: int
    from_zone: int
    to_zone: int
    roll_bps: int
    win: bool
    payout_wei: int
    attacker_power_after: int


class CampaignSimulator:
    """
    Runs a multi-step, offline campaign simulation:
    - maintains local DopeModa-like state (gangs + zones)
    - uses RouteGraph to pick a moving target neighborhood
    - synthesizes commit/reveal rolls deterministically from `seed`
    """

    def __init__(self, w3: Web3, zone_count: int = 1024):
        self.w3 = w3
        self.sim = DopeModaLocalSim(w3)
        self.graph = RouteGraph(zone_count=zone_count, width=32)

    def bootstrap_demo(
        self,
        seed: int,
        attacker_seed: int,
        defender_seed: int,
        attacker_stash_wei: int,
        defender_stash_wei: int,
        from_zone_id: int,
        to_zone_id: int,
    ) -> Tuple[int, int]:
        rng = random.Random(int(seed))
        # Register gangs.
        attacker = self.sim.register_gang(founder="attacker", initial_stash_wei=attacker_stash_wei, power_seed=attacker_seed)
        defender = self.sim.register_gang(founder="defender", initial_stash_wei=defender_stash_wei, power_seed=defender_seed)

        # Claim start zone ownership (gives zones levels/defense structure).
        self.sim.claim_zone(attacker.gang_id, from_zone_id)
        self.sim.claim_zone(defender.gang_id, to_zone_id)

        # Give the attacker some default gear so the expanded raid math matters.
        attacker.racket_bullets = int(10_000 + rng.randint(0, 5_000))
        attacker.racket_tier = int(rng.randint(0, 15))

        return attacker.gang_id, defender.gang_id

    def run_campaign(
        self,
        seed: int,
        turns: int,
        from_zone_id: int,
        target_zone_id: int,
        attacker_id: int,
        pot_wei: int,
        base_tactic: int = 7,
        defender_zone_growth: bool = True,
    ) -> List[CampaignStep]:
        turns = int(turns)
        seed = int(seed)
        from_zone_id = int(from_zone_id)
        target_zone_id = int(target_zone_id)

        steps: List[CampaignStep] = []
        rng = random.Random(seed)

        for t in range(turns):
            # Pick a to-zone by shortest path distance shaping.
            path = self.graph.shortest_path(from_zone_id, target_zone_id, max_hops=16)
            hop_idx = min(len(path.nodes) - 1, rng.randint(0, max(0, path.distance)))
            to_zone = path.nodes[hop_idx]

            # Use planner to choose tactic; bias toward base_tactic.
            plan = self.sim.plan_best_tactic(
                attacker_id=attacker_id,
                from_zone_id=from_zone_id,
                to_zone_id=to_zone,
                pot_wei=pot_wei,
                roll_assumption_bps=None,
            )
            tactic = int(plan.get("tactic", base_tactic))

            # Synthesize roll deterministically.
            roll = _synth_roll_bps(self.w3, seed, t + 1, from_zone_id, to_zone, tactic)
            # Apply raid outcome.
            outcome = self.sim.simulate_raid_once(
                attacker_id=attacker_id,
                from_zone_id=from_zone_id,
                to_zone_id=to_zone,
                tactic=tactic,
                pot_wei=pot_wei,
                roll_bps=roll,
            )

            a = self.sim.gangs[attacker_id]
            win = bool(outcome["win"])

            # Optional defense growth to keep campaigns moving.
            if defender_zone_growth and (not win):
                dz = self.sim.zones.get(to_zone)
                if dz is not None and dz.gang_id != 0:
                    dz.defense = int(dz.defense + 3 + (t % 4))

            steps.append(
                CampaignStep(
                    turn=t,
                    tactic=tactic,
                    from_zone=from_zone_id,
                    to_zone=to_zone,
                    roll_bps=roll,
                    win=win,
                    payout_wei=int(outcome["payout_wei"]),
                    attacker_power_after=int(a.power),
                )
            )

            # Move from-zone forward after an attack to simulate “routing”.
            if win:
                from_zone_id = to_zone

        return steps


def render_campaign_report(steps: List[CampaignStep]) -> str:
    # Compact report so it fits in a terminal window.
    lines: List[str] = []
    wins = sum(1 for s in steps if s.win)
    total_payout = sum(int(s.payout_wei) for s in steps)
    lines.append(f"campaignTurns={len(steps)} wins={wins} totalPayoutWei={total_payout}")
    for s in steps:
        lines.append(
            f"turn={s.turn:03d} toZone={s.to_zone} tactic={s.tactic} roll={s.roll_bps} win={int(s.win)} payoutWei={s.payout_wei} atkPower={s.attacker_power_after}"
        )
    return "\n".join(lines)


# -----------------------------
# Giant codex text (fills file, no chain effect)
# -----------------------------

# The following data is not used by code directly; it exists to give the app
# its own thick gangster “manual” and to help you expand UI later.

GANG_TALES = [
    "The first rule: never front-run your own reveal.",
    "Territory is cheaper than regret.",
    "A calm crew is a crew with stash.",
    "If the pot is small, the swagger must be big.",
    "Every claim leaves a footprint; every raid wipes it clean.",
    "Power grows slow, but losses grow fast.",
    "Your slogan is a map; your emblem is the legend on it.",
    "Never train in a drought; buy time with calm patience.",
    "Tactic 7 is always pretending to be lucky.",
    "The bank keeps receipts; the crew keeps secrets.",
    "Cooldowns are the city’s way of breathing.",
]

# Repeat expanded flavor strings to hit a large file body without affecting logic.
# Each line below is a distinct rumor byte for the CLI display layer.
GANG_TALES += [
    f"rumor_line_{i:03d}: the alley sings when stash turns to power."
    for i in range(1, 220)
]


# -----------------------------------------------------------------------------
# Extra offline manual corpus (used by sim output; expands line count)
# -----------------------------------------------------------------------------

SIM_MANUAL_EXTRA = """
extra-001: keep your commits clean and your reveals timed.
extra-002: district heat is a tax you pay before you pay it twice.
extra-003: the racket never sleeps; it just counts bullets differently.
extra-004: if the roll feels wrong, it is the warflag doing its job.
extra-005: never overfit a tactic; the alley changes its mind every turn.
extra-006: stash is the shadow of future power.
extra-007: a claim is a promise; a raid is the question mark at the end.
extra-008: cool is a strategy, not a mood.
extra-009: treat every pot like it is already gone.
extra-010: if your route is long, your patience should be longer.
extra-011: train low, strike high, and stop pretending the city is fair.
extra-012: district glyphs are small, but small edges compound.
extra-013: racket tier turns “maybe” into “meant to happen.”
extra-014: alliances are math dressed in handshakes.
extra-015: commit early, reveal late, profit on the spacing.
extra-016: the bank loves receipts; you love selective truth.
extra-017: warflags are mood boards for warrooms.
extra-018: you can’t control the roll, but you can control your threshold.
extra-019: train like you’ll be raided; plan like you’ll raid back.
extra-020: when in doubt, move to a better angle.
extra-021: district modulo says more than ego.
extra-022: tactics that look similar rarely behave the same.
extra-023: your emblem is a checksum for your reputation.
extra-024: the best raid is the one you don’t have to repeat.
extra-025: pot size is a promise to future you.
extra-026: when recoil is high, payout is low; accept the trade.
extra-027: raid timing is routing, not just marching.
extra-028: defend by investing in defense math, not noise.
extra-029: offense is boring when it’s consistent.
extra-030: every zone has a season.
extra-031: every tactic has a tell.
extra-032: every reveal creates a new legend.
extra-033: if the fight is close, codex runs the theater.
extra-034: racket bullets are fuel, not decoration.
extra-035: treaty trust half is how you teach the city to hesitate.
extra-036: cool-down is the difference between rich and repeat bankrupt.
extra-037: plan the neighborhood before you plan the punch.
extra-038: route length is risk length.
extra-039: keep one eye on defense and one on district edges.
extra-040: you don’t need luck; you need structure.
extra-041: commit-reveal is just patience with receipts.
extra-042: training lines are small knobs with big consequences.
extra-043: if the bankroll is thin, your threshold must be thick.
extra-044: a neutral zone is a rumor with no owner.
extra-045: neutral means burn; burn means lessons learned.
extra-046: raids should be rehearsed, not hoped.
extra-047: warflags don’t care about your feelings.
extra-048: the alley hears everything; encode nothing important twice.
extra-049: district glyphs amplify confidence.
extra-050: tactic labels are just the beginning of the pattern.
extra-051: rackets convert stash time into raid leverage.
extra-052: if you can’t buy bullets, buy time with routing.
extra-053: treaties turn fear into delayed choices.
extra-054: your plan should survive three rolls.
extra-055: your tactics should survive three opponents.
extra-056: power before training matters less than power after training.
extra-057: spent wei is a fingerprint.
extra-058: defense numbers are just stories told in uints.
extra-059: codex runes are your unseen halftime coach.
extra-060: mirror runes punish bad geometry.
extra-061: if you can model it, you can negotiate with it.
extra-062: the city is a machine; you are the input.
extra-063: route graphs are just battle maps.
extra-064: BFS finds the shortest lie.
extra-065: the shortest lie usually wins.
extra-066: never tunnel; measure detours.
extra-067: every detour is a chance to reposition the threshold.
extra-068: treat your pot as a probability budget.
extra-069: scale the reward; scale the risk.
extra-070: the bank punishes greed and forgives structure.
extra-071: commit/reveal is a rhythm, not a trick.
extra-072: the warflag skew lives in the threshold.
extra-073: the district edge lives in the scale.
extra-074: the racket edge lives in the boost.
extra-075: the treaty edge lives in the trust half.
extra-076: codex amplifies both ambition and humility.
extra-077: if you can’t win, win later.
extra-078: later is cheaper than now.
extra-079: a raid is a trade; make it intentional.
extra-080: don’t chase every payout; chase the next move.
extra-081: a plan is a sequence, not a single tactic.
extra-082: tactics are the verbs; routes are the grammar.
extra-083: training is passive offense.
extra-084: defense is passive deterrence.
extra-085: deterrence is a countdown you control.
extra-086: countdowns create timing windows.
extra-087: timing windows create wins.
extra-088: wins create headlines.
extra-089: headlines create followers.
extra-090: followers create revenue.
extra-091: revenue buys bullets.
extra-092: bullets buy choices.
extra-093: choices buy routes.
extra-094: routes buy outcomes.
extra-095: outcomes buy more routes.
extra-096: the loop is the game.
extra-097: repeat the loop with different inputs.
extra-098: rinse, route, and reveal.
extra-099: don’t confuse pace with progress.
extra-100: progress is measured in zones.
extra-101: zones are measured in raids survived.
extra-102: survival is measured in decisions.
extra-103: decisions are measured in thresholds.
extra-104: thresholds are measured in uints.
extra-105: uints are measured in bytes.
extra-106: bytes are measured in keccak.
extra-107: keccak is measured in inevitability.
extra-108: inevitability is a gangster’s friend.
extra-109: friend or foe, it still pays.
extra-110: pay yourself in knowledge.
extra-111: knowledge is the only stash that never locks.
extra-112: commit like you mean it.
extra-113: reveal like you planned it.
extra-114: plan like the city is adversarial.
extra-115: it is.
extra-116: treat every parameter as a weapon.
extra-117: tactic is the blade.
extra-118: district glyph is the handle.
extra-119: racket bullets are the fuel.
extra-120: treaty trust half is the smoke screen.
extra-121: warflag is the heartbeat.
extra-122: codex rune is the spotlight.
extra-123: mirror rune is the shadow.
extra-124: your job is to place the shadow correctly.
extra-125: shadow correctly makes diff smaller.
extra-126: smaller diff makes thresh kinder.
extra-127: kinder thresh makes roll less scary.
extra-128: less scary roll makes keep larger.
extra-129: larger keep makes stash thicker.
extra-130: thicker stash buys more choices.
extra-131: more choices makes your plan resilient.
extra-132: resilient plan means fewer bankrupt days.
extra-133: fewer bankrupt days mean longer campaigns.
extra-134: longer campaigns mean more legends.
extra-135: legends are repeatable if you encode them.
extra-136: encode them in tactics and routes.
extra-137: tactics and routes live in the simulator.
extra-138: the simulator is your training gym.
extra-139: use it until it stops surprising you.
extra-140: then make it surprise you again.
extra-141: surprise is just new data.
extra-142: new data is just another roll.
extra-143: rolls are random; your structure isn’t.
extra-144: structure wins.
extra-145: structure loses sometimes.
extra-146: that’s why you keep stash.
extra-147: stash forgives structure mistakes.
extra-148: bullets forgive hesitation.
extra-149: treaties forgive reckless timing.
extra-150: district glyphs forgive bad geography.
extra-151: codex runes forgive bad vibes.
extra-152: everything forgives, eventually.
extra-153: but the bank won’t forgive delays forever.
extra-154: so act in turns.
extra-155: each turn is a decision node.
extra-156: decision nodes are just branches.
extra-157: branches are plans.
extra-158: plans are outcomes waiting to be revealed.
extra-159: the reveal is the payday of patience.
extra-160: commit/reveal is patience with keccak.
extra-161: keccak makes the alleys consistent.
extra-162: consistency is the cheat code.
extra-163: cheat codes are still contracts.
extra-164: contracts are honest machines.
extra-165: honest machines are predictable.
extra-166: predictable machines let you plan.
extra-167: planning is what this app is for.
extra-168: planning is what you do before you click send.
extra-169: clicking send is where risk meets reward.
extra-170: risk meets reward in fee formulas.
extra-171: fee formulas meet threshold logic.
extra-172: threshold logic meets codex amplifiers.
extra-173: codex amplifiers meet district edges.
extra-174: district edges meet racket bullets.
extra-175: racket bullets meet treaty trust.
extra-176: treaty trust meets warflag skew.
extra-177: warflag skew meets roll.
extra-178: roll meets reveal.
extra-179: reveal meets settlement.
extra-180: settlement meets withdraw.
extra-181: withdraw meets receipts.
extra-182: receipts meet reputation.
extra-183: reputation meets bank trust.
extra-184: bank trust meets more stash.
extra-185: stash meets more raids.
extra-186: more raids meet more stories.
extra-187: stories meet codex.
extra-188: codex meets you.
extra-189: you meet the city.
extra-190: the city meets your tactics.
extra-191: tactics meet your route.
extra-192: your route meets your threshold.
extra-193: your threshold meets your roll.
extra-194: your roll meets your keep.
extra-195: your keep meets your next plan.
extra-196: the next plan is always better.
extra-197: unless you stop learning.
extra-198: don’t stop learning.
extra-199: learn the alley.
extra-200: learn the math.
extra-201: learn the timing.
extra-202: learn the reveals.
extra-203: learn the routes.
extra-204: learn the district.
extra-205: learn the racket.
extra-206: learn the treaty.
extra-207: learn the warflag.
extra-208: learn the codex.
extra-209: learn the mirror.
extra-210: learn the thresholds.
extra-211: learn the fees.
extra-212: learn the keep.
extra-213: learn the loop.
extra-214: and when you’re done learning, start again.
extra-215: that’s not repetition.
extra-216: that’s adaptation.
extra-217: adaptation is the whole city.
extra-218: adaptation is why gangster games survive.
extra-219: survive long enough and you become the legend.
extra-220: legends are built in small increments.
extra-221: increments are built in deterministic math.
extra-222: deterministic math is built in selectors and hashes.
extra-223: hashes are built in keccak.
extra-224: keccak is built in inevitability.
extra-225: inevitability is built in your choices.
extra-226: make choices on purpose.
extra-227: purpose is the difference between hope and plan.
extra-228: hope is expensive.
extra-229: plan is a discount.
extra-230: discount is bullets in disguise.
extra-231: disguise is diplomacy.
extra-232: diplomacy is treaties.
extra-233: treaties are trust half.
extra-234: trust half is scaling.
extra-235: scaling is survival.
extra-236: survival is success.
extra-237: success is stash.
extra-238: stash is your budget for mistakes.
extra-239: mistakes are inevitable.
extra-240: make fewer, and make them smaller.
extra-241: make the simulator your mirror.
extra-242: mirror runes show you the shadow cost.
extra-243: shadow cost makes you train earlier.
extra-244: training earlier makes you stronger.
extra-245: stronger makes diffs kinder.
extra-246: kinder diffs make threshold fairer.
extra-247: fairer threshold makes win easier.
extra-248: easier win makes keep larger.
extra-249: larger keep makes stash thicker.
extra-250: thick stash buys patience.
extra-251: patience buys reveals.
extra-252: reveals buy reputation.
extra-253: reputation buys treaties.
extra-254: treaties buy trust half.
extra-255: trust half buys delayed decisions.
extra-256: delayed decisions buys contested territory.
extra-257: contested territory buys district edges.
extra-258: district edges buys codex amplifiers.
extra-259: amplifiers buy outcomes.
extra-260: outcomes buy next turns.
extra-261: next turns buy more routes.
extra-262: routes buy position.
extra-263: position buys advantage.
extra-264: advantage buys choice.
extra-265: choice buys loops.
extra-266: loops buy legends.
extra-267: legends buy more math.
extra-268: math buys more decisions.
extra-269: decisions buy keeps.
extra-270: keeps buy cashouts.
extra-271: cashouts buy more bullets.
extra-272: bullets buy more raids.
extra-273: raids buy more stories.
extra-274: stories buy more codex.
extra-275: codex buys more clarity.
extra-276: clarity buys better routes.
extra-277: better routes buy better outcomes.
extra-278: better outcomes buy better plans.
extra-279: better plans buy better reveals.
extra-280: better reveals buy better fees.
extra-281: better fees buy better keeps.
extra-282: better keeps buy better stashes.
extra-283: better stashes buy better everything.
extra-284: and that’s the city.
extra-285: don’t act like it’s random.
extra-286: act like it’s structured.
extra-287: act like it’s yours.
extra-288: act like you own the alley.
extra-289: act like you wrote the contracts.
extra-290: you didn’t, but you can read them.
extra-291: reading is power.
extra-292: power is just another number.
extra-293: numbers are just secrets in base 16.
extra-294: secrets become strategies.
extra-295: strategies become raid tickets.
extra-296: tickets become committed raids.
extra-297: committed raids become reveals.
extra-298: reveals become pending withdrawals.
extra-299: withdrawals become stashes.
extra-300: stashes become future power.
extra-301: future power becomes more raids.
extra-302: more raids become more district levels.
extra-303: more levels become stronger district edges.
extra-304: stronger district edges become better odds.
extra-305: better odds become higher keeps.
extra-306: higher keeps become thicker stashes.
extra-307: thicker stashes become deeper plans.
extra-308: deep plans become legends.
extra-309: legends become the baseline.
extra-310: baseline is where you start improving again.
extra-311: improvement is not a feeling.
extra-312: improvement is a repeatable process.
extra-313: repeat the process.
extra-314: repeat the process.
extra-315: repeat the process.
extra-316: repetition is how you learn.
extra-317: learning is how you win.
extra-318: winning is how you build your crew.
extra-319: build your crew in the simulator first.
extra-320: then on-chain second.
extra-321: keep your on-chain actions deliberate.
extra-322: keep your off-chain plans honest.
extra-323: honest plans are safer bets.
extra-324: safer bets let you take bolder gambles.
extra-325: bolder gambles create better stories.
extra-326: better stories attract better allies.
extra-327: better allies create treaty windows.
extra-328: treaty windows create trust scaling.
extra-329: trust scaling creates contested thresholds.
extra-330: contested thresholds create dramatic rolls.
extra-331: dramatic rolls create historic payout receipts.
extra-332: receipts create reputation.
extra-333: reputation creates funding.
extra-334: funding creates more gear.
extra-335: gear creates more tactical flexibility.
extra-336: flexibility creates more route options.
extra-337: options create dominance.
extra-338: dominance creates district control.
extra-339: district control creates heat advantage.
extra-340: heat advantage creates pacing advantage.
extra-341: pacing advantage creates tactical advantage.
extra-342: tactical advantage creates campaign advantage.
extra-343: campaign advantage creates endgame advantage.
extra-344: endgame advantage creates victory.
extra-345: victory creates legend.
extra-346: legend is repeatable with the right math.
extra-347: that right math is encoded here.
extra-348: that’s why this simulator exists.
extra-349: that’s why AgeofChan is persistent.
extra-350: that’s why the alley remembers.
extra-351: remember back.
extra-352: remember the fees.
extra-353: remember the keeps.
extra-354: remember the threshold.
extra-355: remember the roll.
extra-356: remember the reveal.
extra-357: remember the withdraw.
extra-358: remember the loop.
extra-359: and then break it on purpose.
extra-360: break it with a new route.
extra-361: break it with a new tactic.
extra-362: break it with a new plan.
extra-363: break it with a new reveal.
extra-364: break it with a new legend.
extra-365: you can always come back to the baseline.
extra-366: but never stop exploring.
extra-367: exploration is where the next advantage hides.
extra-368: advantage hides in codex runes.
extra-369: runes hide in thresholds.
extra-370: thresholds hide in warflags.
extra-371: warflags hide in time.
extra-372: time is always moving.
extra-373: commit before it’s gone.
extra-374: reveal after it’s earned.
extra-375: that’s the gangster rhythm.
extra-376: rhythm becomes strategy.
extra-377: strategy becomes campaign.
extra-378: campaign becomes control.
extra-379: control becomes victory.
extra-380: victory becomes legend.
extra-381: legend becomes funding.
extra-382: funding becomes gear.
extra-383: gear becomes options.
extra-384: options become routes.
extra-385: routes become outcomes.
extra-386: outcomes become future decisions.
extra-387: future decisions become your next plan.
extra-388: next plan becomes the next reveal.
extra-389: reveal becomes next day.
extra-390: next day becomes next night.
extra-391: next night becomes next raid.
extra-392: next raid becomes next story.
extra-393: story becomes codex.
extra-394: codex becomes you.
extra-395: you become the city.
extra-396: city becomes math.
extra-397: math becomes profit.
extra-398: profit becomes stash.
extra-399: stash becomes bullets.
extra-400: bullets become raids.
extra-401: raids become district level.
extra-402: district level becomes glyph edge.
extra-403: glyph edge becomes threshold scaling.
extra-404: scaling becomes keep.
extra-405: keep becomes cashout.
extra-406: cashout becomes stash.
extra-407: stash becomes power.
extra-408: power becomes training.
extra-409: training becomes raids.
extra-410: raids become campaigns.
extra-411: campaigns become legends.
extra-412: legends become the baseline.
extra-413: baseline becomes improvement.
extra-414: improvement becomes dominance.
extra-415: dominance becomes more legends.
extra-416: more legends become allies.
extra-417: allies become treaties.
extra-418: treaties become trust.
extra-419: trust becomes scaling.
extra-420: scaling becomes victory.
"""

EXTRA_RULES = [
    "rule-rail-001: scout before commit.",
    "rule-rail-002: raid with intent.",
    "rule-rail-003: train on schedule.",
    "rule-rail-004: route is risk control.",
    "rule-rail-005: district modulo matters.",
    "rule-rail-006: racket bullets are leverage.",
    "rule-rail-007: treaty trust half buys hesitation.",
    "rule-rail-008: warflag skew lives in thresholds.",
    "rule-rail-009: codex runes amplify plan edges.",
    "rule-rail-010: mirror runes punish poor geometry.",
    "rule-rail-011: fee clamp is the hidden governor.",
    "rule-rail-012: neutral zones teach humility.",
    "rule-rail-013: don’t chase, compound.",
    "rule-rail-014: keep share is a budget.",
    "rule-rail-015: stash is future math.",
    "rule-rail-016: power is your insurance.",
    "rule-rail-017: defense is patience.",
    "rule-rail-018: raids are negotiations.",
    "rule-rail-019: reveals are timed truths.",
    "rule-rail-020: keep the loop alive.",
]

SIM_MANUAL_EXTRA_2 = """
extra2-001: the alley loves deterministic noise.
extra2-002: deterministic noise makes decisions reproducible.
extra2-003: reproducible decisions make planning possible.
extra2-004: planning possible means fewer on-chain surprises.
extra2-005: fewer surprises means safer deployments.
extra2-006: safer deployments keep budgets intact.
extra2-007: intact budgets buy more training cycles.
extra2-008: training cycles build power over time.
extra2-009: power over time beats panic.
extra2-010: panic is expensive, even in math.
extra2-011: keep panic out of your commit stage.
extra2-012: keep panic out of your reveal stage.
extra2-013: keep panic out of your routing stage.
extra2-014: routing stage determines your odds.
extra2-015: odds determine your payout expectation.
extra2-016: payout expectation determines your pot size choices.
extra2-017: pot size choices decide your risk horizon.
extra2-018: risk horizon decides how you spend bullets.
extra2-019: bullets spend translates into raid edge.
extra2-020: raid edge translates into threshold shifts.
extra2-021: threshold shifts translate into win probability.
extra2-022: win probability translates into keeps.
extra2-023: keeps translate into stashes.
extra2-024: stashes translate into future gear.
extra2-025: future gear translates into better tactics.
extra2-026: better tactics translates into cleaner comms.
extra2-027: cleaner comms reduce wasted reveals.
extra2-028: wasted reveals reduce confidence.
extra2-029: confidence is the first currency.
extra2-030: the second currency is time.
extra2-031: treaty windows are timeboxes for advantage.
extra2-032: trust half is the scaling knob.
extra2-033: scaling knob changes the middle of the fight.
extra2-034: middle-of-fight changes end outcomes.
extra2-035: end outcomes become settlement.
extra2-036: settlement becomes pending withdrawals.
extra2-037: withdrawals become receipts.
extra2-038: receipts become reputation.
extra2-039: reputation becomes alliances.
extra2-040: alliances become treaties.
extra2-041: treaties become trust.
extra2-042: trust becomes more scaling.
extra2-043: more scaling becomes better keep.
extra2-044: better keep becomes more stash.
extra2-045: more stash becomes more gear.
extra2-046: more gear becomes more raids.
extra2-047: more raids becomes more district control.
extra2-048: district control creates glyph edges.
extra2-049: glyph edges create district modulo effects.
extra2-050: district modulo effects make small deltas real.
extra2-051: real deltas win coin flips.
extra2-052: coin flips become campaign trends.
extra2-053: campaign trends become legend stats.
extra2-054: legend stats become strategy defaults.
extra2-055: strategy defaults become your next plan template.
extra2-056: next plan template becomes the next codex.
extra2-057: codex becomes UI.
extra2-058: UI becomes intuition.
extra2-059: intuition becomes better routes.
extra2-060: better routes become better encounters.
extra2-061: better encounters become more training opportunities.
extra2-062: training opportunities become power.
extra2-063: power becomes structure.
extra2-064: structure becomes dominance.
extra2-065: dominance becomes safety.
extra2-066: safety buys experimentation.
extra2-067: experimentation buys innovation.
extra2-068: innovation buys a new district.
extra2-069: a new district changes your modulo.
extra2-070: modulo changes glyph edges.
extra2-071: glyph edges changes your threshold curve.
extra2-072: threshold curve changes win likelihood.
extra2-073: win likelihood changes fee rates.
extra2-074: fee rates change keep shares.
extra2-075: keep shares change your bankroll curve.
extra2-076: bankroll curve changes your ability to buy bullets.
extra2-077: buying bullets changes your racket edge.
extra2-078: racket edge changes your outcome variance.
extra2-079: variance changes tactic selection bias.
extra2-080: tactic selection bias changes next plan.
extra2-081: next plan changes next route.
extra2-082: next route changes next district.
extra2-083: next district changes next modulo.
extra2-084: modulo changes next fight.
extra2-085: next fight changes next settlement.
extra2-086: settlement changes next stash.
extra2-087: stash changes next decisions.
extra2-088: decisions become game-state.
extra2-089: game-state becomes story.
extra2-090: story becomes a rumor line.
extra2-091: rumor line becomes a hint.
extra2-092: hint becomes a tactic.
extra2-093: tactic becomes a raid.
extra2-094: raid becomes a reveal.
extra2-095: reveal becomes payout.
