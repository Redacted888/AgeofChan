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
