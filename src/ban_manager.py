"""
ban_manager.py
--------------
Applies and removes firewall bans for offending IPs, using one of:
  - iptables
  - nftables
  - ufw

Also tracks ban expiry times in memory + an on-disk audit log so bans can
be lifted automatically after `ban_duration_seconds`.

NOTE: Actually blocking traffic requires root privileges on the host
running this script (sudo / run as root).
"""

import json
import os
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import Dict, Optional


@dataclass
class BanRecord:
    ip: str
    banned_at: float
    expires_at: Optional[float]  # None = permanent


class BanManager:
    def __init__(
        self,
        backend: str = "iptables",
        chain_name: str = "SSH_BF_BAN",
        ban_log_file: str = "logs/banned_ips.log",
        dry_run: bool = False,
    ):
        self.backend = backend
        self.chain_name = chain_name
        self.ban_log_file = ban_log_file
        self.dry_run = dry_run
        self._active_bans: Dict[str, BanRecord] = {}

        os.makedirs(os.path.dirname(ban_log_file) or ".", exist_ok=True)

        if backend == "iptables":
            self._ensure_iptables_chain()

    # ---------- backend setup ----------

    def _run(self, cmd: list) -> None:
        if self.dry_run:
            print(f"[DRY-RUN] {' '.join(cmd)}")
            return
        subprocess.run(cmd, check=True)

    def _ensure_iptables_chain(self) -> None:
        # Create the chain if it doesn't exist, and make sure INPUT jumps to it
        check = subprocess.run(
            ["iptables", "-L", self.chain_name], capture_output=True
        )
        if check.returncode != 0:
            self._run(["iptables", "-N", self.chain_name])
            self._run(["iptables", "-I", "INPUT", "-j", self.chain_name])

    # ---------- public API ----------

    def is_banned(self, ip: str) -> bool:
        return ip in self._active_bans

    def ban(self, ip: str, duration_seconds: int = 0) -> None:
        if self.is_banned(ip):
            return  # already banned

        if self.backend == "iptables":
            self._run(["iptables", "-A", self.chain_name, "-s", ip, "-j", "DROP"])
        elif self.backend == "nftables":
            self._run(
                ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"]
            )
        elif self.backend == "ufw":
            self._run(["ufw", "deny", "from", ip, "to", "any"])
        else:
            raise ValueError(f"Unsupported backend: {self.backend}")

        now = time.time()
        expires_at = now + duration_seconds if duration_seconds > 0 else None
        record = BanRecord(ip=ip, banned_at=now, expires_at=expires_at)
        self._active_bans[ip] = record
        self._log_event("BAN", record)

    def unban(self, ip: str) -> None:
        if not self.is_banned(ip):
            return

        if self.backend == "iptables":
            self._run(["iptables", "-D", self.chain_name, "-s", ip, "-j", "DROP"])
        elif self.backend == "nftables":
            # Removing a single nft rule requires a handle lookup; simplest
            # robust approach is flushing and re-adding remaining bans.
            self._run(["nft", "flush", "chain", "inet", "filter", "input"])
            for other_ip, rec in self._active_bans.items():
                if other_ip != ip:
                    self._run(
                        ["nft", "add", "rule", "inet", "filter", "input", "ip",
                         "saddr", other_ip, "drop"]
                    )
        elif self.backend == "ufw":
            self._run(["ufw", "delete", "deny", "from", ip, "to", "any"])

        record = self._active_bans.pop(ip)
        self._log_event("UNBAN", record)

    def check_expired(self) -> None:
        """Call periodically to auto-unban IPs whose ban has expired."""
        now = time.time()
        expired = [
            ip for ip, rec in self._active_bans.items()
            if rec.expires_at is not None and rec.expires_at <= now
        ]
        for ip in expired:
            self.unban(ip)

    # ---------- audit log ----------

    def _log_event(self, action: str, record: BanRecord) -> None:
        entry = {"action": action, **asdict(record)}
        with open(self.ban_log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
