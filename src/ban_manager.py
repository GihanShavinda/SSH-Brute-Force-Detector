"""
ban_manager.py (Windows)
------------------------
Applies and removes Windows Firewall rules to block offending IPs, using
`netsh advfirewall firewall`. Must be run from an elevated (Administrator)
terminal/prompt.

Also tracks ban expiry times in memory + an on-disk JSON audit log so bans
can be lifted automatically after `ban_duration_seconds`.
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


def _rule_name(prefix: str, ip: str) -> str:
    # Firewall rule names can't contain some characters; ':' from IPv6 is fine
    # for netsh but we normalise anyway to keep rule names tidy.
    return f"{prefix}_{ip}"


class BanManager:
    def __init__(
        self,
        rule_prefix: str = "SSH_BF_BAN",
        ban_log_file: str = "logs\\banned_ips.log",
        dry_run: bool = False,
    ):
        self.rule_prefix = rule_prefix
        self.ban_log_file = ban_log_file
        self.dry_run = dry_run
        self._active_bans: Dict[str, BanRecord] = {}

        os.makedirs(os.path.dirname(ban_log_file) or ".", exist_ok=True)

    # ---------- backend ----------

    def _run(self, cmd: list) -> None:
        if self.dry_run:
            print(f"[DRY-RUN] {' '.join(cmd)}")
            return
        subprocess.run(cmd, check=True, shell=False)

    # ---------- public API ----------

    def is_banned(self, ip: str) -> bool:
        return ip in self._active_bans

    def ban(self, ip: str, duration_seconds: int = 0) -> None:
        if self.is_banned(ip):
            return  # already banned

        name = _rule_name(self.rule_prefix, ip)
        self._run(
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
            ]
        )

        now = time.time()
        expires_at = now + duration_seconds if duration_seconds > 0 else None
        record = BanRecord(ip=ip, banned_at=now, expires_at=expires_at)
        self._active_bans[ip] = record
        self._log_event("BAN", record)

    def unban(self, ip: str) -> None:
        if not self.is_banned(ip):
            return

        name = _rule_name(self.rule_prefix, ip)
        self._run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        )

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
