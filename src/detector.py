"""
detector.py
-----------
Keeps a sliding-window count of failed login attempts per IP address and
decides when an IP has crossed the threshold and should be banned.
"""

import ipaddress
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List


class BruteForceDetector:
    def __init__(
        self,
        max_failures: int,
        window_seconds: int,
        whitelist: List[str] = None,
    ):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.whitelist = whitelist or []
        # ip -> deque of failure timestamps
        self._attempts: Dict[str, Deque[float]] = defaultdict(deque)

    def _is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for entry in self.whitelist:
            try:
                if "/" in entry:
                    if addr in ipaddress.ip_network(entry, strict=False):
                        return True
                elif addr == ipaddress.ip_address(entry):
                    return True
            except ValueError:
                continue
        return False

    def record_failure(self, ip: str, timestamp: float = None) -> bool:
        """
        Record a failed login attempt for `ip`. Returns True if this
        attempt pushed the IP over the ban threshold, False otherwise.
        Whitelisted IPs never trigger a ban.
        """
        if self._is_whitelisted(ip):
            return False

        ts = timestamp or time.time()
        window = self._attempts[ip]
        window.append(ts)

        # Drop timestamps outside the sliding window
        cutoff = ts - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        return len(window) >= self.max_failures

    def failure_count(self, ip: str) -> int:
        return len(self._attempts.get(ip, []))

    def reset(self, ip: str) -> None:
        """Clear tracked attempts for an IP (e.g. after banning it)."""
        self._attempts.pop(ip, None)
