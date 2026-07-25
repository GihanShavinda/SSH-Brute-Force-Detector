"""
log_monitor.py
--------------
Tails the SSH auth log (or journalctl output) in real time and yields
structured "failed login" events as they occur.

Supported log line formats (OpenSSH via sshd):

  Failed password for root from 192.168.1.50 port 51514 ssh2
  Failed password for invalid user admin from 10.0.0.7 port 44210 ssh2
  Invalid user test from 10.0.0.7 port 44212
  Connection closed by authenticating user root 10.0.0.7 port 51514 [preauth]
"""

import re
import subprocess
import time
from dataclasses import dataclass
from typing import Iterator, Optional


FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)


@dataclass
class FailedLoginEvent:
    ip: str
    user: str
    raw_line: str
    timestamp: float


def _parse_line(line: str) -> Optional[FailedLoginEvent]:
    match = FAILED_PASSWORD_RE.search(line) or INVALID_USER_RE.search(line)
    if not match:
        return None
    return FailedLoginEvent(
        ip=match.group("ip"),
        user=match.group("user"),
        raw_line=line.strip(),
        timestamp=time.time(),
    )


def tail_file(path: str) -> Iterator[str]:
    """Generator that yields new lines appended to `path`, like `tail -f`."""
    with open(path, "r", errors="ignore") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def tail_journalctl() -> Iterator[str]:
    """Generator that yields new lines from `journalctl -f -u ssh(d)`."""
    cmd = ["journalctl", "-f", "-u", "ssh", "-u", "sshd", "-o", "cat"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        yield line


def watch(log_file: str, use_journalctl: bool = False) -> Iterator[FailedLoginEvent]:
    """Yield FailedLoginEvent objects as failed logins appear in the log."""
    source = tail_journalctl() if use_journalctl else tail_file(log_file)
    for line in source:
        event = _parse_line(line)
        if event:
            yield event
