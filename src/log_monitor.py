"""
log_monitor.py (Windows)
------------------------
Two source modes:

1. "eventlog" (default) - polls the Windows Security Event Log for Event ID
   4625 ("An account failed to log on"), which covers RDP logons, SMB/network
   logons, and OpenSSH-on-Windows when it authenticates against a local or
   domain Windows account. Requires `pywin32` and must be run as
   Administrator (the Security log is not readable otherwise).

2. "logfile" - tails a plain text log file, e.g. OpenSSH's own sshd.log,
   using the same regex-based parsing as the Linux version. Useful if
   you've configured OpenSSH on Windows to log to a file instead of the
   event log (see sshd_config -> SyslogFacility / LogLevel).
"""

import re
import time
from dataclasses import dataclass
from typing import Iterator, List, Optional

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
except ImportError:
    win32evtlog = None  # allows "logfile" mode to work without pywin32


FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)

# Inside a 4625 event's inserted strings, the source IP and logon type are
# at fixed indices for standard Windows builds.
EVT_LOGON_TYPE_INDEX = 10
EVT_IP_ADDRESS_INDEX = 19
EVT_USER_NAME_INDEX = 5
FAILED_LOGON_EVENT_ID = 4625


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


def watch_logfile(log_file: str) -> Iterator[FailedLoginEvent]:
    for line in tail_file(log_file):
        event = _parse_line(line)
        if event:
            yield event


def _event_to_failed_login(event, allowed_logon_types: List[int]) -> Optional[FailedLoginEvent]:
    if event.EventID != FAILED_LOGON_EVENT_ID:
        return None

    strings = event.StringInserts or []
    if len(strings) <= max(EVT_LOGON_TYPE_INDEX, EVT_IP_ADDRESS_INDEX):
        return None

    logon_type_str = strings[EVT_LOGON_TYPE_INDEX]
    try:
        logon_type = int(logon_type_str)
    except (ValueError, TypeError):
        logon_type = None

    if allowed_logon_types and logon_type not in allowed_logon_types:
        return None

    ip = strings[EVT_IP_ADDRESS_INDEX].strip()
    if not ip or ip == "-":
        return None

    user = strings[EVT_USER_NAME_INDEX] if len(strings) > EVT_USER_NAME_INDEX else "unknown"

    return FailedLoginEvent(
        ip=ip,
        user=user,
        raw_line=f"EventID=4625 user={user} ip={ip} logon_type={logon_type}",
        timestamp=time.time(),
    )


def watch_eventlog(
    allowed_logon_types: List[int] = None,
    poll_interval: float = 2.0,
) -> Iterator[FailedLoginEvent]:
    """
    Poll the Security event log for new 4625 (failed logon) events and
    yield FailedLoginEvent objects. Must run as Administrator.
    """
    if win32evtlog is None:
        raise RuntimeError(
            "pywin32 is required for eventlog mode. Install with: pip install pywin32"
        )

    server = "localhost"
    log_type = "Security"
    hand = win32evtlog.OpenEventLog(server, log_type)

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    # Start from the current end of the log so we only see NEW events.
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    seen_record_numbers = set()
    last_seen_count = total

    allowed_logon_types = allowed_logon_types or []

    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            time.sleep(poll_interval)
            continue

        for event in events:
            if event.RecordNumber in seen_record_numbers:
                continue
            seen_record_numbers.add(event.RecordNumber)

            # Only process events newer than what existed at startup
            if event.RecordNumber <= last_seen_count:
                continue

            parsed = _event_to_failed_login(event, allowed_logon_types)
            if parsed:
                yield parsed

        # Keep the seen-set from growing unbounded
        if len(seen_record_numbers) > 5000:
            seen_record_numbers = set(list(seen_record_numbers)[-2000:])

        time.sleep(poll_interval)


def watch(
    log_source: str,
    log_file: str = None,
    eventlog_logon_types: List[int] = None,
) -> Iterator[FailedLoginEvent]:
    if log_source == "eventlog":
        yield from watch_eventlog(allowed_logon_types=eventlog_logon_types)
    elif log_source == "logfile":
        yield from watch_logfile(log_file)
    else:
        raise ValueError(f"Unknown log_source: {log_source}")
