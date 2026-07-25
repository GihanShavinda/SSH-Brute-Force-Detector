import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from detector import BruteForceDetector  # noqa: E402
from log_monitor import _parse_line  # noqa: E402


def test_ban_triggers_after_threshold():
    d = BruteForceDetector(max_failures=3, window_seconds=60)
    ip = "10.0.0.5"
    assert d.record_failure(ip) is False
    assert d.record_failure(ip) is False
    assert d.record_failure(ip) is True  # 3rd failure crosses threshold


def test_whitelisted_ip_never_bans():
    d = BruteForceDetector(max_failures=1, window_seconds=60, whitelist=["10.0.0.5"])
    assert d.record_failure("10.0.0.5") is False
    assert d.record_failure("10.0.0.5") is False


def test_window_expiry_resets_count():
    d = BruteForceDetector(max_failures=2, window_seconds=1)
    ip = "10.0.0.9"
    assert d.record_failure(ip, timestamp=1000) is False
    # Second failure well outside the 1s window -> should NOT trigger ban
    assert d.record_failure(ip, timestamp=1010) is False


def test_cidr_whitelist():
    d = BruteForceDetector(max_failures=1, window_seconds=60, whitelist=["10.0.0.0/24"])
    assert d.record_failure("10.0.0.42") is False


def test_parse_failed_password_line():
    line = "Jul 25 10:00:01 host sshd[1234]: Failed password for root from 192.168.1.50 port 51514 ssh2"
    event = _parse_line(line)
    assert event is not None
    assert event.ip == "192.168.1.50"
    assert event.user == "root"


def test_parse_invalid_user_line():
    line = "Jul 25 10:00:02 host sshd[1234]: Invalid user admin from 10.0.0.7 port 44212"
    event = _parse_line(line)
    assert event is not None
    assert event.ip == "10.0.0.7"
    assert event.user == "admin"


def test_parse_unrelated_line_returns_none():
    line = "Jul 25 10:00:03 host sshd[1234]: Accepted password for alice from 10.0.0.2 port 22 ssh2"
    assert _parse_line(line) is None


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
