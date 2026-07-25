"""
main.py (Windows)
------------------
Entry point for the SSH/RDP Brute Force Detector on Windows.

IMPORTANT: There is no `sudo` on Windows. Instead, open Command Prompt or
PowerShell **as Administrator** (right-click -> "Run as administrator"),
then run:

    python src\\main.py --config config\\config.yaml
    python src\\main.py --config config\\config.yaml --dry-run

Administrator rights are required because reading the Security Event Log
and adding/removing Windows Firewall rules both require elevation.
"""

import argparse
import logging
import os
import sys
import threading
import time

import yaml

sys.path.insert(0, os.path.dirname(__file__))

from log_monitor import watch  # noqa: E402
from detector import BruteForceDetector  # noqa: E402
from ban_manager import BanManager  # noqa: E402
from notifier import send_ban_alert  # noqa: E402


def setup_logging(log_file: str, level: str) -> logging.Logger:
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    logger = logging.getLogger("ssh-bf-detector")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(fmt)
    logger.addHandler(console_handler)

    return logger


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def expiry_loop(ban_manager: BanManager, interval: int = 30) -> None:
    """Background thread: periodically unban IPs whose ban has expired."""
    while True:
        ban_manager.check_expired()
        time.sleep(interval)


def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH/RDP Brute Force Detector (Windows)")
    parser.add_argument(
        "--config", default="config/config.yaml", help="Path to config.yaml"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would be banned without touching the firewall",
    )
    args = parser.parse_args()

    if not is_admin() and not args.dry_run:
        print(
            "WARNING: This does not appear to be running elevated.\n"
            "Reading the Security Event Log and modifying the Windows "
            "Firewall both require Administrator rights.\n"
            "Right-click your terminal and choose 'Run as administrator', "
            "then re-run this command.\n"
        )

    cfg = load_config(args.config)

    logger = setup_logging(
        cfg["logging"]["app_log_file"], cfg["logging"].get("level", "INFO")
    )

    detector = BruteForceDetector(
        max_failures=cfg["detection"]["max_failures"],
        window_seconds=cfg["detection"]["window_seconds"],
        whitelist=cfg["detection"].get("whitelist", []),
    )

    ban_manager = BanManager(
        rule_prefix=cfg["banning"]["rule_prefix"],
        ban_log_file=cfg["logging"]["ban_log_file"],
        dry_run=args.dry_run,
    )

    ban_duration = cfg["detection"].get("ban_duration_seconds", 0)
    webhook_url = cfg.get("notifications", {}).get("webhook_url") if cfg.get(
        "notifications", {}
    ).get("enabled") else None

    logger.info(
        "Starting SSH/RDP Brute Force Detector (max_failures=%s, window=%ss, source=%s, dry_run=%s)",
        detector.max_failures,
        detector.window_seconds,
        cfg["log_source"],
        args.dry_run,
    )

    # Background thread to lift expired bans
    threading.Thread(
        target=expiry_loop, args=(ban_manager,), daemon=True
    ).start()

    try:
        for event in watch(
            log_source=cfg["log_source"],
            log_file=cfg.get("log_file"),
            eventlog_logon_types=cfg.get("eventlog_logon_types", []),
        ):
            logger.info(
                "Failed login attempt: user=%s ip=%s", event.user, event.ip
            )

            if ban_manager.is_banned(event.ip):
                continue

            should_ban = detector.record_failure(event.ip, event.timestamp)
            if should_ban:
                count = detector.failure_count(event.ip)
                logger.warning(
                    "IP %s exceeded threshold (%s failures) -> BANNING", event.ip, count
                )
                ban_manager.ban(event.ip, duration_seconds=ban_duration)
                detector.reset(event.ip)
                send_ban_alert(webhook_url, event.ip, count)

    except KeyboardInterrupt:
        logger.info("Shutting down.")
    except FileNotFoundError as exc:
        logger.error("Log file not found: %s", exc)
        sys.exit(1)
    except PermissionError as exc:
        logger.error("Permission denied — re-run from an elevated (Administrator) prompt: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
