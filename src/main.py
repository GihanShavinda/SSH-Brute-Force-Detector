"""
main.py
-------
Entry point for the SSH Brute Force Detector.

Usage:
    sudo python3 src/main.py --config config/config.yaml
    sudo python3 src/main.py --config config/config.yaml --dry-run

Run as root (or with sudo) since reading /var/log/auth.log and modifying
firewall rules both typically require elevated privileges.
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


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH Brute Force Detector")
    parser.add_argument(
        "--config", default="config/config.yaml", help="Path to config.yaml"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would be banned without touching the firewall",
    )
    args = parser.parse_args()

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
        backend=cfg["banning"]["backend"],
        chain_name=cfg["banning"]["chain_name"],
        ban_log_file=cfg["logging"]["ban_log_file"],
        dry_run=args.dry_run,
    )

    ban_duration = cfg["detection"].get("ban_duration_seconds", 0)
    webhook_url = cfg.get("notifications", {}).get("webhook_url") if cfg.get(
        "notifications", {}
    ).get("enabled") else None

    logger.info(
        "Starting SSH Brute Force Detector (max_failures=%s, window=%ss, backend=%s, dry_run=%s)",
        detector.max_failures,
        detector.window_seconds,
        ban_manager.backend,
        args.dry_run,
    )

    # Background thread to lift expired bans
    threading.Thread(
        target=expiry_loop, args=(ban_manager,), daemon=True
    ).start()

    try:
        for event in watch(cfg["log_file"], use_journalctl=cfg.get("use_journalctl", False)):
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
        logger.error("Permission denied — try running with sudo: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
