"""
manage_bans.py
--------------
Small CLI helper for inspecting/manually adjusting bans, reading straight
from the ban_log_file audit trail (JSON lines, one event per line).

Usage:
    python3 src/manage_bans.py list
    sudo python3 src/manage_bans.py unban 10.0.0.7 --config config/config.yaml
"""

import argparse
import json
import subprocess
import sys

import yaml


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def list_active_bans(ban_log_file: str) -> None:
    state = {}
    try:
        with open(ban_log_file, "r") as f:
            for line in f:
                entry = json.loads(line)
                if entry["action"] == "BAN":
                    state[entry["ip"]] = entry
                elif entry["action"] == "UNBAN":
                    state.pop(entry["ip"], None)
    except FileNotFoundError:
        print("No ban log found yet — nothing has been banned.")
        return

    if not state:
        print("No IPs currently banned.")
        return

    print(f"{'IP':<20}{'Banned At':<25}{'Expires At'}")
    for ip, entry in state.items():
        print(f"{ip:<20}{entry['banned_at']:<25}{entry.get('expires_at') or 'never'}")


def unban_ip(ip: str, chain_name: str, backend: str) -> None:
    if backend == "iptables":
        subprocess.run(["iptables", "-D", chain_name, "-s", ip, "-j", "DROP"], check=True)
    elif backend == "ufw":
        subprocess.run(["ufw", "delete", "deny", "from", ip, "to", "any"], check=True)
    else:
        print(f"Manual unban for backend '{backend}' not implemented in this helper.")
        sys.exit(1)
    print(f"Unbanned {ip}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage SSH brute-force bans")
    parser.add_argument("--config", default="config/config.yaml")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List currently banned IPs")

    unban_parser = sub.add_parser("unban", help="Manually unban an IP")
    unban_parser.add_argument("ip")

    args = parser.parse_args()
    cfg = load_config(args.config)

    if args.command == "list":
        list_active_bans(cfg["logging"]["ban_log_file"])
    elif args.command == "unban":
        unban_ip(args.ip, cfg["banning"]["chain_name"], cfg["banning"]["backend"])


if __name__ == "__main__":
    main()
