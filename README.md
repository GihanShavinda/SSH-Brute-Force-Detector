# SSH Brute Force Detector

A lightweight, fail2ban-style tool that watches your SSH auth log in real
time, counts failed login attempts per IP, and automatically firewalls
(bans) any IP that crosses a configurable threshold within a time window.

## Features

- Real-time log tailing (`/var/log/auth.log`, `/var/log/secure`, or `journalctl`)
- Sliding-window failure counting per IP (not just a raw total)
- Auto-ban via `iptables`, `nftables`, or `ufw`
- Auto-unban after a configurable ban duration (or permanent bans)
- Whitelist support (single IPs or CIDR ranges)
- JSON audit log of every ban/unban event
- Optional webhook notifications (Slack/Discord/generic)
- `--dry-run` mode to test detection logic without touching the firewall
- Unit-tested detection/parsing logic (no root required to run tests)

## Project Structure

```
ssh-bruteforce-detector/
├── README.md
├── requirements.txt
├── config/
│   └── config.yaml          # all tunables live here
├── src/
│   ├── main.py               # entry point / orchestration
│   ├── log_monitor.py        # tails auth.log / journalctl, parses events
│   ├── detector.py           # sliding-window failure tracking + whitelist
│   ├── ban_manager.py        # iptables/nftables/ufw ban + auto-expiry
│   ├── notifier.py           # optional webhook alerts
│   └── manage_bans.py        # CLI: list / manually unban IPs
├── logs/
│   ├── detector.log          # app activity log (created at runtime)
│   └── banned_ips.log        # JSON audit trail of ban/unban events
└── tests/
    └── test_detector.py       # unit tests (pytest)
```

## Requirements

- Linux host with OpenSSH (`sshd`) logging to `auth.log` / `secure` / journald
- Python 3.8+
- `iptables`, `nftables`, or `ufw` installed (matching your `backend` config)
- Root privileges to read the auth log and modify firewall rules

## Installation

```bash
git clone <your-repo-url> ssh-bruteforce-detector
cd ssh-bruteforce-detector
pip install -r requirements.txt
```

## Configuration

Edit `config/config.yaml`:

```yaml
log_file: "/var/log/auth.log"     # or /var/log/secure on RHEL/CentOS
use_journalctl: false              # true if your distro only logs to journald

detection:
  max_failures: 5                  # attempts allowed before ban
  window_seconds: 300               # time window for counting attempts
  ban_duration_seconds: 3600        # 0 = permanent ban
  whitelist:
    - "127.0.0.1"
    - "203.0.113.10"                # your own admin IP — add this!

banning:
  backend: "iptables"               # iptables | nftables | ufw
  chain_name: "SSH_BF_BAN"
```

**Important:** add your own IP (or management network) to the whitelist
before running this on a box you access remotely — it is entirely possible
to lock yourself out otherwise.

## Usage

Run it (must be root to read the log and manage the firewall):

```bash
sudo python3 src/main.py --config config/config.yaml
```

Test the detection logic safely first without changing firewall rules:

```bash
sudo python3 src/main.py --config config/config.yaml --dry-run
```

List current bans / manually unban an IP:

```bash
python3 src/manage_bans.py list
sudo python3 src/manage_bans.py unban 203.0.113.55
```

### Run as a systemd service (recommended for production)

Create `/etc/systemd/system/ssh-bf-detector.service`:

```ini
[Unit]
Description=SSH Brute Force Detector
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/ssh-bruteforce-detector/src/main.py --config /opt/ssh-bruteforce-detector/config/config.yaml
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-bf-detector
sudo systemctl status ssh-bf-detector
```

## Running Tests

The detection/parsing logic is pure Python and fully unit-testable without
root or a real server:

```bash
pip install pytest
pytest tests/ -v
```

## How It Works

1. `log_monitor.py` tails the auth log and regex-matches `Failed password`
   / `Invalid user` lines, extracting the source IP.
2. `detector.py` keeps a per-IP deque of failure timestamps; anything
   outside the configured `window_seconds` is dropped, so only *recent*
   bursts count.
3. Once an IP's recent-failure count hits `max_failures`, `main.py` calls
   `ban_manager.py`, which inserts a `DROP` rule in a dedicated firewall
   chain and records the ban (with expiry, if configured) to a JSON audit
   log.
4. A background thread periodically checks for expired bans and lifts them
   automatically.

## Extending

- Swap the webhook in `notifier.py` for email/SMS/PagerDuty as needed.
- Add a `GET /bans` HTTP endpoint (Flask/FastAPI) on top of `manage_bans.py`
  if you want a small dashboard.
- Persist detector state to disk/Redis if you need it to survive restarts
  without relosing in-progress failure counts.

## Disclaimer

This tool modifies live firewall rules. Test with `--dry-run` first, always
whitelist your own access IP, and keep an out-of-band way to reach the
server (cloud provider console, IPMI, etc.) in case of misconfiguration.
