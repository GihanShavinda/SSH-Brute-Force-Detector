# SSH / RDP Brute Force Detector (Windows Edition)

A fail2ban-style tool for Windows that watches for failed login attempts
(SSH via OpenSSH-on-Windows, RDP, or general network logon) and
automatically blocks offending IPs using Windows Firewall.

## Features

- Reads failed-logon events from the **Windows Security Event Log**
  (Event ID 4625) — covers RDP, SMB, and OpenSSH-on-Windows logons
- Optional **log file mode** if you've configured OpenSSH to log to a file
  instead of the event log
- Sliding-window failure counting per IP (not just a raw total)
- Auto-ban via `netsh advfirewall firewall` rules
- Auto-unban after a configurable ban duration (or permanent bans)
- Whitelist support (single IPs or CIDR ranges)
- JSON audit log of every ban/unban event
- Optional webhook notifications (Slack/Discord/generic)
- `--dry-run` mode to test detection logic without touching the firewall
- Unit-tested detection/parsing logic (no admin rights required to run tests)

## Project Structure

```
ssh-bruteforce-detector-windows\
├── README.md
├── requirements.txt
├── config\
│   └── config.yaml           # all tunables live here
├── src\
│   ├── main.py                # entry point / orchestration
│   ├── log_monitor.py         # reads Security Event Log or tails a log file
│   ├── detector.py            # sliding-window failure tracking + whitelist
│   ├── ban_manager.py         # Windows Firewall ban + auto-expiry
│   ├── notifier.py            # optional webhook alerts
│   └── manage_bans.py         # CLI: list / manually unban IPs
├── logs\
│   ├── detector.log           # app activity log (created at runtime)
│   └── banned_ips.log         # JSON audit trail of ban/unban events
└── tests\
    └── test_detector.py        # unit tests (pytest)
```

## Requirements

- Windows 10/11 or Windows Server
- Python 3.8+ (from python.org or Microsoft Store)
- Administrator rights (to read the Security log and edit Windows Firewall)
- If using SSH specifically: the optional **OpenSSH Server** Windows feature
  installed and running (`Settings > Apps > Optional Features > OpenSSH Server`,
  or `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`)

## Installation

```powershell
git clone <your-repo-url> ssh-bruteforce-detector-windows
cd ssh-bruteforce-detector-windows
pip install -r requirements.txt
```

`pywin32` is required for event-log mode; it's in requirements.txt.

## There is no `sudo` on Windows

Everywhere Linux instructions say `sudo python3 ...`, on Windows you instead:

1. Right-click **Command Prompt** or **PowerShell** and choose
   **"Run as administrator"**.
2. Run the script normally from that elevated prompt:
   ```powershell
   python src\main.py --config config\config.yaml --dry-run
   ```

Reading the Security Event Log and adding/removing Windows Firewall rules
both require elevation — the script will print a warning if it detects it
isn't running elevated.

## Configuration

Edit `config\config.yaml`:

```yaml
log_source: "eventlog"     # "eventlog" or "logfile"
log_file: "C:\\ProgramData\\ssh\\logs\\sshd.log"   # only used if log_source = "logfile"
eventlog_logon_types: [3, 10]   # 3 = Network, 10 = RDP. [] = match all.

detection:
  max_failures: 5
  window_seconds: 300
  ban_duration_seconds: 3600     # 0 = permanent ban
  whitelist:
    - "127.0.0.1"
    - "203.0.113.10"              # your own admin/VPN IP — add this!

banning:
  rule_prefix: "SSH_BF_BAN"
```

**Important:** add your own IP (or VPN/management network) to the whitelist
before running this on a box you access remotely via RDP/SSH — it is
entirely possible to lock yourself out otherwise.

### Which `log_source` should I use?

- **`eventlog`** (default, recommended): works out of the box for RDP and
  for OpenSSH-on-Windows, since both authenticate through Windows and
  generate Event ID 4625 on failure. No extra sshd configuration needed.
- **`logfile`**: only needed if you've specifically configured OpenSSH's
  `sshd_config` to write its own text log (via `LogLevel`/output
  redirection) and you'd rather parse that directly.

To confirm 4625 events are being generated, open **Event Viewer** →
*Windows Logs* → *Security* and try an intentionally failed RDP/SSH login,
then look for "An account failed to log on".

## Usage

From an elevated PowerShell/Command Prompt:

```powershell
# Test detection logic safely first — no firewall changes made
python src\main.py --config config\config.yaml --dry-run

# Run for real
python src\main.py --config config\config.yaml
```

List current bans / manually unban an IP:

```powershell
python src\manage_bans.py list
python src\manage_bans.py unban 203.0.113.55
```

You can also verify bans directly in **Windows Defender Firewall with
Advanced Security** → *Inbound Rules* → look for rules starting with
`SSH_BF_BAN_`.

### Run as a background/scheduled service (recommended)

The simplest option on Windows is **Task Scheduler**:

1. Open Task Scheduler → *Create Task*.
2. General tab: check **"Run with highest privileges"**.
3. Triggers tab: **"At startup"** (or "At log on").
4. Actions tab: **Start a program**
   - Program: `C:\Path\To\python.exe`
   - Arguments: `src\main.py --config config\config.yaml`
   - Start in: `C:\Path\To\ssh-bruteforce-detector-windows`
5. Save (you'll be prompted for admin credentials).

This keeps it running in the background across reboots without needing
NSSM or a separate Windows service wrapper.

## Running Tests

The detection/parsing logic is pure Python and fully unit-testable without
Administrator rights or a live event log:

```powershell
pip install pytest
pytest tests\ -v
```

## How It Works

1. `log_monitor.py` polls the Security Event Log for new Event ID 4625
   entries (or tails a log file), extracting the source IP, username, and
   logon type.
2. `detector.py` keeps a per-IP deque of failure timestamps; anything
   outside the configured `window_seconds` is dropped, so only *recent*
   bursts count.
3. Once an IP's recent-failure count hits `max_failures`, `main.py` calls
   `ban_manager.py`, which adds a Windows Firewall `block` rule for that
   IP and records the ban (with expiry, if configured) to a JSON audit log.
4. A background thread periodically checks for expired bans and removes
   the corresponding firewall rule automatically.

## Extending

- Swap the webhook in `notifier.py` for email/Teams/PagerDuty as needed.
- Add a small Flask/FastAPI dashboard on top of `manage_bans.py`.
- Persist detector state to disk if you need failure counts to survive a
  restart of the script itself (currently in-memory only).

## Disclaimer

This tool modifies live Windows Firewall rules. Test with `--dry-run`
first, always whitelist your own access IP/VPN range, and keep an
out-of-band way to reach the machine (physical/console access, cloud
provider serial console, etc.) in case of misconfiguration.



## Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\WINDOWS\system32> cd F:\My_Projects\SSH-Bruteforce-Detector\ssh-bruteforce-detector
PS F:\My_Projects\SSH-Bruteforce-Detector\ssh-bruteforce-detector> python src\main.py --config config\config.yaml --dry-run
2026-07-25 22:34:42,848 [INFO] Starting SSH/RDP Brute Force Detector (max_failures=5, window=300s, source=eventlog, dry_run=True)

