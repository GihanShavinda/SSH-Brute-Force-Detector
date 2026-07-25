"""
notifier.py
-----------
Sends an optional webhook notification (Slack/Discord/generic JSON
endpoint) whenever an IP is banned.
"""

import json
import logging
import urllib.request
from typing import Optional

logger = logging.getLogger("ssh-bf-detector")


def send_ban_alert(webhook_url: Optional[str], ip: str, failure_count: int) -> None:
    if not webhook_url:
        return

    payload = {
        "text": f":no_entry: Banned IP `{ip}` after {failure_count} failed SSH login attempts."
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to send webhook notification: %s", exc)
