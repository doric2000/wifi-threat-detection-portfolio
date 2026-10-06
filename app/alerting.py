"""
alerting.py — Alert Dispatcher

Sends alerts via console (always), Slack, and/or email.
Add more channels here as needed.
"""

import json
import logging
import smtplib
import time
from email.mime.text import MIMEText

try:
    import requests as req_lib
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from logic_engine import AlertEvent
from config import (
    ALERT_CONSOLE, ALERT_SLACK, ALERT_EMAIL,
    SLACK_WEBHOOK_URL,
    EMAIL_SMTP_HOST, EMAIL_FROM, EMAIL_TO, EMAIL_PASSWORD,
    ALERT_LOG_FILE
)

logger = logging.getLogger(__name__)


# ── Alert formatting ──────────────────────────────────────────

def _format_alert(event: AlertEvent) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🚨 WIFI ALERT  [{event.alert_type}]",
        f"Time         : {ts}",
        f"MAC          : {event.mac}",
        f"Fingerprint  : {event.fingerprint}",
        f"Avg RSSI     : {event.rssi_avg:.0f} dBm",
    ]

    if event.alert_type == "EVIL_TWIN":
        lines.append(f"⚠ Spoofing SSID : {event.spoofed_ssid}")
    elif event.alert_type == "ROGUE_AP":
        lines.append(f"Broadcasting unknown beacon")
    elif event.alert_type == "SPOOFED_AP":
        lines.append(f"⚠ MAC SPOOFING  : {event.spoof_reason}")
    elif event.alert_type == "UNKNOWN_CLIENT":
        lines.append(f"Time in zone : {event.seconds_present:.0f}s")
        lines.append(f"Probed SSIDs : {', '.join(event.probed_ssids) or 'none'}")

    lines.append(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


# ── Individual channel senders ────────────────────────────────

def _send_console(event: AlertEvent):
    print(_format_alert(event))
    # Also write to alert log file
    try:
        with open(ALERT_LOG_FILE, "a") as f:
            f.write(_format_alert(event) + "\n\n")
    except Exception as e:
        logger.warning(f"Could not write alert log: {e}")


def _send_slack(event: AlertEvent):
    if not _HAS_REQUESTS or not SLACK_WEBHOOK_URL:
        return
    payload = {
        "text": f"*[{event.alert_type}]* MAC `{event.mac}` "
                f"(fp: `{event.fingerprint}`) — RSSI avg {event.rssi_avg:.0f} dBm\n"
                + (f"Spoofing: *{event.spoofed_ssid}*" if event.spoofed_ssid else
                   f"Probing: {', '.join(event.probed_ssids)}")
    }
    try:
        r = req_lib.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        r.raise_for_status()
        logger.info("Slack alert sent")
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")


def _send_email(event: AlertEvent):
    if not EMAIL_SMTP_HOST or not EMAIL_FROM or not EMAIL_TO:
        return
    body = _format_alert(event)
    msg = MIMEText(body)
    msg["Subject"] = f"[WiFi ALERT] {event.alert_type} — {event.mac}"
    msg["From"]    = EMAIL_FROM
    msg["To"]      = EMAIL_TO
    try:
        with smtplib.SMTP_SSL(EMAIL_SMTP_HOST, 465) as s:
            s.login(EMAIL_FROM, EMAIL_PASSWORD)
            s.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        logger.info("Email alert sent")
    except Exception as e:
        logger.error(f"Email alert failed: {e}")


# ── Public dispatcher ─────────────────────────────────────────

class AlertDispatcher:

    def dispatch(self, event: AlertEvent):
        """Send alert to all enabled channels."""
        if ALERT_CONSOLE:
            _send_console(event)
        if ALERT_SLACK:
            _send_slack(event)
        if ALERT_EMAIL:
            _send_email(event)
