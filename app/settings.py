"""
settings.py — Runtime-mutable detection settings stored in SQLite.

config.py values become defaults; the user can override them from the UI
without editing files or restarting. Read order on every access:
  1. SQLite `settings` table (user override)
  2. config.py constant (default)
"""

import json
import logging

from db import db
from config import (
    RSSI_RED_ZONE       as CFG_RSSI_RED_ZONE,
    ALERT_TIMER_SECONDS as CFG_ALERT_TIMER_SECONDS,
)

logger = logging.getLogger(__name__)


SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""
db.execute(SCHEMA)


DEFAULTS = {
    "rssi_red_zone":          CFG_RSSI_RED_ZONE,           # dBm enter threshold
    "rssi_exit_offset_db":    5,                           # exit threshold = enter - this (hysteresis)
    "alert_timer_seconds":    CFG_ALERT_TIMER_SECONDS,     # seconds before UNKNOWN_CLIENT fires
    "use_dynamic_threshold":  False,                       # relative to office AP RSSI
    "dynamic_offset_db":      15,                          # threshold = office_ap_rssi - this
    "baseline_office_rssi":   None,                        # last site survey result
    "enabled_alerts":         ["UNKNOWN_CLIENT", "ROGUE_AP", "EVIL_TWIN", "SPOOFED_AP"],
    "alert_cooldown_seconds": 600,                         # bump count instead of new visit if < this
}


def _get_raw(key: str):
    row = db.query_one("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else None


def get(key: str):
    raw = _get_raw(key)
    if raw is None:
        return DEFAULTS.get(key)
    try:
        return json.loads(raw)
    except Exception:
        return raw


def set_(key: str, value) -> None:
    payload = json.dumps(value)
    db.execute(
        "INSERT INTO settings(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, payload),
    )
    logger.info(f"setting {key} = {value}")


def all_settings() -> dict:
    return {k: get(k) for k in DEFAULTS}


# ── Effective threshold (handles dynamic mode) ─────────────────

def effective_red_zone() -> int:
    """Threshold in dBm. Dynamic mode = office_ap_baseline - offset."""
    if get("use_dynamic_threshold"):
        baseline = get("baseline_office_rssi")
        offset   = get("dynamic_offset_db")
        if baseline is not None:
            return int(baseline) - int(offset)
    return int(get("rssi_red_zone"))


def alert_enabled(alert_type: str) -> bool:
    enabled = get("enabled_alerts") or []
    return alert_type in enabled
