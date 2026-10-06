"""
ignores.py — Permanent alert suppression rules.

A rule matches an incoming alert when:
  - alert_type matches exactly
  - fingerprint matches OR rule.fingerprint is NULL (= any device)
  - mac         matches OR rule.mac         is NULL (= any device)

Examples:
  (EVIL_TWIN, mac=AP2_MAC)         → that one twin AP is allowed (you have 2 APs broadcasting same SSID)
  (UNKNOWN_CLIENT, fp=<hash>)      → that one person is allowed (e.g. cleaner)
  (ROGUE_AP, fp=NULL, mac=NULL)    → disable rogue-AP alerts globally
"""

import time
import logging
from db import db

logger = logging.getLogger(__name__)


def list_all() -> list[dict]:
    return db.query("SELECT * FROM alert_ignores ORDER BY created_ts DESC")


def add(alert_type: str, fingerprint: str = None, mac: str = None,
        reason: str = "") -> dict:
    if not alert_type:
        return {"ok": False, "reason": "alert_type required"}
    fp  = fingerprint or None
    m   = (mac or "").upper() or None
    now = time.time()
    try:
        db.execute(
            "INSERT INTO alert_ignores(alert_type, fingerprint, mac, reason, created_ts) "
            "VALUES(?,?,?,?,?)",
            (alert_type, fp, m, reason or None, now),
        )
    except Exception as e:
        return {"ok": False, "reason": f"already ignored or invalid: {e}"}
    logger.info(f"ignore rule added: type={alert_type} fp={fp} mac={m} reason={reason}")
    return {"ok": True}


def remove(rule_id: int) -> bool:
    db.execute("DELETE FROM alert_ignores WHERE id=?", (rule_id,))
    return True


def is_ignored(alert_type: str, fingerprint: str = None, mac: str = None) -> bool:
    """True if any rule matches this alert."""
    m = (mac or "").upper() or None
    row = db.query_one(
        "SELECT 1 FROM alert_ignores "
        "WHERE alert_type = ? "
        "  AND (fingerprint IS NULL OR fingerprint = ?) "
        "  AND (mac         IS NULL OR mac         = ?) "
        "LIMIT 1",
        (alert_type, fingerprint, m),
    )
    return row is not None
