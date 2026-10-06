"""
whitelist.py — DB-backed whitelist manager.

Backed by SQLite (`analyzer.db`). The legacy `known_devices.json`
file is still imported on first run for backward compatibility.
Used by logic_engine and the web UI.
"""

import json
import logging
import time
from typing import Optional

from config import WHITELIST_FILE, OFFICE_SSIDS
from db import db, migrate_whitelist_json_once

logger = logging.getLogger(__name__)


class WhitelistManager:
    """
    Deny-by-default. A device is safe if its MAC or fingerprint is
    listed. Infra APs are stored with channel + hw_signatures so the
    logic engine can detect MAC-spoofing via hardware mismatch.

    All state lives in SQLite; an in-RAM cache is rebuilt on `_load()`
    and `reload()` for fast `is_safe`/`is_infrastructure` lookups.
    """

    def __init__(self):
        migrate_whitelist_json_once(WHITELIST_FILE, OFFICE_SSIDS)

        self._safe_macs:         set  = set()
        self._safe_fingerprints: set  = set()
        self._fp_to_macs:        dict = {}
        self._infrastructure:    dict = {}   # mac → {label, ssids, channel, hw_signatures, manuf}
        self._office_ssids:      set  = set(OFFICE_SSIDS)
        self._load()

    # ── load from DB into RAM cache ────────────────────────

    def _load(self):
        self._safe_macs.clear()
        self._safe_fingerprints.clear()
        self._fp_to_macs.clear()
        self._infrastructure.clear()
        self._office_ssids = set(OFFICE_SSIDS)

        for row in db.query("SELECT fingerprint FROM wl_employees"):
            fp = row["fingerprint"]
            self._safe_fingerprints.add(fp)
            self._fp_to_macs[fp] = set()

        for row in db.query("SELECT mac, fingerprint FROM wl_employee_macs"):
            mac = row["mac"].upper()
            fp  = row["fingerprint"]
            self._safe_macs.add(mac)
            self._fp_to_macs.setdefault(fp, set()).add(mac)

        for row in db.query(
            "SELECT mac, label, ssids, channel, hw_signatures, manuf "
            "FROM wl_infrastructure"
        ):
            mac = row["mac"].upper()
            try:    ssids = json.loads(row["ssids"] or "[]")
            except Exception: ssids = []
            try:    hw    = json.loads(row["hw_signatures"] or "[]")
            except Exception: hw    = []
            self._infrastructure[mac] = {
                "label":         row["label"] or "",
                "ssids":         ssids,
                "channel":       row["channel"] or "",
                "hw_signatures": hw,
                "manuf":         row["manuf"] or "",
            }
            for s in ssids:
                self._office_ssids.add(s)

        for row in db.query("SELECT ssid FROM wl_office_ssids"):
            self._office_ssids.add(row["ssid"])

        logger.info(
            f"Whitelist loaded: {len(self._safe_fingerprints)} fingerprints, "
            f"{len(self._safe_macs)} MACs, "
            f"{len(self._infrastructure)} infra APs, "
            f"{len(self._office_ssids)} office SSIDs"
        )

    # ── lookups ────────────────────────────────────────────

    def is_safe(self, mac: str, fingerprint: str) -> bool:
        return (
            mac.upper() in self._safe_macs or
            fingerprint in self._safe_fingerprints
        )

    def is_infrastructure(self, mac: str) -> bool:
        return mac.upper() in self._infrastructure

    def get_infrastructure(self, mac: str) -> Optional[dict]:
        return self._infrastructure.get(mac.upper())

    def infrastructure_macs(self) -> list:
        return list(self._infrastructure.keys())

    @property
    def office_ssids(self) -> set:
        return self._office_ssids

    # ── mutations (DB write-through) ───────────────────────

    def add_employee(self, profile) -> None:
        fp   = profile.fingerprint
        macs = {m.upper() for m in profile.known_macs}
        now  = time.time()

        db.execute(
            "INSERT OR IGNORE INTO wl_employees(fingerprint, added_ts) VALUES(?,?)",
            (fp, now),
        )
        for m in macs:
            db.execute(
                "INSERT OR REPLACE INTO wl_employee_macs(mac, fingerprint) VALUES(?,?)",
                (m, fp),
            )

        self._safe_fingerprints.add(fp)
        self._safe_macs.update(macs)
        self._fp_to_macs.setdefault(fp, set()).update(macs)
        logger.info(f"Added employee fingerprint {fp} ({len(macs)} MACs)")

    def add_infrastructure(self, mac: str, label: str = "",
                           ssids: list = None, channel: str = "",
                           hw_signatures: list = None, manuf: str = "") -> None:
        mac = mac.upper()
        ssids = ssids or []
        hw    = hw_signatures or []
        now   = time.time()

        db.execute(
            "INSERT OR REPLACE INTO wl_infrastructure"
            "(mac, label, ssids, channel, hw_signatures, manuf, added_ts) "
            "VALUES(?,?,?,?,?,?,?)",
            (mac, label, json.dumps(ssids), channel, json.dumps(hw), manuf, now),
        )
        for s in ssids:
            if s:
                db.execute(
                    "INSERT OR IGNORE INTO wl_office_ssids(ssid) VALUES(?)", (s,)
                )

        self._infrastructure[mac] = {
            "label":         label,
            "ssids":         ssids,
            "channel":       channel,
            "hw_signatures": hw,
            "manuf":         manuf,
        }
        for s in ssids:
            if s:
                self._office_ssids.add(s)
        logger.info(f"Added infra AP {mac} ({label}) ch={channel} ssids={ssids}")

    def remove_employee(self, fingerprint: str) -> bool:
        if fingerprint not in self._safe_fingerprints:
            return False
        db.execute("DELETE FROM wl_employees WHERE fingerprint=?", (fingerprint,))
        # cascade removes employee_macs rows
        macs = self._fp_to_macs.pop(fingerprint, set())
        self._safe_fingerprints.discard(fingerprint)
        for m in macs:
            self._safe_macs.discard(m)
        logger.info(f"Removed employee fingerprint {fingerprint}")
        return True

    def remove_infrastructure(self, mac: str) -> bool:
        mac = mac.upper()
        if mac not in self._infrastructure:
            return False
        db.execute("DELETE FROM wl_infrastructure WHERE mac=?", (mac,))
        del self._infrastructure[mac]
        logger.info(f"Removed infrastructure AP {mac}")
        return True

    # ── listings (used by web UI) ──────────────────────────

    def employees(self) -> list:
        return [
            {"fingerprint": fp, "known_macs": list(self._fp_to_macs.get(fp, set()))}
            for fp in self._safe_fingerprints
        ]

    def infrastructure(self) -> list:
        return [{"mac": mac, **profile}
                for mac, profile in self._infrastructure.items()]

    # ── lifecycle ──────────────────────────────────────────

    def reload(self):
        self._load()

    def stats(self) -> dict:
        return {
            "employee_fingerprints": len(self._safe_fingerprints),
            "safe_macs":             len(self._safe_macs),
            "infrastructure_macs":   len(self._infrastructure),
        }
