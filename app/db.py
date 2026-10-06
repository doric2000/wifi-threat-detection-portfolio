"""
db.py — Single SQLite store for the WiFi Analyzer.

Holds profiles, RSSI history, alerts, and the whitelist.
Kismet remains the upstream live source; this DB is everything we
care about persisting locally. Independent of Kismet's SQLite log.
"""

import sqlite3
import json
import os
import time
import logging
from typing import Optional

from config import ANALYZER_DB

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    fingerprint       TEXT PRIMARY KEY,
    first_seen        REAL NOT NULL,
    last_seen         REAL NOT NULL,
    classification    TEXT,
    alert_sent        INTEGER DEFAULT 0,
    last_rssi         INTEGER,
    rssi_avg          REAL,
    in_red_zone       INTEGER DEFAULT 0,
    red_zone_entry    REAL,
    manuf             TEXT,
    channel           TEXT,
    is_ap             INTEGER DEFAULT 0,
    last_bssid        TEXT,
    probed_ssids      TEXT,
    advertised_ssids  TEXT,
    ie_tags           TEXT,
    ap_hw_signatures  TEXT
);

CREATE TABLE IF NOT EXISTS profile_macs (
    mac          TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES profiles(fingerprint) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_profile_macs_fp ON profile_macs(fingerprint);

CREATE TABLE IF NOT EXISTS rssi_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    ts          REAL NOT NULL,
    rssi        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rssi_fp_ts ON rssi_samples(fingerprint, ts);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL NOT NULL,
    alert_type      TEXT NOT NULL,
    mac             TEXT NOT NULL,
    fingerprint     TEXT,
    rssi_avg        REAL,
    spoofed_ssid    TEXT,
    spoof_reason    TEXT,
    seconds_present REAL,
    probed_ssids    TEXT,
    device_type     TEXT,
    manuf           TEXT,
    channel         TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS visits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    entered     REAL NOT NULL,
    exited      REAL,
    max_rssi    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_visits_fp ON visits(fingerprint);

CREATE TABLE IF NOT EXISTS wl_employees (
    fingerprint TEXT PRIMARY KEY,
    added_ts    REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wl_employee_macs (
    mac          TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL,
    FOREIGN KEY (fingerprint) REFERENCES wl_employees(fingerprint) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wl_infrastructure (
    mac           TEXT PRIMARY KEY,
    label         TEXT,
    ssids         TEXT,
    channel       TEXT,
    hw_signatures TEXT,
    manuf         TEXT,
    added_ts      REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS wl_office_ssids (
    ssid TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS alert_ignores (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type  TEXT NOT NULL,
    fingerprint TEXT,
    mac         TEXT,
    reason      TEXT,
    created_ts  REAL NOT NULL,
    UNIQUE(alert_type, fingerprint, mac)
);
CREATE INDEX IF NOT EXISTS idx_ignores_type ON alert_ignores(alert_type);

-- Snapshot of the devices visible in the most recent poll cycle. Replaced
-- wholesale each cycle so the UI (and the Claude bot) can read the live view
-- from SQL instead of process RAM, and it survives restarts.
CREATE TABLE IF NOT EXISTS live_devices (
    mac               TEXT PRIMARY KEY,
    fingerprint       TEXT,
    rssi              INTEGER,
    rssi_avg          REAL,
    is_ap             INTEGER,
    device_type       TEXT,
    manuf             TEXT,
    channel           TEXT,
    last_bssid        TEXT,
    last_bssid_label  TEXT,
    known_mac_count   INTEGER,
    first_seen        REAL,
    last_seen         REAL,
    seconds_in_zone   REAL,
    in_red_zone       INTEGER,
    alert_sent        INTEGER,
    is_safe           INTEGER,
    is_infrastructure INTEGER,
    ap_confirmed      INTEGER,
    confidence_tier   TEXT,
    confidence_score  INTEGER,
    updated_ts        REAL,
    probed_ssids      TEXT,
    advertised_ssids  TEXT,
    ap_hw_signatures  TEXT
);
"""

# Columns of live_devices in INSERT order; the JSON_COLS are stored as text.
LIVE_DEVICE_COLS = [
    "mac", "fingerprint", "rssi", "rssi_avg", "is_ap", "device_type", "manuf",
    "channel", "last_bssid", "last_bssid_label", "known_mac_count", "first_seen",
    "last_seen", "seconds_in_zone", "in_red_zone", "alert_sent", "is_safe",
    "is_infrastructure", "ap_confirmed", "confidence_tier", "confidence_score",
    "updated_ts", "probed_ssids", "advertised_ssids", "ap_hw_signatures",
]
LIVE_DEVICE_JSON_COLS = {"probed_ssids", "advertised_ssids", "ap_hw_signatures"}


class DB:
    def __init__(self, path: str = ANALYZER_DB):
        self.path = path
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        self._conn = sqlite3.connect(
            path, check_same_thread=False, isolation_level=None,
            timeout=10.0,
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)
        self._add_missing_columns()
        logger.info(f"Analyzer DB ready at {path}")

    def _add_missing_columns(self):
        """Idempotent column-add migrations for older DBs."""
        existing = {row[1] for row in self._conn.execute("PRAGMA table_info(alerts)")}
        for col in ("device_type", "manuf", "channel"):
            if col not in existing:
                self._conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
        if "count" not in existing:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN count INTEGER DEFAULT 1")
        if "first_ts" not in existing:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN first_ts REAL")
            self._conn.execute("UPDATE alerts SET first_ts = ts WHERE first_ts IS NULL")
        if "advertised_ssids" not in existing:
            self._conn.execute("ALTER TABLE alerts ADD COLUMN advertised_ssids TEXT")

        prof_cols = {row[1] for row in self._conn.execute("PRAGMA table_info(profiles)")}
        if "confidence_tier" not in prof_cols:
            self._conn.execute("ALTER TABLE profiles ADD COLUMN confidence_tier TEXT DEFAULT 'mac'")
        if "confidence_score" not in prof_cols:
            self._conn.execute("ALTER TABLE profiles ADD COLUMN confidence_score INTEGER DEFAULT 0")

        # Deduplicate existing rows (keep latest per fingerprint+alert_type),
        # then add the unique index for future UPSERTs. Rows without a fingerprint
        # are kept as-is (they're rare and shouldn't collide).
        self._conn.execute("""
            DELETE FROM alerts
            WHERE fingerprint IS NOT NULL
              AND id NOT IN (
                SELECT MAX(id) FROM alerts
                WHERE fingerprint IS NOT NULL
                GROUP BY fingerprint, alert_type
              )
        """)
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_fp_type "
            "ON alerts(fingerprint, alert_type) WHERE fingerprint IS NOT NULL"
        )

    # ── helpers ────────────────────────────────────────────

    def execute(self, sql: str, params: tuple = ()):
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, seq):
        return self._conn.executemany(sql, seq)

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        cur = self._conn.execute(sql, params)
        cols = [c[0] for c in cur.description] if cur.description else []
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def query_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def get_meta(self, key: str) -> Optional[str]:
        row = self.query_one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else None

    def set_meta(self, key: str, value: str):
        self._conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def replace_live_devices(self, rows: list[dict]):
        """
        Replace the live_devices snapshot with the current cycle's devices.
        `rows` are the dicts produced by AnalyzerRunner._serialize(); list-valued
        fields are JSON-encoded. Done as a single atomic swap.
        """
        now = time.time()
        params = []
        for r in rows:
            vals = []
            for col in LIVE_DEVICE_COLS:
                if col == "updated_ts":
                    vals.append(now)
                elif col in LIVE_DEVICE_JSON_COLS:
                    vals.append(json.dumps(r.get(col, []) or []))
                else:
                    v = r.get(col)
                    if isinstance(v, bool):
                        v = int(v)
                    vals.append(v)
            params.append(tuple(vals))

        placeholders = ",".join("?" for _ in LIVE_DEVICE_COLS)
        cols = ",".join(LIVE_DEVICE_COLS)
        self._conn.execute("BEGIN")
        try:
            self._conn.execute("DELETE FROM live_devices")
            if params:
                self._conn.executemany(
                    f"INSERT INTO live_devices({cols}) VALUES({placeholders})",
                    params,
                )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def prune_rssi(self, retention_seconds: float) -> int:
        """Delete rssi_samples older than the retention window. Returns rows removed."""
        cutoff = time.time() - retention_seconds
        cur = self._conn.execute("DELETE FROM rssi_samples WHERE ts < ?", (cutoff,))
        removed = cur.rowcount or 0
        if removed:
            logger.info("Pruned %d rssi_samples older than %.0fs", removed, retention_seconds)
        return removed

    def close(self):
        self._conn.close()


# ── singleton ──────────────────────────────────────────────

db = DB()


# ── one-time migration: import legacy known_devices.json ───

def migrate_whitelist_json_once(json_path: str, office_ssids_seed: list):
    """
    On first run, import the legacy JSON whitelist into the DB.
    Idempotent: marks itself done in `meta` table.
    """
    if db.get_meta("wl_imported") == "1":
        return

    # Always seed office SSIDs from config
    for s in office_ssids_seed:
        db.execute(
            "INSERT OR IGNORE INTO wl_office_ssids(ssid) VALUES(?)", (s,)
        )

    if not os.path.exists(json_path):
        db.set_meta("wl_imported", "1")
        return

    try:
        with open(json_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read legacy whitelist for migration: {e}")
        db.set_meta("wl_imported", "1")
        return

    now = time.time()

    for entry in data.get("employee_devices", []):
        fp = entry.get("fingerprint")
        if not fp:
            continue
        db.execute(
            "INSERT OR IGNORE INTO wl_employees(fingerprint, added_ts) VALUES(?,?)",
            (fp, now),
        )
        for mac in entry.get("known_macs", []):
            db.execute(
                "INSERT OR IGNORE INTO wl_employee_macs(mac, fingerprint) VALUES(?,?)",
                (mac.upper(), fp),
            )

    for item in data.get("infrastructure_devices", []):
        mac = item.get("mac", "").upper()
        if not mac:
            continue
        db.execute(
            "INSERT OR IGNORE INTO wl_infrastructure"
            "(mac, label, ssids, channel, hw_signatures, manuf, added_ts) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                mac,
                item.get("label", ""),
                json.dumps(item.get("ssids", [])),
                item.get("channel", ""),
                json.dumps(item.get("hw_signatures", [])),
                item.get("manuf", ""),
                now,
            ),
        )
        for s in item.get("ssids", []):
            db.execute("INSERT OR IGNORE INTO wl_office_ssids(ssid) VALUES(?)", (s,))

    for mac in data.get("infrastructure_macs", []):
        mac = mac.upper()
        db.execute(
            "INSERT OR IGNORE INTO wl_infrastructure(mac, added_ts) VALUES(?,?)",
            (mac, now),
        )

    for s in data.get("office_ssids", []):
        db.execute("INSERT OR IGNORE INTO wl_office_ssids(ssid) VALUES(?)", (s,))

    db.set_meta("wl_imported", "1")
    logger.info("Legacy whitelist JSON imported into SQLite")
