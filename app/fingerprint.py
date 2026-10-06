"""
fingerprint.py — Device Profile & Fingerprint Engine

Handles MAC-randomization-resistant identification by hashing
the device's probed SSID list and IE capabilities into a stable key.
"""

import hashlib
import time
import json
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from config import RSSI_ROLLING_WINDOW, DEVICE_EXPIRY_SECONDS
from db import db

logger = logging.getLogger(__name__)


# ─── Device Classification Labels ────────────────────────────
class Classification:
    EMPLOYEE        = "Employee Device"
    SEARCHING       = "Searching Client"    # sends probes, not connected
    ROGUE_AP        = "Rogue Access Point"  # unknown beacon
    EVIL_TWIN       = "Evil Twin AP"        # spoofing office SSID
    UNKNOWN         = "Unknown"


@dataclass
class DeviceProfile:
    """
    In-RAM record for one unique device fingerprint.
    Multiple MACs can map to the same profile (MAC rotation).
    """
    fingerprint:          str
    known_macs:           set              = field(default_factory=set)
    probed_ssids:         list             = field(default_factory=list)
    first_seen:           float            = field(default_factory=time.time)
    last_seen:            float            = field(default_factory=time.time)
    rssi_window:          deque            = field(default_factory=lambda: deque(maxlen=RSSI_ROLLING_WINDOW))
    classification:       str              = Classification.UNKNOWN
    red_zone_entry_time:  Optional[float]  = None   # when it first hit -50 dBm
    alert_sent:           bool             = False
    advertised_ssids:     list             = field(default_factory=list)  # for AP detection
    last_bssid:           str              = ""
    ie_tags:              list             = field(default_factory=list)
    ie_tags_order:        list             = field(default_factory=list)
    ht_caps:              int              = 0
    vht_caps:             int              = 0
    he_caps:              int              = 0
    ext_caps:             int              = 0
    crypt_set:            int              = 0
    wps_uuid_e:           str              = ""
    vendor_ouis:          list             = field(default_factory=list)
    supported_rates:      list             = field(default_factory=list)
    ap_hw_signatures:     list             = field(default_factory=list)
    manuf:                str              = ""
    channel:              str              = ""
    in_red_zone_flag:     bool             = False
    confidence_tier:      str              = "mac"
    confidence_score:     int              = 0

    # ── Computed properties ──────────────────────────────────

    @property
    def rssi_average(self) -> Optional[float]:
        if not self.rssi_window:
            return None
        return sum(self.rssi_window) / len(self.rssi_window)

    @property
    def is_in_red_zone(self) -> bool:
        # Now driven by hysteresis logic in update(); fall back to legacy
        # threshold-only check when no samples yet so old callers still work.
        return self.in_red_zone_flag

    @property
    def seconds_in_red_zone(self) -> float:
        if self.red_zone_entry_time is None:
            return 0.0
        return time.time() - self.red_zone_entry_time

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > DEVICE_EXPIRY_SECONDS

    # ── Update helpers ───────────────────────────────────────

    def update(self, mac: str, rssi: int, probed_ssids: list,
               advertised_ssids: list = None, last_bssid: str = "",
               ie_tags: list = None, channel: str = "",
               ap_hw_signatures: list = None, manuf: str = "",
               device: dict = None):
        """Called every poll cycle when this device is still visible."""
        self.known_macs.add(mac)
        self.last_seen = time.time()
        # Defense-in-depth: ignore impossible RSSI values (Kismet sometimes
        # emits 0 for unmeasured devices, which would otherwise look "close").
        if rssi is not None and rssi < 0:
            self.rssi_window.append(rssi)
        if probed_ssids:
            self.probed_ssids = probed_ssids
        if advertised_ssids:
            self.advertised_ssids = advertised_ssids
        if last_bssid:
            self.last_bssid = last_bssid
        if ie_tags:
            self.ie_tags = ie_tags
        if ap_hw_signatures:
            self.ap_hw_signatures = ap_hw_signatures
        if channel:
            self.channel = channel
        if manuf:
            self.manuf = manuf
        # Absorb richer device features (passed via device dict from analyzer/runner)
        if device:
            io = device.get("ie_tags_order") or []
            if io:
                self.ie_tags_order = io
            for attr in ("ht_caps", "vht_caps", "he_caps", "ext_caps",
                         "crypt_set"):
                v = device.get(attr)
                if v:
                    setattr(self, attr, v)
            wuu = device.get("wps_uuid_e")
            if wuu:
                self.wps_uuid_e = wuu
            ouis = device.get("vendor_ouis")
            if ouis:
                self.vendor_ouis = list(ouis)
            rates = device.get("supported_rates")
            if rates:
                self.supported_rates = list(rates)

        # Hysteresis red-zone tracking.
        # Enter when avg > enter_threshold; leave only when avg <= exit_threshold.
        # Asymmetric thresholds prevent rapid flapping at the boundary.
        import settings as _cfg
        avg = self.rssi_average
        if avg is not None:
            enter_t = _cfg.effective_red_zone()
            exit_t  = enter_t - int(_cfg.get("rssi_exit_offset_db") or 5)
            if self.in_red_zone_flag:
                if avg <= exit_t:
                    self.in_red_zone_flag = False
                    self.red_zone_entry_time = None
                    self.alert_sent = False
            else:
                if avg > enter_t:
                    self.in_red_zone_flag = True
                    if self.red_zone_entry_time is None:
                        self.red_zone_entry_time = time.time()


# ─── Fingerprint Generation ───────────────────────────────────

def _norm(val) -> str:
    """Stable string repr — accepts int/str/list/None."""
    if val is None:
        return ""
    if isinstance(val, (list, tuple, set)):
        return ",".join(str(x) for x in val)
    return str(val)


def build_fingerprint(features: dict) -> tuple[str, str, int]:
    """
    Build multi-feature fingerprint. Returns (fingerprint, tier, score).

    Features dict may contain any of:
      probed_ssids, ie_tags_order, ht_caps, vht_caps, he_caps, ext_caps,
      crypt_set, wps_uuid_e, wps_state, ms_vsa, supported_rates,
      vendor_ouis, manuf, mac.

    Tier:
      "strong" — 3+ hardware/OS signals available (SSIDs, HT/VHT/HE, vendor OUIs)
      "medium" — 1-2 signals
      "mac"    — no useful signals, MAC-only fallback (per-MAC, fragile)

    Score 0-100 rough quality indicator.
    """
    ssids   = sorted((s.strip().lower() for s in (features.get("probed_ssids") or []) if s))
    tags    = features.get("ie_tags_order") or features.get("ie_tags") or []
    ht      = features.get("ht_caps")
    vht     = features.get("vht_caps")
    he      = features.get("he_caps")
    ext     = features.get("ext_caps")
    crypt   = features.get("crypt_set")
    wps_u   = features.get("wps_uuid_e")
    wps_s   = features.get("wps_state")
    ms      = features.get("ms_vsa")
    rates   = features.get("supported_rates") or []
    ouis    = features.get("vendor_ouis") or []
    manuf   = (features.get("manuf") or "").strip()
    mac     = (features.get("mac") or "").upper()

    # WPS UUID-E is globally unique by design — if present, use it directly
    if wps_u:
        h = hashlib.sha256(("wps:" + str(wps_u)).encode()).hexdigest()[:16]
        return ("wps_" + h, "strong", 100)

    parts = []
    score = 0
    if ssids:        parts.append("ssids:" + "|".join(ssids));                score += 30
    if tags:         parts.append("tags:"  + _norm(tags));                    score += 15
    if ht:           parts.append("ht:"    + _norm(ht));                      score += 12
    if vht:          parts.append("vht:"   + _norm(vht));                     score += 12
    if he:           parts.append("he:"    + _norm(he));                      score += 10
    if ext:          parts.append("ext:"   + _norm(ext));                     score += 8
    if crypt:        parts.append("crypt:" + _norm(crypt));                   score += 5
    if rates:        parts.append("rates:" + _norm(sorted(rates)));           score += 5
    if ouis:         parts.append("ouis:"  + _norm(sorted(ouis)));            score += 10
    if ms:           parts.append("ms:"    + _norm(ms));                      score += 3
    if wps_s:        parts.append("wpss:"  + _norm(wps_s));                   score += 2

    # Non-randomized MAC's OUI is informative (printer, IoT, old laptop)
    if mac and len(mac) >= 2:
        try:
            first = int(mac[:2], 16)
            if not (first & 0x02) and manuf:   # globally administered
                parts.append("manuf:" + manuf.lower())
                score += 8
        except Exception:
            pass

    if not parts:
        # Nothing observable — fall back to MAC hash
        return (mac_fingerprint(mac), "mac", 0)

    combined = "::".join(parts)
    h = hashlib.sha256(combined.encode()).hexdigest()[:16]

    if score >= 40:    tier = "strong"
    elif score >= 15:  tier = "medium"
    else:              tier = "weak"

    return ("fp_" + h, tier, score)


def mac_fingerprint(mac: str) -> str:
    """Last-resort fingerprint when no observable features. Breaks on MAC rotation."""
    return "mac_" + hashlib.sha256(mac.encode()).hexdigest()[:12]


# ─── Profile Database ─────────────────────────────────────────

class ProfileDatabase:
    """
    DB-backed store: fingerprint → DeviceProfile.

    SQLite holds the source of truth; an in-RAM cache mirrors recently
    seen profiles for fast per-cycle lookup. Rows survive process
    restarts so cross-session detection (visit history, behavioural
    baselining) becomes possible.
    """

    def __init__(self):
        self._profiles:  dict[str, DeviceProfile] = {}
        self._mac_index: dict[str, str] = {}
        self._load_recent()

    # ── DB ↔ RAM ───────────────────────────────────────────

    def _load_recent(self):
        """Rehydrate non-expired profiles from DB into the RAM cache."""
        cutoff = time.time() - DEVICE_EXPIRY_SECONDS
        rows = db.query(
            "SELECT * FROM profiles WHERE last_seen >= ?", (cutoff,)
        )
        for r in rows:
            try:
                p = DeviceProfile(
                    fingerprint         = r["fingerprint"],
                    first_seen          = r["first_seen"] or time.time(),
                    last_seen           = r["last_seen"]  or time.time(),
                    classification      = r["classification"] or Classification.UNKNOWN,
                    alert_sent          = bool(r["alert_sent"]),
                    red_zone_entry_time = r["red_zone_entry"],
                    in_red_zone_flag    = bool(r["in_red_zone"]),
                    last_bssid          = r["last_bssid"] or "",
                    manuf               = r["manuf"] or "",
                    channel             = r["channel"] or "",
                    probed_ssids        = json.loads(r["probed_ssids"]      or "[]"),
                    advertised_ssids    = json.loads(r["advertised_ssids"]  or "[]"),
                    ie_tags             = json.loads(r["ie_tags"]           or "[]"),
                    ap_hw_signatures    = json.loads(r["ap_hw_signatures"]  or "[]"),
                )
            except Exception as e:
                logger.warning(f"Skipping corrupt profile row {r.get('fingerprint')}: {e}")
                continue
            # Restore rolling window from last N valid samples.
            # Reject impossible values (>=0) — those are Kismet "unmeasured"
            # markers that would otherwise poison the average and push every
            # device into the red zone.
            samples = db.query(
                "SELECT rssi FROM rssi_samples WHERE fingerprint=? AND rssi < 0 "
                "ORDER BY ts DESC LIMIT ?",
                (p.fingerprint, RSSI_ROLLING_WINDOW),
            )
            for s in reversed(samples):
                p.rssi_window.append(s["rssi"])
            self._profiles[p.fingerprint] = p

        for r in db.query("SELECT mac, fingerprint FROM profile_macs"):
            if r["fingerprint"] in self._profiles:
                self._mac_index[r["mac"].upper()] = r["fingerprint"]
                self._profiles[r["fingerprint"]].known_macs.add(r["mac"].upper())

        if rows:
            logger.info(f"Rehydrated {len(self._profiles)} profiles from DB")

    def _persist(self, profile: DeviceProfile):
        """UPSERT a profile row + ensure mac index rows exist."""
        db.execute(
            "INSERT INTO profiles"
            "(fingerprint, first_seen, last_seen, classification, alert_sent, "
            " last_rssi, rssi_avg, in_red_zone, red_zone_entry, manuf, channel, "
            " is_ap, last_bssid, probed_ssids, advertised_ssids, ie_tags, ap_hw_signatures, "
            " confidence_tier, confidence_score) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET "
            " last_seen        = excluded.last_seen,"
            " classification   = excluded.classification,"
            " alert_sent       = excluded.alert_sent,"
            " last_rssi        = excluded.last_rssi,"
            " rssi_avg         = excluded.rssi_avg,"
            " in_red_zone      = excluded.in_red_zone,"
            " red_zone_entry   = excluded.red_zone_entry,"
            " manuf            = excluded.manuf,"
            " channel          = excluded.channel,"
            " is_ap            = excluded.is_ap,"
            " last_bssid       = excluded.last_bssid,"
            " probed_ssids     = excluded.probed_ssids,"
            " advertised_ssids = excluded.advertised_ssids,"
            " ie_tags          = excluded.ie_tags,"
            " ap_hw_signatures = excluded.ap_hw_signatures,"
            " confidence_tier  = excluded.confidence_tier,"
            " confidence_score = excluded.confidence_score",
            (
                profile.fingerprint,
                profile.first_seen,
                profile.last_seen,
                profile.classification,
                int(profile.alert_sent),
                (profile.rssi_window[-1] if profile.rssi_window else None),
                profile.rssi_average,
                int(profile.is_in_red_zone),
                profile.red_zone_entry_time,
                profile.manuf,
                profile.channel,
                int(bool(profile.advertised_ssids)),
                profile.last_bssid,
                json.dumps(profile.probed_ssids),
                json.dumps(profile.advertised_ssids),
                json.dumps(profile.ie_tags),
                json.dumps(profile.ap_hw_signatures),
                profile.confidence_tier,
                profile.confidence_score,
            ),
        )
        for m in profile.known_macs:
            db.execute(
                "INSERT OR IGNORE INTO profile_macs(mac, fingerprint) VALUES(?,?)",
                (m.upper(), profile.fingerprint),
            )

    # ── visit tracking ─────────────────────────────────────

    def _open_visit(self, fp: str, rssi: int):
        already = db.query_one(
            "SELECT id FROM visits WHERE fingerprint=? AND exited IS NULL", (fp,)
        )
        if already:
            return
        db.execute(
            "INSERT INTO visits(fingerprint, entered, max_rssi) VALUES(?,?,?)",
            (fp, time.time(), rssi),
        )

    def _update_visit_rssi(self, fp: str, rssi: int):
        db.execute(
            "UPDATE visits SET max_rssi = MAX(COALESCE(max_rssi,-200), ?) "
            "WHERE fingerprint=? AND exited IS NULL",
            (rssi, fp),
        )

    def _close_visit(self, fp: str):
        db.execute(
            "UPDATE visits SET exited=? "
            "WHERE fingerprint=? AND exited IS NULL",
            (time.time(), fp),
        )

    # ── public API (called by analyzer/runner each cycle) ──

    def get_or_create(self, mac: str, device: dict) -> DeviceProfile:
        """Lookup or create profile from a Kismet-normalized device dict."""
        features = {
            "mac":              mac,
            "manuf":            device.get("manuf", ""),
            "probed_ssids":     device.get("probed_ssids") or [],
            "ie_tags_order":    device.get("ie_tags_order") or device.get("ie_tags") or [],
            "ht_caps":          device.get("ht_caps"),
            "vht_caps":         device.get("vht_caps"),
            "he_caps":          device.get("he_caps"),
            "ext_caps":         device.get("ext_caps"),
            "crypt_set":        device.get("crypt_set"),
            "wps_uuid_e":       device.get("wps_uuid_e"),
            "wps_state":        device.get("wps_state"),
            "ms_vsa":           device.get("ms_vsa"),
            "supported_rates":  device.get("supported_rates"),
            "vendor_ouis":      device.get("vendor_ouis"),
        }
        fp, tier, score = build_fingerprint(features)
        if fp not in self._profiles:
            self._profiles[fp] = DeviceProfile(fingerprint=fp,
                                               confidence_tier=tier,
                                               confidence_score=score)
        profile = self._profiles[fp]
        # Tier may upgrade as more features arrive across cycles
        if score > profile.confidence_score:
            profile.confidence_tier  = tier
            profile.confidence_score = score
        self._mac_index[mac.upper()] = fp
        return profile

    def record_observation(self, profile: DeviceProfile, rssi: int):
        """
        Persist this cycle's update for `profile`:
          - append an rssi sample ONLY while the device is in the red zone
          - upsert profile row
          - manage visit lifecycle (red-zone enter/leave)
        Call this AFTER profile.update().
        """
        if profile.is_in_red_zone:
            # Only red-zone devices are worth persisting at full resolution —
            # they're the ones we chart and alert on. Sampling all ~25k devices
            # Kismet reports every cycle is what exploded rssi_samples. Live
            # detection uses the in-RAM rolling window, not this table, so this
            # gate costs nothing in accuracy.
            db.execute(
                "INSERT INTO rssi_samples(fingerprint, ts, rssi) VALUES(?,?,?)",
                (profile.fingerprint, time.time(), rssi),
            )
            self._open_visit(profile.fingerprint, rssi)
            self._update_visit_rssi(profile.fingerprint, rssi)
        else:
            self._close_visit(profile.fingerprint)

        self._persist(profile)

    def get_by_mac(self, mac: str) -> Optional[DeviceProfile]:
        fp = self._mac_index.get(mac.upper())
        return self._profiles.get(fp) if fp else None

    def all_profiles(self):
        return self._profiles.values()

    def purge_expired(self) -> int:
        """
        Drop expired profiles from RAM cache + close any open visits.
        DB rows are kept for history; only the live cache shrinks.
        """
        expired = [fp for fp, p in self._profiles.items() if p.is_expired]
        for fp in expired:
            self._close_visit(fp)
            dead_macs = [m for m, f in self._mac_index.items() if f == fp]
            for m in dead_macs:
                del self._mac_index[m]
            del self._profiles[fp]
        return len(expired)

    def count(self) -> int:
        return len(self._profiles)
