"""
logic_engine.py — The 4-Stage Evaluation Funnel

Takes a normalized device dict + profile and decides:
  - Drop it (noise / whitelisted)
  - Classify and alert
"""

import json
import logging
import time
from dataclasses import dataclass
from fingerprint import DeviceProfile, Classification
from whitelist import WhitelistManager
from db import db
import settings as cfg

logger = logging.getLogger(__name__)


@dataclass
class AlertEvent:
    alert_type:        str    # "ROGUE_AP"|"EVIL_TWIN"|"UNKNOWN_CLIENT"|"SPOOFED_AP"
    mac:               str
    fingerprint:       str
    rssi_avg:          float
    probed_ssids:      list
    spoofed_ssid:      str   = ""
    seconds_present:   float = 0
    spoof_reason:      str   = ""   # SPOOFED_AP only
    advertised_ssids:  list  = None  # what the AP is beaconing (ROGUE_AP/EVIL_TWIN/SPOOFED_AP)
    channel:           str   = ""


class LogicEngine:

    def __init__(self, whitelist: WhitelistManager):
        self.whitelist = whitelist

    def evaluate(self, device: dict, profile: DeviceProfile,
                 associated_clients: set | None = None) -> list[AlertEvent]:
        """
        Run the device through all 4 stages.
        Returns a list of AlertEvents (usually 0 or 1).

        `associated_clients` is the set of client MACs that Kismet has
        observed completing association with one of our office APs
        (AP-side `associated_client_map`). It is treated as an auxiliary
        trust signal — stronger than client-reported `last_bssid`, but
        not cryptographic: it can still be spoofed by a sufficiently
        capable on-air attacker. We use it only to suppress noise from
        legitimate office clients, not as a sole whitelist source.
        """
        mac           = device["mac"]
        rssi          = device["rssi"]
        probed_ssids  = device["probed_ssids"]
        advert_ssids  = device["advertised_ssids"]
        is_ap         = device["is_ap"]
        fingerprint   = profile.fingerprint
        associated_clients = associated_clients or set()

        alerts = []

        # ── Stage 1: Red Zone check ───────────────────────────
        # Use rolling average once we have data; fall back to raw RSSI
        avg_rssi = profile.rssi_average if profile.rssi_average is not None else rssi
        red_zone_threshold = cfg.effective_red_zone()
        if avg_rssi <= red_zone_threshold:
            logger.debug(f"[{mac}] Outside red zone (avg {avg_rssi:.0f} dBm, threshold {red_zone_threshold}) — skipping")
            return []

        # ── Stage 2: Whitelist check ──────────────────────────
        if self.whitelist.is_safe(mac, fingerprint):
            logger.debug(f"[{mac}] Whitelisted — ignoring")
            return []

        # ── Stage 3: Frame / device type check ───────────────

        # 3a. Known AP — verify it hasn't been hardware-spoofed
        if is_ap and self.whitelist.is_infrastructure(mac):
            infra = self.whitelist.get_infrastructure(mac)
            reason = None

            actual_channel  = device.get("channel", "")
            expected_channel = infra.get("channel", "")
            if actual_channel and expected_channel and actual_channel != expected_channel:
                reason = f"channel mismatch: expected {expected_channel}, got {actual_channel}"

            actual_hw   = sorted(device.get("ap_hw_signatures", []))
            expected_hw = sorted(infra.get("hw_signatures", []))
            if not reason and actual_hw and expected_hw and actual_hw != expected_hw:
                reason = f"hardware mismatch: expected {expected_hw}, got {actual_hw}"

            if reason and not profile.alert_sent and cfg.alert_enabled("SPOOFED_AP"):
                profile.alert_sent = True
                logger.warning(f"[SPOOFED AP] {mac} failed hardware check — {reason}")
                alerts.append(AlertEvent(
                    alert_type       = "SPOOFED_AP",
                    mac              = mac,
                    fingerprint      = fingerprint,
                    rssi_avg         = avg_rssi,
                    probed_ssids     = probed_ssids,
                    advertised_ssids = list(advert_ssids or []),
                    channel          = device.get("channel", ""),
                    spoof_reason     = reason,
                ))
            return alerts

        # 3b. Rogue AP — broadcasting a beacon but not in infra whitelist
        if is_ap and not self.whitelist.is_infrastructure(mac):
            # Check for Evil Twin first (higher severity)
            for ssid in advert_ssids:
                if ssid in self.whitelist.office_ssids:
                    logger.warning(f"[EVIL TWIN] {mac} is spoofing '{ssid}'!")
                    if not profile.alert_sent and cfg.alert_enabled("EVIL_TWIN"):
                        profile.alert_sent = True
                        alerts.append(AlertEvent(
                            alert_type       = "EVIL_TWIN",
                            mac              = mac,
                            fingerprint      = fingerprint,
                            rssi_avg         = avg_rssi,
                            probed_ssids     = probed_ssids,
                            spoofed_ssid     = ssid,
                            advertised_ssids = list(advert_ssids or []),
                            channel          = device.get("channel", ""),
                        ))
                    return alerts   # highest priority — no need to continue

            # Generic rogue AP
            logger.warning(f"[ROGUE AP] Unknown AP {mac} advertising {advert_ssids}")
            if not profile.alert_sent and cfg.alert_enabled("ROGUE_AP"):
                profile.alert_sent = True
                alerts.append(AlertEvent(
                    alert_type       = "ROGUE_AP",
                    mac              = mac,
                    fingerprint      = fingerprint,
                    rssi_avg         = avg_rssi,
                    probed_ssids     = probed_ssids,
                    advertised_ssids = list(advert_ssids or []),
                    channel          = device.get("channel", ""),
                ))
            return alerts

        # 3b. Searching client — only sending probe requests
        # (no advertised SSIDs, not an AP)

        # ── Stage 3c: AP-confirmed association grace ─────────
        # If one of our office APs reports this client MAC in its
        # associated_client_map, Kismet has seen the client complete
        # association at the AP side. Trust higher than client-reported
        # last_bssid; suppress UNKNOWN_CLIENT alert.
        if mac in associated_clients:
            logger.debug(f"[{mac}] AP-confirmed associated to office AP — skipping")
            return []

        # ── Stage 3d: Office SSID probe grace ────────────────
        # A device probing for our own SSID almost certainly knows
        # the network (returning employee, not a stranger). Skip alert.
        if any(ssid in self.whitelist.office_ssids for ssid in probed_ssids):
            logger.debug(f"[{mac}] Probing for office SSID — likely returning employee, skipping")
            return []

        # ── Stage 4: Sharpness timer ─────────────────────────
        seconds = profile.seconds_in_red_zone
        alert_timer = int(cfg.get("alert_timer_seconds"))
        logger.debug(
            f"[{mac}] Unknown client · avg RSSI {avg_rssi:.0f} dBm · "
            f"in red zone {seconds:.0f}s (threshold {alert_timer}s)"
        )

        if seconds >= alert_timer and not profile.alert_sent and cfg.alert_enabled("UNKNOWN_CLIENT"):
            profile.alert_sent = True
            profile.classification = Classification.SEARCHING
            logger.warning(
                f"[ALERT] Unknown client {mac} (fp={fingerprint}) "
                f"in red zone for {seconds:.0f}s — probing {probed_ssids}"
            )
            alerts.append(AlertEvent(
                alert_type      = "UNKNOWN_CLIENT",
                mac             = mac,
                fingerprint     = fingerprint,
                rssi_avg        = avg_rssi,
                probed_ssids    = probed_ssids,
                seconds_present = seconds,
            ))

        return alerts


def persist_alert(event: AlertEvent, *,
                  device_type: str = "", manuf: str = "", channel: str = "") -> int:
    """
    Insert or bump alert row keyed on (fingerprint, alert_type).

    Cooldown logic:
      • If previous alert for same (fp, type) is within `alert_cooldown_seconds`,
        bump `ts` and `count` on the existing row.
      • Otherwise treat as a fresh visit: reset `count` to 1, refresh `first_ts`.
    """
    now    = time.time()
    rssi   = float(event.rssi_avg) if event.rssi_avg is not None else None
    secs   = float(event.seconds_present) if event.seconds_present else None
    probes = json.dumps(event.probed_ssids or [])
    adverts = json.dumps(event.advertised_ssids or [])
    cooldown = int(cfg.get("alert_cooldown_seconds") or 600)

    existing = db.query_one(
        "SELECT id, ts, count, first_ts FROM alerts WHERE fingerprint=? AND alert_type=?",
        (event.fingerprint, event.alert_type),
    )

    if existing and (now - (existing["ts"] or 0)) <= cooldown:
        new_count = (existing["count"] or 1) + 1
        ap_channel = event.channel or channel
        db.execute(
            "UPDATE alerts SET "
            " ts=?, mac=?, rssi_avg=?, spoofed_ssid=COALESCE(?, spoofed_ssid),"
            " spoof_reason=COALESCE(?, spoof_reason), seconds_present=?, probed_ssids=?,"
            " advertised_ssids=?,"
            " device_type=COALESCE(?, device_type), manuf=COALESCE(?, manuf), channel=COALESCE(?, channel),"
            " count=? "
            "WHERE id=?",
            (now, event.mac, rssi, event.spoofed_ssid or None, event.spoof_reason or None,
             secs, probes, adverts,
             device_type or None, manuf or None, ap_channel or None,
             new_count, existing["id"]),
        )
        return new_count

    # No prior row OR cooldown expired → fresh visit
    if existing:
        db.execute("DELETE FROM alerts WHERE id=?", (existing["id"],))
    ap_channel = event.channel or channel
    db.execute(
        "INSERT INTO alerts"
        "(ts, first_ts, alert_type, mac, fingerprint, rssi_avg, "
        " spoofed_ssid, spoof_reason, seconds_present, probed_ssids, "
        " advertised_ssids, device_type, manuf, channel, count) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
        (now, now, event.alert_type, event.mac, event.fingerprint, rssi,
         event.spoofed_ssid or None, event.spoof_reason or None,
         secs, probes, adverts,
         device_type or None, manuf or None, ap_channel or None),
    )
    return 1
