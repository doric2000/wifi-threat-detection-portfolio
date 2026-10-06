"""
runner.py — Async wrapper around the existing analyzer pipeline.

Runs the same pipeline as analyzer.py but as an asyncio task so
it can coexist with the FastAPI server in one process and push
events to the EventBus for WebSocket fan-out.
"""

import asyncio
import logging
import time
from dataclasses import asdict

from kismet_client import KismetClient
from fingerprint import ProfileDatabase
from whitelist import WhitelistManager
from logic_engine import LogicEngine, persist_alert
from alerting import AlertDispatcher
from config import POLL_INTERVAL, RSSI_RETENTION_DAYS
from db import db
import ignores

from web.event_bus import bus

logger = logging.getLogger("runner")

ALERT_HISTORY_MAX = 500

# Run retention pruning roughly hourly (cycles are POLL_INTERVAL seconds apart).
PRUNE_EVERY_CYCLES = max(1, int(3600 / POLL_INTERVAL))


class AnalyzerRunner:
    def __init__(self):
        self.kismet      = KismetClient()
        self.db          = ProfileDatabase()
        self.whitelist   = WhitelistManager()
        self.engine      = LogicEngine(self.whitelist)
        self.dispatcher  = AlertDispatcher()

        self.cycle           = 0
        self.last_devices:   list = []
        self.alerts_history: list = []

        self._task: asyncio.Task | None = None
        self._running = False

    # ── lifecycle ───────────────────────────────────────────

    async def start(self):
        if self._running:
            return {"ok": False, "reason": "already running"}
        if not self.kismet.test_connection():
            return {"ok": False, "reason": "Kismet unreachable at localhost:2501"}
        self._running = True
        self._task = asyncio.create_task(self._loop())
        bus.publish({"type": "status", "running": True, "ts": time.time()})
        return {"ok": True}

    async def stop(self):
        if not self._running:
            return {"ok": False, "reason": "not running"}
        self._running = False
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=POLL_INTERVAL + 5)
            except asyncio.TimeoutError:
                self._task.cancel()
            self._task = None
        bus.publish({"type": "status", "running": False, "ts": time.time()})
        return {"ok": True}

    @property
    def running(self) -> bool:
        return self._running

    # ── main loop ───────────────────────────────────────────

    async def _loop(self):
        while self._running:
            self.cycle += 1
            try:
                await self._cycle_once()
            except Exception as e:
                logger.exception(f"Cycle {self.cycle} failed: {e}")
                bus.publish({"type": "error", "message": str(e), "ts": time.time()})

            # cooperative sleep, breaks early on stop
            slept = 0.0
            while slept < POLL_INTERVAL and self._running:
                await asyncio.sleep(0.2)
                slept += 0.2

    async def _cycle_once(self):
        devices = await asyncio.to_thread(self.kismet.fetch_devices)
        associated = await asyncio.to_thread(
            self.kismet.fetch_associated_clients,
            self.whitelist.infrastructure_macs(),
        )

        live = []
        for device in devices:
            mac    = device["mac"]
            probed = device["probed_ssids"]
            ie_tags = device.get("ie_tags", [])
            profile = self.db.get_or_create(mac, device)
            profile.update(
                mac,
                device["rssi"],
                probed,
                device["advertised_ssids"],
                device.get("last_bssid", ""),
                ie_tags,
                device.get("channel", ""),
                device.get("ap_hw_signatures", []),
                device.get("manuf", ""),
                device=device,
            )

            self.db.record_observation(profile, device["rssi"])

            alerts = self.engine.evaluate(device, profile, associated)
            for alert in alerts:
                # Permanent-ignore rules — skip persist/dispatch/publish entirely
                if ignores.is_ignored(alert.alert_type, alert.fingerprint, alert.mac):
                    logger.debug(
                        f"ignored alert {alert.alert_type} fp={alert.fingerprint} mac={alert.mac}"
                    )
                    continue
                dtype = self._classify(device)
                count = persist_alert(
                    alert,
                    device_type=dtype,
                    manuf=device.get("manuf", ""),
                    channel=device.get("channel", ""),
                )
                self.dispatcher.dispatch(alert)
                data = asdict(alert)
                data["device_type"] = dtype
                data["manuf"]       = device.get("manuf", "")
                data["channel"]     = device.get("channel", "")
                data["count"]       = count
                event = {
                    "type": "alert",
                    "ts":   time.time(),
                    "data": data,
                }
                # In-memory history is also deduped by (fingerprint, alert_type):
                # update existing entry instead of stacking duplicates.
                key = (alert.fingerprint, alert.alert_type)
                replaced = False
                for i, e in enumerate(self.alerts_history):
                    if (e["data"].get("fingerprint"), e["data"].get("alert_type")) == key:
                        self.alerts_history[i] = event
                        replaced = True
                        break
                if not replaced:
                    self.alerts_history.append(event)
                if len(self.alerts_history) > ALERT_HISTORY_MAX:
                    self.alerts_history = self.alerts_history[-ALERT_HISTORY_MAX:]
                bus.publish(event)

            live.append(self._serialize(device, profile, mac in associated))

        self.last_devices = live
        # Persist the live snapshot so the UI and the Claude bot can read the
        # current view from SQL and it survives restarts.
        try:
            db.replace_live_devices(live)
        except Exception as e:
            logger.warning(f"Failed to persist live_devices snapshot: {e}")

        self.db.purge_expired()
        if RSSI_RETENTION_DAYS > 0 and self.cycle % PRUNE_EVERY_CYCLES == 0:
            try:
                db.prune_rssi(RSSI_RETENTION_DAYS * 86400)
            except Exception as e:
                logger.warning(f"rssi_samples prune failed: {e}")
        if self.cycle % 10 == 0:
            self.whitelist.reload()

        bus.publish({
            "type":    "cycle",
            "ts":      time.time(),
            "cycle":   self.cycle,
            "devices": live,
            "stats":   self.stats(),
        })

    # ── classification heuristic ────────────────────────────

    @staticmethod
    def _classify(device: dict) -> str:
        """
        Best-effort device-type guess (display only, NOT in fingerprint).
        manuf is unreliable for randomized MACs, but for non-randomized
        IoT / printers / laptops it's strong.
        """
        if device.get("is_ap"):
            return "AP / Router"

        manuf = (device.get("manuf") or "").lower()
        mac   = device.get("mac", "")

        if "apple" in manuf:                       return "Apple (iPhone/iPad/Mac)"
        if "samsung" in manuf:                     return "Samsung phone"
        if "xiaomi"  in manuf or "redmi" in manuf: return "Xiaomi / Redmi"
        if "huawei"  in manuf or "honor" in manuf: return "Huawei / Honor"
        if "google"  in manuf and "home" in manuf: return "Google Home"
        if "amazon"  in manuf:                     return "Amazon device"
        if "sonos"   in manuf:                     return "Sonos"
        if any(k in manuf for k in ["hp ", "deskjet", "canon", "epson", "brother"]):
            return "Printer"
        if "intel"   in manuf:                     return "Laptop (Intel Wi-Fi)"
        if "realtek" in manuf:                     return "Laptop (Realtek)"
        if "broadcom" in manuf:                    return "Laptop / IoT"
        if any(k in manuf for k in ["tp-link", "tplink", "ubiquiti", "mikrotik", "asus"]):
            return "Network gear"

        # locally-administered bit → randomized MAC
        try:
            first = int(mac[:2], 16)
            if first & 0x02:
                return "Randomized (phone/laptop)"
        except Exception:
            pass

        return manuf or "Unknown"

    # ── serialization ───────────────────────────────────────

    def _serialize(self, device: dict, profile, ap_confirmed: bool) -> dict:
        avg = profile.rssi_average
        last_bssid = device.get("last_bssid", "")
        bssid_label = ""
        if last_bssid:
            infra = self.whitelist.get_infrastructure(last_bssid)
            if infra:
                bssid_label = (infra.get("label") or
                               ", ".join(infra.get("ssids", [])[:1]) or
                               "office AP")
        return {
            "mac":               device["mac"],
            "fingerprint":       profile.fingerprint,
            "rssi":              device["rssi"],
            "rssi_avg":          round(avg, 1) if avg is not None else None,
            "is_ap":             device["is_ap"],
            "device_type":       self._classify(device),
            "probed_ssids":      device["probed_ssids"][:8],
            "advertised_ssids":  device["advertised_ssids"],
            "ap_hw_signatures":  device.get("ap_hw_signatures", []),
            "manuf":             device.get("manuf", ""),
            "channel":           device.get("channel", ""),
            "last_bssid":        last_bssid,
            "last_bssid_label":  bssid_label,
            "known_mac_count":   len(profile.known_macs),
            "first_seen":        profile.first_seen,
            "last_seen":         profile.last_seen,
            "seconds_in_zone":   round(profile.seconds_in_red_zone, 1),
            "in_red_zone":       profile.is_in_red_zone,
            "alert_sent":        profile.alert_sent,
            "is_safe":           self.whitelist.is_safe(device["mac"], profile.fingerprint),
            "is_infrastructure": self.whitelist.is_infrastructure(device["mac"]),
            "ap_confirmed":      ap_confirmed,
            "confidence_tier":   profile.confidence_tier,
            "confidence_score":  profile.confidence_score,
        }

    def stats(self) -> dict:
        return {
            "cycle":    self.cycle,
            "profiles": self.db.count(),
            "running":  self._running,
            **self.whitelist.stats(),
        }

    # ── whitelist ops (used by REST routes) ─────────────────

    def add_employee_by_mac(self, mac: str) -> dict:
        mac = mac.upper().strip()
        profile = self.db.get_by_mac(mac)
        if profile is None:
            for p in self.db.all_profiles():
                if mac in {m.upper() for m in p.known_macs}:
                    profile = p
                    break
        if profile is None:
            return {"ok": False, "reason": f"MAC {mac} not seen yet"}
        self.whitelist.add_employee(profile)
        return {"ok": True, "fingerprint": profile.fingerprint}

    def add_infrastructure_by_mac(self, mac: str, label: str = "") -> dict:
        mac = mac.upper().strip()
        seen = next((d for d in self.last_devices if d["mac"] == mac), None)
        if seen is None:
            return {"ok": False, "reason": f"MAC {mac} not seen yet"}
        self.whitelist.add_infrastructure(
            mac           = mac,
            label         = label,
            ssids         = seen.get("advertised_ssids", []),
            channel       = seen.get("channel", ""),
            hw_signatures = seen.get("ap_hw_signatures", []),
            manuf         = seen.get("manuf", ""),
        )
        return {"ok": True}

    # ── Setup helpers ───────────────────────────────────────

    def visible_aps(self) -> list:
        """All APs from the most recent cycle, sorted by RSSI."""
        aps = [d for d in self.last_devices if d.get("is_ap")]
        aps.sort(key=lambda d: (d.get("rssi_avg") or d.get("rssi") or -100), reverse=True)
        return aps

    def mark_safe_aps(self, macs: list, label: str = "") -> dict:
        """Bulk-add APs as infrastructure using their currently observed hw signature."""
        added, not_seen = 0, []
        for raw in macs:
            mac = raw.upper().strip()
            seen = next((d for d in self.last_devices if d["mac"] == mac), None)
            if seen is None:
                not_seen.append(mac)
                continue
            ap_label = label or ", ".join(seen.get("advertised_ssids", [])[:2])
            self.whitelist.add_infrastructure(
                mac           = mac,
                label         = ap_label,
                ssids         = seen.get("advertised_ssids", []),
                channel       = seen.get("channel", ""),
                hw_signatures = seen.get("ap_hw_signatures", []),
                manuf         = seen.get("manuf", ""),
            )
            added += 1
        return {"ok": True, "added": added, "not_seen": not_seen}

    def site_survey(self) -> dict:
        """
        Walk visible whitelisted APs, compute median RSSI = office baseline.
        UI uses this as the anchor for dynamic threshold (baseline - offset).
        """
        infra_macs = {m.upper() for m in self.whitelist.infrastructure_macs()}
        if not infra_macs:
            return {"ok": False, "reason": "No infrastructure APs whitelisted yet"}

        rssis = []
        per_ap = []
        for d in self.last_devices:
            if d["mac"].upper() in infra_macs:
                r = d.get("rssi_avg") if d.get("rssi_avg") is not None else d.get("rssi")
                if r is not None and r < 0:
                    rssis.append(r)
                    per_ap.append({
                        "mac":   d["mac"],
                        "ssids": d.get("advertised_ssids", []),
                        "rssi":  r,
                    })

        if not rssis:
            return {"ok": False, "reason": "Whitelisted APs not visible in current cycle. Start engine and wait."}

        rssis.sort()
        median = rssis[len(rssis) // 2]
        return {"ok": True, "baseline_rssi": int(median), "samples": per_ap}

    def rescan_connected_devices(self) -> dict:
        """
        Query Kismet for every client currently associated with one of our
        whitelisted APs, and add their profile as an employee device.
        """
        infra_macs = self.whitelist.infrastructure_macs()
        if not infra_macs:
            return {"ok": False, "reason": "No infrastructure APs whitelisted yet"}

        associated = self.kismet.fetch_associated_clients(infra_macs)
        added, skipped, not_seen = 0, 0, 0

        for mac in associated:
            profile = self.db.get_by_mac(mac)
            if profile is None:
                for p in self.db.all_profiles():
                    if mac in {m.upper() for m in p.known_macs}:
                        profile = p
                        break
            if profile is None:
                not_seen += 1
                continue

            if self.whitelist.is_safe(mac, profile.fingerprint):
                skipped += 1
                continue

            self.whitelist.add_employee(profile)
            added += 1

        return {
            "ok":               True,
            "added":            added,
            "already_safe":     skipped,
            "not_seen":         not_seen,
            "total_associated": len(associated),
        }


runner = AnalyzerRunner()
