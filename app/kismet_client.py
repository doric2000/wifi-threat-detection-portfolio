"""
kismet_client.py — Kismet REST API Watcher

Polls the Kismet REST API every POLL_INTERVAL seconds and returns
normalized device records ready for the logic engine.
"""

import requests
import logging
import json
from typing import Optional
from config import (
    KISMET_HOST, KISMET_USER, KISMET_PASSWORD,
    KISMET_ENDPOINT, KISMET_FIELDS
)

logger = logging.getLogger(__name__)


class KismetClient:

    def __init__(self):
        self.base_url = KISMET_HOST
        self.active_endpoint = KISMET_ENDPOINT
        self.session  = requests.Session()
        self.session.auth = (KISMET_USER, KISMET_PASSWORD)
        self.session.headers.update({"Content-Type": "application/json"})

    def _post(self, endpoint: str, body: dict) -> Optional[list]:
        url = f"{self.base_url}{endpoint}"
        try:
            resp = self.session.post(url, json=body, timeout=8)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            logger.error("Cannot reach Kismet — is it running on localhost:2501?")
        except requests.exceptions.Timeout:
            logger.warning("Kismet API timed out")
        except requests.exceptions.HTTPError as e:
            logger.error(f"Kismet HTTP error: {e}")
        except Exception as e:
            logger.error(f"Unexpected Kismet error: {e}")
        return None

    def _fetch_with_fallback(self, body: dict) -> Optional[list]:
        """Try configured endpoint first, then known compatible fallbacks on 404-like failures."""
        endpoints = [
            self.active_endpoint,
            "/devices/views/phy-IEEE802.11/devices.json",
            "/devices/views/all/devices.json",
            "/devices/all_devices.ekjson",
        ]

        # Preserve order while removing duplicates.
        seen = set()
        ordered = []
        for ep in endpoints:
            if ep and ep not in seen:
                seen.add(ep)
                ordered.append(ep)

        for idx, endpoint in enumerate(ordered):
            raw = self._post(endpoint, body)
            if raw is not None:
                if self.active_endpoint != endpoint:
                    logger.warning(
                        f"Configured endpoint failed; switched to working endpoint: {endpoint}"
                    )
                    self.active_endpoint = endpoint
                return raw

            if idx < len(ordered) - 1:
                logger.debug(f"Endpoint failed, trying fallback: {ordered[idx + 1]}")

        return None

    def fetch_devices(self) -> list[dict]:
        """
        Pull all Wi-Fi client devices from Kismet and return a
        clean list of normalized dicts.
        """
        body = {"fields": KISMET_FIELDS}
        raw = self._fetch_with_fallback(body)
        if raw is None:
            return []

        devices = []
        for d in raw:
            parsed = self._parse_device(d)
            if parsed:
                devices.append(parsed)

        logger.debug(f"Fetched {len(devices)} devices from Kismet")
        return devices

    def _parse_device(self, d: dict) -> Optional[dict]:
        """
        Normalize one raw Kismet device record into a flat dict.
        Returns None if the record is too incomplete to use.
        """
        try:
            mac  = d.get("kismet.device.base.macaddr", "").upper()
            if not mac:
                return None

            # Kismet can return signal as a flat key or nested dict depending on view.
            # Treat 0 / positive values as "no measurement yet" — real Wi-Fi RSSI is always negative.
            rssi = d.get("kismet.common.signal.last_signal")
            if rssi is None:
                rssi = d.get(
                    "kismet.device.base.signal", {}
                ).get("kismet.common.signal.last_signal", None)
            try:
                rssi = int(rssi) if rssi is not None else -100
            except (TypeError, ValueError):
                rssi = -100
            if rssi >= 0:
                rssi = -100   # 0 or positive means Kismet has no signal reading

            last_time = d.get("kismet.device.base.last_time", 0)

            # ── Probed SSIDs ─────────────────────────────────
            probe_map = d.get("dot11.device.probed_ssid_map")
            if probe_map is None:
                probe_map = d.get("dot11.device", {}).get(
                    "dot11.device.probed_ssid_map", {}
                )

            probed_ssids   = []
            ie_tags_set    = set()
            ie_tags_order  = []           # first-seen order across all probe entries
            ht_caps        = None
            vht_caps       = None
            he_caps        = None
            ext_caps       = None
            crypt_set      = 0
            wps_state      = 0
            wps_uuid_e     = ""
            ms_vsa         = 0
            supported_rates = []
            vendor_ouis    = set()

            if isinstance(probe_map, dict):
                probe_entries = list(probe_map.values())
            elif isinstance(probe_map, list):
                probe_entries = probe_map
            else:
                probe_entries = []

            for entry in probe_entries:
                if not isinstance(entry, dict):
                    continue
                ssid = entry.get("dot11.probedssid.ssid", "").strip()
                if ssid:
                    probed_ssids.append(ssid)
                tags = entry.get("dot11.probedssid.ie_tag_list", []) or []
                if isinstance(tags, list):
                    for t in tags:
                        if t not in ie_tags_set:
                            ie_tags_set.add(t)
                            ie_tags_order.append(t)
                # Cap bytes / state — Kismet exposes parsed integers
                ht_caps   = ht_caps   or entry.get("dot11.probedssid.ht_caps")
                vht_caps  = vht_caps  or entry.get("dot11.probedssid.vht_caps")
                he_caps   = he_caps   or entry.get("dot11.probedssid.he_caps")
                ext_caps  = ext_caps  or entry.get("dot11.probedssid.ext_caps")
                crypt_set = crypt_set or entry.get("dot11.probedssid.crypt_set", 0)
                wps_state = wps_state or entry.get("dot11.probedssid.wps_state", 0)
                wps_uuid_e = wps_uuid_e or entry.get("dot11.probedssid.wps_uuid_e", "")
                ms_vsa    = ms_vsa    or entry.get("dot11.probedssid.ms_vsa", 0)
                rates = entry.get("dot11.probedssid.supported_rates", [])
                if isinstance(rates, list):
                    for r in rates:
                        if r not in supported_rates:
                            supported_rates.append(r)
                # Vendor IE OUIs (tag 221 sub-records when Kismet parses them)
                vsa = entry.get("dot11.probedssid.vendor_specific", []) or []
                if isinstance(vsa, list):
                    for v in vsa:
                        if isinstance(v, dict):
                            oui = v.get("dot11.vendor.oui")
                            if oui:
                                vendor_ouis.add(str(oui))

            # Back-compat exposure
            ie_tags = sorted(ie_tags_set)

            # ── Advertised SSIDs (AP beacon) ──────────────────
            advert_map = d.get("dot11.device.advertised_ssid_map")
            if advert_map is None:
                advert_map = d.get("dot11.device", {}).get(
                    "dot11.device.advertised_ssid_map", {}
                )

            advertised_ssids = []
            ap_ie_tags = []
            if isinstance(advert_map, dict):
                advert_entries = advert_map.values()
            elif isinstance(advert_map, list):
                advert_entries = advert_map
            else:
                advert_entries = []

            ap_hw_signatures = []
            for entry in advert_entries:
                if isinstance(entry, dict):
                    ssid = entry.get("dot11.advertisedssid.ssid", "").strip()
                    if ssid:
                        advertised_ssids.append(ssid)
                    # Real Kismet beacon fields — channel, encryption, HT mode
                    sig_parts = []
                    ap_ch = str(entry.get("dot11.advertisedssid.channel", "")).strip()
                    ht    = str(entry.get("dot11.advertisedssid.ht_mode", "")).strip()
                    crypt = str(entry.get("dot11.advertisedssid.crypt_set", "")).strip()
                    if ap_ch:   sig_parts.append(f"ch:{ap_ch}")
                    if ht:      sig_parts.append(f"ht:{ht}")
                    if crypt:   sig_parts.append(f"crypt:{crypt}")
                    if sig_parts:
                        ap_hw_signatures.append("|".join(sig_parts))

            device_type = d.get("kismet.device.base.type", "").lower()

            raw_channel = d.get("kismet.device.base.channel", "")
            channel = str(raw_channel).strip().split("HT")[0].split("VHT")[0].strip() if raw_channel else ""
            manuf = str(d.get("kismet.device.base.manuf", "")).strip()

            last_bssid_raw = d.get("dot11.device.last_bssid") or \
                             d.get("dot11.device", {}).get("dot11.device.last_bssid", "")
            last_bssid = str(last_bssid_raw).upper().strip() if last_bssid_raw else ""

            return {
                "mac":              mac,
                "rssi":             rssi,
                "last_time":        last_time,
                "channel":          channel,
                "manuf":            manuf,
                "probed_ssids":     probed_ssids,
                "ie_tags":          ie_tags,            # legacy: sorted set
                "ie_tags_order":    ie_tags_order,      # new: first-seen order
                "ht_caps":          ht_caps,
                "vht_caps":         vht_caps,
                "he_caps":          he_caps,
                "ext_caps":         ext_caps,
                "crypt_set":        crypt_set,
                "wps_state":        wps_state,
                "wps_uuid_e":       wps_uuid_e,
                "ms_vsa":           ms_vsa,
                "supported_rates":  supported_rates,
                "vendor_ouis":      sorted(vendor_ouis),
                "advertised_ssids": advertised_ssids,
                "ap_hw_signatures": ap_hw_signatures,
                "is_ap":            "ap" in device_type or bool(advertised_ssids),
                "last_bssid":       last_bssid,
            }

        except Exception as e:
            logger.warning(f"Failed to parse device record: {e}")
            return None

    def fetch_associated_clients(self, ap_macs: list) -> set:
        """
        AP-side confirmation: pull each infrastructure AP's
        associated_client_map from Kismet and return the union of
        client MACs Kismet has observed completing association.

        Stronger than client-reported `last_bssid` because it relies on
        Kismet's correlation of frames seen at the AP, not on a value
        the client itself transmits (which is trivially spoofable).
        """
        associated: set = set()
        for ap_mac in ap_macs:
            url = f"{self.base_url}/devices/by-mac/{ap_mac}/devices.json"
            try:
                resp = self.session.get(url, timeout=8)
                resp.raise_for_status()
                records = resp.json()
            except requests.exceptions.HTTPError as e:
                logger.debug(f"AP {ap_mac} lookup failed: {e}")
                continue
            except Exception as e:
                logger.debug(f"AP {ap_mac} fetch error: {e}")
                continue

            if not isinstance(records, list):
                continue

            for ap in records:
                client_map = ap.get("dot11.device.associated_client_map")
                if client_map is None:
                    client_map = ap.get("dot11.device", {}).get(
                        "dot11.device.associated_client_map", {}
                    )
                if isinstance(client_map, dict):
                    for client_mac in client_map.keys():
                        if isinstance(client_mac, str) and client_mac:
                            associated.add(client_mac.upper())

        logger.debug(f"AP-confirmed associated clients: {len(associated)}")
        return associated

    def test_connection(self) -> bool:
        """Quick health check — returns True if Kismet responds."""
        try:
            resp = self.session.get(
                f"{self.base_url}/system/status.json", timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False
