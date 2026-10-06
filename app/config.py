"""
WiFi Analyzer - Phase 1 Configuration
Adjust these values to match your environment.
"""

import os

# ─── Kismet API ───────────────────────────────────────────────
KISMET_HOST = os.environ.get("KISMET_HOST", "http://127.0.0.1:2501")
KISMET_USER = os.environ.get("KISMET_USER", "portfolio")
KISMET_PASSWORD = os.environ.get("KISMET_PASSWORD", "")
POLL_INTERVAL   = 10               # seconds between API calls

# ─── Web UI ───────────────────────────────────────────────────
UI_HOST = os.environ.get("UI_HOST", "127.0.0.1")
UI_PORT         = 8081

KISMET_ENDPOINT = (
    "/devices/views/phy-IEEE802.11/devices.json"
)

# Fields we request from Kismet (reduces payload size)
KISMET_FIELDS = [
    "kismet.device.base.macaddr",
    "kismet.device.base.last_time",
    "kismet.device.base.channel",
    "kismet.device.base.manuf",
    "kismet.device.base.signal/kismet.common.signal.last_signal",
    "dot11.device/dot11.device.probed_ssid_map",
    "dot11.device/dot11.device.last_bssid",
    "kismet.device.base.type",
    "dot11.device/dot11.device.advertised_ssid_map",
]

# ─── Detection Thresholds ─────────────────────────────────────
RSSI_RED_ZONE        = -50    # dBm — anything stronger = "in the building"
RSSI_ROLLING_WINDOW  = 6     # last N signals for rolling average
ALERT_TIMER_SECONDS  = 60    # how long a stranger must linger before alert
DEVICE_EXPIRY_SECONDS = 300  # remove profile if not seen for 5 minutes

# ─── Office SSIDs (your known infrastructure) ─────────────────
OFFICE_SSIDS = [v.strip() for v in os.environ.get("OFFICE_SSIDS", "Demo-Lab").split(",") if v.strip()]

# ─── File Paths ───────────────────────────────────────────────
# DATA_DIR lets a deployment (e.g. a Docker volume) relocate all persistent
# state. Defaults to "." so running directly from this folder is unchanged.
DATA_DIR        = os.environ.get("ANALYZER_DATA_DIR", ".")

WHITELIST_FILE  = os.path.join(DATA_DIR, "whitelist/known_devices.json")  # legacy — migrated into ANALYZER_DB on first run
ANALYZER_DB     = os.path.join(DATA_DIR, "analyzer.db")                   # single SQLite store: profiles, alerts, whitelist, history
LOG_FILE        = os.path.join(DATA_DIR, "logs/analyzer.log")
ALERT_LOG_FILE  = os.path.join(DATA_DIR, "logs/alerts.log")

# ─── Data Retention ───────────────────────────────────────────
# Rolling window for the high-volume rssi_samples table. Older rows are
# pruned periodically so the DB stays bounded. 0 disables pruning.
RSSI_RETENTION_DAYS = int(os.environ.get("RSSI_RETENTION_DAYS", "7"))

# ─── Alert Channels (set to True to enable) ──────────────────
ALERT_SLACK   = False
ALERT_EMAIL   = False
ALERT_CONSOLE = True          # always on during development

SLACK_WEBHOOK_URL = ""        # paste your Slack incoming webhook URL
EMAIL_SMTP_HOST   = ""
EMAIL_FROM        = ""
EMAIL_TO          = ""
EMAIL_PASSWORD    = ""
