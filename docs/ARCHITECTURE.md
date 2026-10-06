# Architecture and decisions

1. `kismet_client.py` retrieves passive 802.11 observations.
2. `fingerprint.py` derives multi-signal profiles; `whitelist.py` and `ignores.py` control operator decisions.
3. `logic_engine.py` applies rolling signal, presence, and suspicious-SSID rules.
4. `db.py` persists state in a single SQLite store, including live devices and alert history.
5. `web/runner.py` orchestrates the loop; `web/server.py` serves API responses and WebSocket events.

![Architecture](architecture.svg)

SQLite keeps the installation small and allows the dashboard to read persisted state after restarts. Thresholds are configurable because radio signal strength is environment-dependent. Multiple signals reduce dependence on one MAC address, but are still probabilistic evidence.

Scope: Wi-Fi monitoring. The original working repository's name included BLE; this public snapshot does not claim an implemented BLE detection pipeline.
