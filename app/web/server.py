"""
server.py — FastAPI app: REST + WebSocket + static UI.
"""

import asyncio
import json
import logging
import os
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from web.event_bus import bus
from web.runner import runner
from db import db
import settings as cfg
import time
from dataclasses import asdict
from logic_engine import AlertEvent, persist_alert
import ignores

logger = logging.getLogger("server")

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="WiFi Analyzer UI")


# ─── Engine auto-start ────────────────────────────────────────
# The UI is embedded as an iframe and has no Start button, so the analyzer
# engine starts itself when the service boots. Kismet may come up after us
# (separate container), so retry until start() succeeds.

@app.on_event("startup")
async def _autostart_engine():
    async def _loop():
        while not runner.running:
            res = await runner.start()
            if res.get("ok"):
                logger.info("Engine auto-started")
                return
            logger.info("Engine auto-start waiting: %s", res.get("reason"))
            await asyncio.sleep(10)
    asyncio.create_task(_loop())


# ─── DB-backed read helpers ───────────────────────────────────
# The live view is persisted to SQLite each cycle (see runner / db), so the UI
# and the Claude bot read the same source of truth and it survives restarts.

_LIVE_JSON_COLS = ("probed_ssids", "advertised_ssids", "ap_hw_signatures")


def _live_devices(where: str = "") -> list[dict]:
    rows = db.query(
        "SELECT * FROM live_devices "
        f"{where} ORDER BY in_red_zone DESC, rssi_avg DESC"
    )
    for r in rows:
        for col in _LIVE_JSON_COLS:
            try:
                r[col] = json.loads(r.get(col) or "[]")
            except (TypeError, ValueError):
                r[col] = []
    return rows


def _alert_events(limit: int = 100) -> list[dict]:
    """Read persisted alerts and shape them like the live WS 'alert' events."""
    rows = db.query("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))
    events = []
    for r in rows:
        events.append({
            "type": "alert",
            "ts":   r["ts"],
            "data": {
                "alert_type":       r["alert_type"],
                "mac":              r["mac"],
                "fingerprint":      r["fingerprint"],
                "rssi_avg":         r["rssi_avg"],
                "spoofed_ssid":     r.get("spoofed_ssid") or "",
                "spoof_reason":     r.get("spoof_reason") or "",
                "seconds_present":  r.get("seconds_present") or 0,
                "probed_ssids":     json.loads(r["probed_ssids"]) if r.get("probed_ssids") else [],
                "advertised_ssids": json.loads(r["advertised_ssids"]) if r.get("advertised_ssids") else [],
                "device_type":      r.get("device_type") or "",
                "manuf":            r.get("manuf") or "",
                "channel":          r.get("channel") or "",
                "count":            r.get("count") or 1,
                "first_ts":         r.get("first_ts") or r["ts"],
            },
        })
    # Oldest-first to match the previous in-RAM history ordering the UI expects.
    return list(reversed(events))


# ─── REST models ──────────────────────────────────────────────

class MacBody(BaseModel):
    mac: str
    label: str | None = None


class SafeAPsBody(BaseModel):
    macs: list[str]
    label: str | None = None


# ─── REST routes ──────────────────────────────────────────────

@app.get("/api/stats")
async def stats():
    return runner.stats()

@app.get("/api/devices")
async def devices():
    return _live_devices()

@app.get("/api/suspects")
async def suspects():
    """Live unknown devices currently in the red zone — pre-alert visibility."""
    return _live_devices(
        "WHERE is_safe=0 AND is_infrastructure=0 AND in_red_zone=1"
    )

@app.get("/api/alerts")
async def alerts():
    return _alert_events(100)

@app.get("/api/whitelist")
async def whitelist():
    return {
        "employees":      runner.whitelist.employees(),
        "infrastructure": runner.whitelist.infrastructure(),
        "office_ssids":   list(runner.whitelist.office_ssids),
    }

@app.post("/api/whitelist/employee")
async def add_employee(body: MacBody):
    res = runner.add_employee_by_mac(body.mac)
    if not res["ok"]:
        raise HTTPException(404, res["reason"])
    return res

@app.post("/api/whitelist/infra")
async def add_infra(body: MacBody):
    res = runner.add_infrastructure_by_mac(body.mac, body.label or "")
    if not res["ok"]:
        raise HTTPException(404, res["reason"])
    return res

@app.delete("/api/whitelist/employee/{fingerprint}")
async def remove_employee(fingerprint: str):
    if not runner.whitelist.remove_employee(fingerprint):
        raise HTTPException(404, "Fingerprint not found")
    return {"ok": True}

@app.delete("/api/whitelist/infra/{mac}")
async def remove_infra(mac: str):
    if not runner.whitelist.remove_infrastructure(mac):
        raise HTTPException(404, "MAC not found")
    return {"ok": True}

@app.get("/api/history/alerts")
async def history_alerts(limit: int = 200):
    return db.query(
        "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?",
        (max(1, min(limit, 1000)),),
    )

@app.get("/api/history/profiles")
async def history_profiles(limit: int = 200):
    return db.query(
        "SELECT fingerprint, first_seen, last_seen, classification, "
        "  rssi_avg, in_red_zone, manuf, channel, is_ap, "
        "  probed_ssids, advertised_ssids "
        "FROM profiles ORDER BY last_seen DESC LIMIT ?",
        (max(1, min(limit, 1000)),),
    )

@app.get("/api/history/profile/{fingerprint}")
async def history_profile(fingerprint: str):
    profile = db.query_one("SELECT * FROM profiles WHERE fingerprint=?", (fingerprint,))
    if not profile:
        raise HTTPException(404, "Fingerprint not found")
    macs = db.query("SELECT mac FROM profile_macs WHERE fingerprint=?", (fingerprint,))
    visits = db.query(
        "SELECT entered, exited, max_rssi FROM visits WHERE fingerprint=? "
        "ORDER BY entered DESC LIMIT 100",
        (fingerprint,),
    )
    samples = db.query(
        "SELECT ts, rssi FROM rssi_samples WHERE fingerprint=? "
        "ORDER BY ts DESC LIMIT 500",
        (fingerprint,),
    )
    return {
        "profile": profile,
        "macs":    [m["mac"] for m in macs],
        "visits":  visits,
        "rssi":    list(reversed(samples)),
    }

@app.get("/api/setup/visible_aps")
async def setup_visible_aps():
    return runner.visible_aps()

@app.post("/api/setup/mark_safe_aps")
async def setup_mark_safe_aps(body: SafeAPsBody):
    res = runner.mark_safe_aps(body.macs, body.label or "")
    return res

@app.post("/api/setup/rescan_clients")
async def setup_rescan_clients():
    res = runner.rescan_connected_devices()
    if not res["ok"]:
        raise HTTPException(409, res["reason"])
    return res


@app.get("/api/settings")
async def settings_get():
    return {
        **cfg.all_settings(),
        "effective_red_zone": cfg.effective_red_zone(),
    }


class SettingsBody(BaseModel):
    rssi_red_zone:          int | None = None
    rssi_exit_offset_db:    int | None = None
    alert_timer_seconds:    int | None = None
    use_dynamic_threshold:  bool | None = None
    dynamic_offset_db:      int | None = None
    enabled_alerts:         list[str] | None = None
    alert_cooldown_seconds: int | None = None


@app.post("/api/settings")
async def settings_set(body: SettingsBody):
    for k, v in body.model_dump(exclude_unset=True).items():
        cfg.set_(k, v)
    return {"ok": True, "settings": cfg.all_settings(),
            "effective_red_zone": cfg.effective_red_zone()}


@app.post("/api/setup/site_survey")
async def setup_site_survey():
    res = runner.site_survey()
    if not res["ok"]:
        raise HTTPException(409, res["reason"])
    cfg.set_("baseline_office_rssi", res["baseline_rssi"])
    res["effective_red_zone"] = cfg.effective_red_zone()
    return res


class IgnoreBody(BaseModel):
    alert_type:  str
    fingerprint: str | None = None
    mac:         str | None = None
    reason:      str | None = None


@app.get("/api/ignores")
async def ignores_list():
    return ignores.list_all()


@app.post("/api/ignores")
async def ignores_add(body: IgnoreBody):
    res = ignores.add(body.alert_type, body.fingerprint, body.mac, body.reason or "")
    if not res["ok"]:
        raise HTTPException(409, res["reason"])
    # Drop any matching live alerts so the UI doesn't keep showing them
    runner.alerts_history = [
        e for e in runner.alerts_history
        if not ignores.is_ignored(
            e["data"].get("alert_type"),
            e["data"].get("fingerprint"),
            e["data"].get("mac"),
        )
    ]
    bus.publish({"type": "ignores_changed", "ts": time.time()})
    return res


@app.delete("/api/ignores/{rule_id}")
async def ignores_remove(rule_id: int):
    ignores.remove(rule_id)
    bus.publish({"type": "ignores_changed", "ts": time.time()})
    return {"ok": True}


@app.post("/api/setup/test_alert")
async def setup_test_alert():
    """Inject a fake alert end-to-end so user can verify pipeline works."""
    fake = AlertEvent(
        alert_type   = "UNKNOWN_CLIENT",
        mac          = "DE:AD:BE:EF:00:01",
        fingerprint  = "test_alert_" + str(int(time.time())),
        rssi_avg     = -42.0,
        probed_ssids = ["TEST_NETWORK_A", "TEST_NETWORK_B"],
        seconds_present = 60.0,
    )
    count = persist_alert(fake, device_type="Test injection", manuf="Test", channel="6")
    data = asdict(fake)
    data["device_type"] = "Test injection"
    data["manuf"]   = "Test"
    data["channel"] = "6"
    data["count"]   = count
    event = {"type": "alert", "ts": time.time(), "data": data}
    runner.alerts_history.append(event)
    bus.publish(event)
    return {"ok": True, "fingerprint": fake.fingerprint, "count": count}


@app.post("/api/control/start")
async def control_start():
    res = await runner.start()
    if not res["ok"]:
        raise HTTPException(409, res["reason"])
    return res

@app.post("/api/control/stop")
async def control_stop():
    res = await runner.stop()
    if not res["ok"]:
        raise HTTPException(409, res["reason"])
    return res


# ─── WebSocket ────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    q = await bus.subscribe()
    try:
        # send initial snapshot (from the DB so a fresh client gets persisted
        # state immediately, even right after a restart before the first cycle)
        await ws.send_json({
            "type":    "snapshot",
            "devices": _live_devices(),
            "alerts":  _alert_events(50),
            "stats":   runner.stats(),
        })
        while True:
            event = await q.get()
            await ws.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WS error: {e}")
    finally:
        await bus.unsubscribe(q)


# ─── Static UI ────────────────────────────────────────────────

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def root():
    return FileResponse(str(STATIC_DIR / "index.html"))
