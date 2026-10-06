#!/usr/bin/env python3
"""
run_ui.py — Launch the WiFi Analyzer web UI.

 Binds to 0.0.0.0 so other clients on the network can connect. Visit
http://localhost:8081 after Kismet is running.
"""

import sys
import os
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import uvicorn
from config import LOG_FILE, UI_HOST, UI_PORT

os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)

if __name__ == "__main__":
    uvicorn.run(
        "web.server:app",
        host=UI_HOST,
        port=UI_PORT,
        reload=False,
        log_level="info",
    )
