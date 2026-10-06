# Setup and operation

The recommended Linux lab path is Docker Compose as described in the root README. Set `CAPTURE_INTERFACE` to the interface reported by `iw dev`; do not reuse a device name from another machine.

For Python execution with a separately configured Kismet service:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export KISMET_HOST=http://127.0.0.1:2501
export KISMET_USER=portfolio
read -rs KISMET_PASSWORD; export KISMET_PASSWORD
export OFFICE_SSIDS=Demo-Lab
export ANALYZER_DATA_DIR="$PWD/local-data"
mkdir -p "$ANALYZER_DATA_DIR"
python app/run_ui.py
```

The Python path reads exported environment variables; it does not automatically load `.env`. The Docker path loads `.env` through Compose. Establish known access points and train the whitelist from the Setup view before evaluating alerts. SQLite state survives restarts when the data directory/volume is preserved. Do not publish that directory.

This snapshot was checked statically and with isolated configuration parsing. No company radio, network, or hardware was used for portfolio validation.
