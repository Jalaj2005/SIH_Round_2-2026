# Sentinel Ops Console (Member 6 - Dashboard)

Live operations console for the SIH 26145 passive NDR pipeline: Gbps / flows-per-sec, alert latency,
TI cache stats, live alert feed, and a forensic drawer with TreeSHAP attributions.

## Run
    pip install -r requirements.txt
    streamlit run app.py                      # mock data (demo mode)
    SENTINEL_MODE=file streamlit run app.py   # real pipeline data

## Integration contract (what the pipeline must produce)
| File | Format | Writer |
|---|---|---|
| `data/alerts.jsonl` | one alert JSON per line, **append-only**, schema = Section 6 of the blueprint (`data/sample_alert.json`) | Fusion layer |
| `data/telemetry.json` | latest snapshot, overwritten ~1/sec (`data/sample_telemetry.json`) | Module 1 / dispatcher |

Write telemetry atomically (write temp file, then `os.replace`) so the dashboard never reads a half-written file.
Paths can be changed with `SENTINEL_ALERTS_FILE` / `SENTINEL_TELEMETRY_FILE`.

Fusion side, minimal example:

    with open("data/alerts.jsonl", "a") as f:
        f.write(json.dumps(alert) + "\n")

## Test
    pytest -q
