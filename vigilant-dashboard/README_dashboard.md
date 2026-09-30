# Vigilant Ops Console (Member 6 - Dashboard)

Live operations console for the SIH 26145 passive NDR pipeline: Gbps / flows-per-sec, alert latency,
TI cache stats, live alert feed, and a forensic drawer with TreeSHAP attributions.

## Run
    pip install -r requirements.txt
    streamlit run app.py                      # mock data (demo mode)
    VIGILANT_MODE=file streamlit run app.py   # real pipeline data

## Run the integrated pipeline
From this directory, replay a packet capture through Module 1 and the available local detectors:

    python run_pipeline.py path/to/capture.pcap
    python run_pipeline.py path/to/capture.pcap --loop
    VIGILANT_MODE=file streamlit run app.py

The runner writes normalized alerts to `data/alerts.jsonl` and atomically replaces
`data/telemetry.json`. Integrated detectors are C2 beaconing, DDoS, DGA, DNS tunnelling,
data exfiltration, reconnaissance/port scan, threat-intel fusion, and TLS malware. Threat intel uses the bundled
offline sample feed; set `VIGILANT_IOC_DB` to use a persistent IoC database. DNS-tunnelling
detection scores encoded subdomain patterns, query cadence, uniqueness, and destination popularity.

## Integration contract (what the pipeline must produce)
| File | Format | Writer |
|---|---|---|
| `data/alerts.jsonl` | one alert JSON per line, **append-only**, schema = Section 6 of the blueprint (`data/sample_alert.json`) | Fusion layer |
| `data/telemetry.json` | latest snapshot, overwritten ~1/sec (`data/sample_telemetry.json`) | Module 1 / dispatcher |

Write telemetry atomically (write temp file, then `os.replace`) so the dashboard never reads a half-written file.
Paths can be changed with `VIGILANT_ALERTS_FILE` / `VIGILANT_TELEMETRY_FILE`. Legacy
`SENTINEL_*` environment variable names remain supported.

Fusion side, minimal example:

    with open("data/alerts.jsonl", "a") as f:
        f.write(json.dumps(alert) + "\n")

## Test
    pytest -q
