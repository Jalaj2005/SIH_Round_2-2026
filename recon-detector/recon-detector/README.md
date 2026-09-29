# Module 6 – Reconnaissance & Port-Scan Detector (SIH 2026 #145)

Streaming, read-only, metadata-only sliding-window detector for horizontal and vertical scans.

## Run
    docker compose up --build          # API on :8000, docs at /docs
    python scripts/simulate_scan.py    # replay demo traffic
    pytest -q                          # unit tests
    python -m scripts.benchmark        # throughput

## Input
POST /ingest, POST /ingest/batch, or XADD to Redis stream `flows` with field `data` = Flow JSON.

## Output
Alerts JSON at GET /alerts, SSE at GET /alerts/stream, Redis stream `alerts`, optional webhook.
