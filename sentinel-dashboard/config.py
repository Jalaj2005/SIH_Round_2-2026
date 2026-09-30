"""Central configuration. Override any value with an environment variable."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent

# mock -> built-in generator (demo / UI dev). file -> tail files written by the pipeline.
DATA_MODE = os.getenv("SENTINEL_MODE", "mock")
ALERTS_FILE = Path(os.getenv("SENTINEL_ALERTS_FILE", BASE_DIR / "data" / "alerts.jsonl"))
TELEMETRY_FILE = Path(os.getenv("SENTINEL_TELEMETRY_FILE", BASE_DIR / "data" / "telemetry.json"))
REFRESH_SECONDS = float(os.getenv("SENTINEL_REFRESH", "1"))

MAX_ALERTS = 5000
MAX_TELEMETRY_POINTS = 600

# SIH 26145 targets shown on the KPI bar
TARGET_GBPS = 1.0
TARGET_FLOWS_PER_SEC = 50_000
LATENCY_BUDGET_MS = 1000  # "bounded sub-second alerting"

THREAT_CLASSES = [
    "DDoS Flood", "Botnet C2 Beaconing", "DGA Domain", "DNS Tunnelling",
    "TLS Malware", "Port Scan", "Data Exfiltration", "Known IoC (TI)",
]
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_COLORS = {
    "LOW": "#22c55e", "MEDIUM": "#eab308", "HIGH": "#f97316", "CRITICAL": "#ef4444",
}
