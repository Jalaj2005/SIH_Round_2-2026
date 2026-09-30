"""Atomic telemetry snapshot for the dashboard (write temp file, then os.replace)."""
import json
import os
from datetime import datetime, timezone


def write_telemetry(path: str, engine, **fields) -> None:
    """fields: throughput_gbps, flows_per_sec, p95_latency_ms, packet_drops, module_counts (from Module 1 stats())."""
    snap = {"timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "throughput_gbps": 0.0, "flows_per_sec": 0, "p95_latency_ms": 0.0, "packet_drops": 0,
            "module_counts": {}, **fields, "cache": engine.stats()}
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(snap, fh)
    os.replace(tmp, path)
