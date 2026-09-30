"""In-memory ring buffers for alerts and telemetry.
mock mode -> synthetic data; file mode -> tails the JSONL / JSON files the pipeline writes."""
from __future__ import annotations
import json
import random
from collections import deque

import pandas as pd

import config
from core import mock_feed
from core.schema import flatten, validate_alert


class AlertStore:
    def __init__(self, mode: str = config.DATA_MODE):
        self.mode = mode
        self.alerts: deque = deque(maxlen=config.MAX_ALERTS)
        self.telemetry: deque = deque(maxlen=config.MAX_TELEMETRY_POINTS)
        self.rejected = 0
        self._offset = 0
        self._tel_mtime = 0.0

    # ---- ingestion -------------------------------------------------
    def poll(self) -> None:
        if self.mode == "mock":
            for _ in range(random.choice([0, 1, 1, 2, 3])):
                self.alerts.appendleft(validate_alert(mock_feed.generate_alert()))
            self.telemetry.append(mock_feed.generate_telemetry())
        else:
            self._tail_alerts()
            self._read_telemetry()

    def _tail_alerts(self) -> None:
        p = config.ALERTS_FILE
        if not p.exists():
            return
        if p.stat().st_size < self._offset:  # file rotated / truncated
            self._offset = 0
        with open(p, "r", encoding="utf-8") as fh:
            fh.seek(self._offset)
            while True:
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    break
                if not line.endswith("\n"):  # half-written line, retry next poll
                    fh.seek(pos)
                    break
                line = line.strip()
                if line:
                    try:
                        alert = validate_alert(json.loads(line))
                    except json.JSONDecodeError:
                        alert = None
                    if alert:
                        self.alerts.appendleft(alert)
                    else:
                        self.rejected += 1
            self._offset = fh.tell()

    def _read_telemetry(self) -> None:
        p = config.TELEMETRY_FILE
        if not p.exists() or p.stat().st_mtime == self._tel_mtime:
            return
        try:
            self.telemetry.append(json.loads(p.read_text(encoding="utf-8")))
            self._tel_mtime = p.stat().st_mtime
        except (json.JSONDecodeError, OSError):
            pass  # writer mid-update; try again next tick

    # ---- views -----------------------------------------------------
    def alerts_df(self) -> pd.DataFrame:
        cols = ["time", "alert_id", "severity", "threat_class", "confidence", "src", "dst", "proto", "ti_hit", "path", "latency_ms"]
        return pd.DataFrame([flatten(a) for a in self.alerts], columns=cols)

    def telemetry_df(self) -> pd.DataFrame:
        rows = [{"time": t["timestamp"], "gbps": t.get("throughput_gbps", 0), "flows": t.get("flows_per_sec", 0),
                 "p95_ms": t.get("p95_latency_ms", 0)} for t in self.telemetry]
        return pd.DataFrame(rows, columns=["time", "gbps", "flows", "p95_ms"])

    def latest_telemetry(self) -> dict:
        return self.telemetry[-1] if self.telemetry else {}

    def get(self, alert_id: str) -> dict | None:
        return next((a for a in self.alerts if a["alert_id"] == alert_id), None)
