"""Alert schema validation (Section 6 of the blueprint) and table flattening."""
from __future__ import annotations
from typing import Any

import config

REQUIRED = ("alert_id", "timestamp", "severity", "threat_class", "confidence_score", "flow_identifier")
_PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def _protocol_name(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="replace")
    if isinstance(value, int):
        return _PROTOCOL_NAMES.get(value, str(value))
    protocol = str(value if value is not None else "?").strip()
    if protocol.isdecimal():
        return _PROTOCOL_NAMES.get(int(protocol), protocol)
    return protocol.upper()


def validate_alert(raw: Any) -> dict | None:
    """Return a normalised alert dict, or None if it is malformed."""
    if not isinstance(raw, dict) or any(k not in raw for k in REQUIRED):
        return None
    sev = str(raw["severity"]).upper()
    if sev not in config.SEVERITY_ORDER:
        return None
    flow = raw["flow_identifier"]
    if not isinstance(flow, dict):
        return None
    try:
        conf = float(raw["confidence_score"])
    except (TypeError, ValueError):
        return None
    alert = dict(raw)
    alert["severity"] = sev
    alert["confidence_score"] = min(max(conf, 0.0), 1.0)
    alert["flow_identifier"] = {
        "src_ip": flow.get("src_ip", "?"), "dst_ip": flow.get("dst_ip", "?"),
        "src_port": flow.get("src_port", 0), "dst_port": flow.get("dst_port", 0),
        "protocol": _protocol_name(flow.get("protocol", "?")),
    }
    alert.setdefault("threat_intelligence", {})
    alert.setdefault("supporting_evidence", {"primary_metric": "-", "feature_attributions": {}})
    alert.setdefault("system_telemetry", {})
    return alert


def flatten(alert: dict) -> dict:
    """One flat row per alert for the feed table."""
    f, ti, st = alert["flow_identifier"], alert["threat_intelligence"], alert["system_telemetry"]
    return {
        "time": alert["timestamp"],
        "alert_id": alert["alert_id"],
        "severity": alert["severity"],
        "threat_class": alert["threat_class"],
        "confidence": alert["confidence_score"],
        "src": f"{f['src_ip']}:{f['src_port']}",
        "dst": f"{f['dst_ip']}:{f['dst_port']}",
        "proto": f["protocol"],
        "ti_hit": bool(ti.get("cache_hit", False)),
        "path": st.get("path_taken", "-"),
        "latency_ms": st.get("processing_latency_ms", None),
    }
