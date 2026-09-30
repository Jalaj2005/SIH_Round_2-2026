"""Synthetic alerts + telemetry that follow the real schema, so the UI can be built
and demoed before the pipeline (Members 1-5) is wired up."""
from __future__ import annotations
import random
from datetime import datetime, timezone

import config

_PRIMARY = {
    "DDoS Flood": ("Source-IP Entropy Collapse", ["src_ip_entropy", "pps", "syn_ratio", "bps"]),
    "Botnet C2 Beaconing": ("Lomb-Scargle Periodicity Peak", ["iat_spectral_power", "iat_variance", "repetition_count"]),
    "DGA Domain": ("Domain Character Entropy", ["char_entropy", "bigram_score", "vowel_ratio", "length"]),
    "DNS Tunnelling": ("Query Length Anomaly", ["query_length", "txt_null_ratio", "query_velocity"]),
    "TLS Malware": ("JA3/JA4 + SPLT Classification", ["ja3_reputation", "splt_len_var", "cipher_count"]),
    "Port Scan": ("Fan-out Ratio", ["dst_port_entropy", "fanout_ratio", "syn_only_ratio"]),
    "Data Exfiltration": ("Out/In Byte Ratio", ["bytes_out_in_ratio", "volume_zscore", "duration"]),
    "Known IoC (TI)": ("Local IoC Database Match", ["ti_reputation_weight"]),
}
_seq = 1000


def _ip(internal: bool) -> str:
    return f"10.0.{random.randint(0, 9)}.{random.randint(2, 250)}" if internal else \
        f"{random.choice([198, 203, 45, 91])}.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(2, 250)}"


def generate_alert() -> dict:
    global _seq
    _seq += 1
    cls = random.choices(config.THREAT_CLASSES, weights=[5, 3, 3, 2, 3, 6, 2, 3])[0]
    primary, feats = _PRIMARY[cls]
    ti_hit = cls == "Known IoC (TI)" or random.random() < 0.25
    conf = round(random.uniform(0.98, 1.0) if cls == "Known IoC (TI)" else random.uniform(0.45, 0.99), 2)
    early = cls == "Known IoC (TI)"
    override = ti_hit and not early and conf < 0.7
    if early or (override and conf >= 0.5):
        sev = "CRITICAL"
    else:
        sev = "CRITICAL" if conf > 0.9 else "HIGH" if conf > 0.75 else "MEDIUM" if conf > 0.55 else "LOW"
    now = datetime.now(timezone.utc)
    attrs = {f: round(random.uniform(-0.3, 0.6), 3) for f in feats}
    if ti_hit:
        attrs["ti_reputation_weight"] = round(random.uniform(0.3, 0.6), 2)
    dst = _ip(False)
    return {
        "alert_id": f"ALT-{now:%Y%m%d}-{_seq}",
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        "severity": sev,
        "threat_class": cls,
        "confidence_score": conf,
        "flow_identifier": {"src_ip": _ip(True), "dst_ip": dst, "src_port": random.randint(1024, 65535),
                            "dst_port": random.choice([443, 53, 80, 22, 445, 8080]),
                            "protocol": random.choice(["TCP", "UDP"])},
        "threat_intelligence": {"cache_hit": ti_hit, "ioc_matched": dst if ti_hit else None,
                                "ioc_category": "Known C2 Destination" if ti_hit else None,
                                "ti_override_applied": override or early},
        "supporting_evidence": {"primary_metric": primary, "feature_attributions": attrs},
        "system_telemetry": {"processing_latency_ms": round(random.uniform(0.3, 0.9) if early else random.uniform(1.0, 9.0), 2),
                             "path_taken": "EARLY_EXIT_TI_OVERRIDE" if early else "FUSION_TI_OVERRIDE" if override else "ML_FUSION",
                             "enclave_mode": "PASSIVE_UNIDIRECTIONAL"},
    }


_state = {"hits": 0, "misses": 0, "neg": 0}


def generate_telemetry() -> dict:
    _state["hits"] += random.randint(8000, 9500)
    _state["misses"] += random.randint(300, 700)
    _state["neg"] += random.randint(5000, 6500)
    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "throughput_gbps": round(random.uniform(0.9, 1.3), 2),
        "flows_per_sec": random.randint(48_000, 62_000),
        "p95_latency_ms": round(random.uniform(2.0, 8.0), 1),
        "packet_drops": 0,
        "cache": {"hits": _state["hits"], "misses": _state["misses"], "negative_hits": _state["neg"]},
        "module_counts": {c: random.randint(0, 15) for c in config.THREAT_CLASSES},
    }
