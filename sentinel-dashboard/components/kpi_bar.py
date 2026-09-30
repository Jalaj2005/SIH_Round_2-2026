import pandas as pd
import streamlit as st

import config


def render(tel: dict, df: pd.DataFrame) -> None:
    cache = tel.get("cache", {})
    hits, misses = cache.get("hits", 0), cache.get("misses", 0)
    hit_ratio = hits / (hits + misses) * 100 if (hits + misses) else 0.0
    gbps, flows = tel.get("throughput_gbps", 0.0), tel.get("flows_per_sec", 0)
    lat = tel.get("p95_latency_ms", 0.0)
    crit = int((df["severity"] == "CRITICAL").sum()) if not df.empty else 0

    c = st.columns(6)
    c[0].metric("Throughput", f"{gbps:.2f} Gbps", f"{gbps - config.TARGET_GBPS:+.2f} vs 1 Gbps target")
    c[1].metric("Flows / sec", f"{flows:,}", f"{flows - config.TARGET_FLOWS_PER_SEC:+,} vs 50k target")
    c[2].metric("p95 alert latency", f"{lat:.1f} ms", "within budget" if lat < config.LATENCY_BUDGET_MS else "OVER BUDGET",
                delta_color="normal" if lat < config.LATENCY_BUDGET_MS else "inverse")
    c[3].metric("TI cache hit ratio", f"{hit_ratio:.1f}%")
    c[4].metric("Packet drops", tel.get("packet_drops", 0), delta_color="inverse")
    c[5].metric("Critical alerts (buffer)", crit)
