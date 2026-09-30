import pandas as pd
import streamlit as st


def render(tel: dict, df: pd.DataFrame) -> None:
    cache = tel.get("cache", {})
    st.subheader("Threat-intel cache")
    a, b, c = st.columns(3)
    a.metric("Hits", f"{cache.get('hits', 0):,}")
    b.metric("Misses", f"{cache.get('misses', 0):,}")
    c.metric("Negative-cache hits", f"{cache.get('negative_hits', 0):,}")
    if not df.empty:
        early = int((df["path"] == "EARLY_EXIT_TI_OVERRIDE").sum())
        st.caption(f"Early-exit (TI-confirmed) alerts in buffer: **{early}** of {len(df)}")
