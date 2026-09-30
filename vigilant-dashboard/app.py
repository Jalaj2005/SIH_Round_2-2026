"""NTRO Vigilant - Passive Network Threat Operations Console.
Run:  streamlit run app.py
"""
import streamlit as st

import config
from components import alert_feed, charts, forensic_drawer, kpi_bar, ti_panel
from core.alert_store import AlertStore

st.set_page_config(page_title="Vigilant Ops Console", page_icon="🛡️", layout="wide")


@st.cache_resource
def get_store() -> AlertStore:
    return AlertStore()


store = get_store()

# ---- sidebar -------------------------------------------------------
with st.sidebar:
    st.title("🛡️ Vigilant")
    st.caption("SIH 26145 | PASSIVE_UNIDIRECTIONAL enclave")
    st.markdown(f"**Data source:** `{store.mode}`")
    freeze = st.toggle("Freeze feed (inspect)", value=False)
    sev_filter = st.multiselect("Severity", config.SEVERITY_ORDER, default=config.SEVERITY_ORDER)
    cls_filter = st.multiselect("Threat class", config.THREAT_CLASSES, default=config.THREAT_CLASSES)
    if store.rejected:
        st.warning(f"{store.rejected} malformed alert(s) rejected")

st.title("Vigilant Passive NDR Operations Console")


def live_view() -> None:
    if not freeze:
        store.poll()
    df = store.alerts_df()
    tel_now, tel_hist = store.latest_telemetry(), store.telemetry_df()
    fdf = df[df["severity"].isin(sev_filter) & df["threat_class"].isin(cls_filter)] if not df.empty else df

    kpi_bar.render(tel_now, fdf)

    if not tel_hist.empty:
        c1, c2 = st.columns(2)
        c1.plotly_chart(charts.throughput(tel_hist), use_container_width=True)
        c2.plotly_chart(charts.latency(tel_hist), use_container_width=True)

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Live alert feed")
        picked = alert_feed.render(fdf)
        if picked:
            st.session_state["selected_id"] = picked
    with right:
        forensic_drawer.render(store.get(st.session_state.get("selected_id", "")))

    if not fdf.empty:
        b1, b2, b3 = st.columns([2, 2, 2])
        b1.plotly_chart(charts.by_threat_class(fdf), use_container_width=True)
        b2.plotly_chart(charts.by_path(fdf), use_container_width=True)
        with b3:
            ti_panel.render(tel_now, fdf)


st.fragment(run_every=None if freeze else config.REFRESH_SECONDS)(live_view)()
