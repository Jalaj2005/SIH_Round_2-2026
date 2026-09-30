import json

import streamlit as st

from components import charts


def render(alert: dict | None) -> None:
    st.subheader("Forensic inspection")
    if not alert:
        st.caption("Click an alert row to inspect it.")
        return
    f, ti = alert["flow_identifier"], alert["threat_intelligence"]
    ev, tel = alert["supporting_evidence"], alert["system_telemetry"]

    st.markdown(f"**{alert['alert_id']}** - {alert['threat_class']}  \n"
                f"Severity **{alert['severity']}** | confidence **{alert['confidence_score']:.2f}**")
    st.code(f"{f['src_ip']}:{f['src_port']}  ->  {f['dst_ip']}:{f['dst_port']}  [{f['protocol']}]", language="text")

    t1, t2, t3, t4 = st.tabs(["Evidence", "Threat intel", "Telemetry", "Raw JSON"])
    with t1:
        st.write(f"Primary metric: **{ev.get('primary_metric', '-')}**")
        attrs = ev.get("feature_attributions", {})
        if attrs:
            st.plotly_chart(charts.attributions(attrs), use_container_width=True)
    with t2:
        st.write(f"Cache hit: **{ti.get('cache_hit', False)}**  |  TI override applied: **{ti.get('ti_override_applied', False)}**")
        st.write(f"IoC matched: `{ti.get('ioc_matched')}`  ({ti.get('ioc_category') or 'no category'})")
    with t3:
        st.write(f"Path: `{tel.get('path_taken', '-')}`")
        st.write(f"Processing latency: **{tel.get('processing_latency_ms', '-')} ms**")
        st.write(f"Enclave mode: `{tel.get('enclave_mode', '-')}`")
    with t4:
        st.json(alert)
        st.download_button("Download alert JSON", json.dumps(alert, indent=2),
                           file_name=f"{alert['alert_id']}.json", mime="application/json")
