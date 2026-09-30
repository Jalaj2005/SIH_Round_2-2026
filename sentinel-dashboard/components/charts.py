import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

import config

_LAYOUT = dict(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
               margin=dict(l=10, r=10, t=35, b=10), height=260)


def throughput(tel: pd.DataFrame) -> go.Figure:
    fig = go.Figure()
    fig.add_scatter(x=tel["time"], y=tel["gbps"], name="Gbps", mode="lines", line=dict(color="#38bdf8"))
    fig.add_scatter(x=tel["time"], y=tel["flows"], name="Flows/s", mode="lines", yaxis="y2", line=dict(color="#a78bfa"))
    fig.add_hline(y=config.TARGET_GBPS, line_dash="dot", line_color="#94a3b8", annotation_text="1 Gbps target")
    fig.update_layout(title="Throughput & flow rate", yaxis=dict(title="Gbps"),
                      yaxis2=dict(title="Flows/s", overlaying="y", side="right"),
                      legend=dict(orientation="h", y=-0.2), **_LAYOUT)
    return fig


def latency(tel: pd.DataFrame) -> go.Figure:
    fig = px.line(tel, x="time", y="p95_ms", title="p95 alert latency (ms)")
    fig.add_hline(y=config.LATENCY_BUDGET_MS, line_dash="dot", line_color="#ef4444", annotation_text="1 s budget")
    fig.update_layout(**_LAYOUT)
    return fig


def by_threat_class(df: pd.DataFrame) -> go.Figure:
    counts = df.groupby(["threat_class", "severity"]).size().reset_index(name="n")
    fig = px.bar(counts, x="n", y="threat_class", color="severity", orientation="h", title="Alerts by threat class",
                 color_discrete_map=config.SEVERITY_COLORS, category_orders={"severity": config.SEVERITY_ORDER})
    fig.update_layout(**_LAYOUT)
    return fig


def by_path(df: pd.DataFrame) -> go.Figure:
    counts = df["path"].value_counts().reset_index()
    counts.columns = ["path", "n"]
    fig = px.pie(counts, names="path", values="n", hole=0.55, title="Detection path (early-exit vs ML fusion)")
    fig.update_layout(**_LAYOUT)
    return fig


def attributions(attrs: dict) -> go.Figure:
    items = sorted(attrs.items(), key=lambda kv: abs(kv[1]))
    fig = go.Figure(go.Bar(x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
                           marker_color=["#ef4444" if v >= 0 else "#38bdf8" for _, v in items]))
    fig.update_layout(title="Feature attributions (TreeSHAP)", **{**_LAYOUT, "height": 240})
    return fig
