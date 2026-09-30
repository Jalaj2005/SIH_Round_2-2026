import pandas as pd
import streamlit as st

import config


def _row_style(row):
    color = config.SEVERITY_COLORS.get(row["severity"], "#fff")
    return [f"color: {color}; font-weight: 600" if c == "severity" else "" for c in row.index]


def render(df: pd.DataFrame, height: int = 420) -> str | None:
    """Show the feed; return the alert_id the analyst clicked (or None)."""
    if df.empty:
        st.info("Waiting for alerts from the pipeline...")
        return None
    view = df.head(200).reset_index(drop=True)
    event = st.dataframe(
        view.style.apply(_row_style, axis=1).format({"confidence": "{:.2f}", "latency_ms": "{:.2f}"}, na_rep="-"),
        on_select="rerun", selection_mode="single-row", hide_index=True,
        use_container_width=True, height=height, key="alert_table",
    )
    rows = event.selection.rows
    if rows and rows[0] != st.session_state.get("_last_row"):
        st.session_state["_last_row"] = rows[0]
        return view.loc[rows[0], "alert_id"]
    if not rows:
        st.session_state["_last_row"] = None
    return None
