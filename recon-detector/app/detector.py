"""Streaming reconnaissance / port-scan detector (horizontal + vertical fan-out)."""
import threading
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Optional

from .config import Settings, settings as default_settings
from .schemas import Alert, Flow, TCP_ACK, TCP_RST, TCP_SYN
from .window import Ev, SourceState


class ReconDetector:
    def __init__(self, cfg: Settings = default_settings):
        self.cfg = cfg
        self.sources: dict[str, SourceState] = {}
        self.pending: dict[tuple, deque] = {}     # (src,dst,dport) -> unanswered events
        self.watermark = 0.0                      # max event time seen (event-time clock)
        self._last_sweep = 0.0
        self._last_alert: dict[tuple, float] = {}
        self._lock = threading.Lock()
        self.flows_seen = 0
        self.alerts_emitted = 0

    # ---------- helpers ----------
    @staticmethod
    def _looks_like_response(f: Flow) -> bool:
        """Well-known service port answering to an ephemeral port = server reply."""
        return 0 < f.src_port < 1024 <= f.dst_port

    def _forget(self, src, ev: Ev):
        key = (src, ev.dst, ev.dport)
        q = self.pending.get(key)
        if q:
            if q[0] is ev:
                q.popleft()
            elif ev in q:
                q.remove(ev)
            if not q:
                self.pending.pop(key, None)

    def _match_reply(self, f: Flow) -> bool:
        """If f is the reverse leg of a tracked probe, mark the probe answered.
        A bare RST reply means 'port closed' => probe still counts as failed."""
        key = (f.dst_ip, f.src_ip, f.src_port)
        q = self.pending.get(key)
        if not q:
            return False
        if not (f.protocol.upper() == "TCP" and f.tcp_flags & TCP_RST and not f.tcp_flags & TCP_ACK):
            src_state = self.sources.get(f.dst_ip)
            for ev in q:
                if not ev.answered:
                    ev.answered = True
                    if src_state:
                        src_state.answered += 1
            self.pending.pop(key, None)
        return True

    def _sweep(self):
        cutoff = self.watermark - self.cfg.window_seconds
        for src in list(self.sources):
            st = self.sources[src]
            st.evict(cutoff, lambda ev, s=src: self._forget(s, ev))
            if not st.events:
                del self.sources[src]
        self._last_alert = {k: t for k, t in self._last_alert.items()
                            if self.watermark - t < self.cfg.alert_cooldown}
        self._last_sweep = self.watermark

    # ---------- main entry ----------
    def process(self, f: Flow) -> Optional[Alert]:
        with self._lock:
            self.flows_seen += 1
            if f.ts > self.watermark:
                self.watermark = f.ts
            if self.watermark - self._last_sweep >= self.cfg.window_seconds:
                self._sweep()

            if self._match_reply(f) or self._looks_like_response(f):
                return None                       # reverse leg / server reply: not an initiation
            if f.protocol.upper() == "TCP" and f.tcp_flags and not f.tcp_flags & TCP_SYN:
                return None                       # mid-stream TCP, not a connection attempt

            st = self.sources.get(f.src_ip)
            if st is None:
                if len(self.sources) >= self.cfg.max_tracked_sources:
                    return None                   # memory guard against spoofed-source floods
                st = self.sources[f.src_ip] = SourceState()
            st.evict(self.watermark - self.cfg.window_seconds,
                     lambda ev: self._forget(f.src_ip, ev))
            ev = Ev(f.ts, f.dst_ip, f.dst_port)
            st.add(ev)
            self.pending.setdefault((f.src_ip, f.dst_ip, f.dst_port), deque()).append(ev)
            st.last_flow_id = f.fid()
            return self._evaluate(f, st)

    # ---------- scoring ----------
    def _evaluate(self, f: Flow, st: SourceState) -> Optional[Alert]:
        c = self.cfg
        horiz = len(st.dst_counts) >= c.horizontal_threshold
        vert = st.max_ports_single_dst() >= c.vertical_threshold
        if not (horiz or vert):
            return None
        m = st.metrics()
        sub = "combined_scan" if horiz and vert else "horizontal_scan" if horiz else "vertical_scan"

        fan_scores = []
        if horiz:
            fan_scores.append(m["unique_dst_ips"] / (2 * c.horizontal_threshold))
        if vert:
            fan_scores.append(m["max_ports_single_dst"] / (2 * c.vertical_threshold))
        fan = min(1.0, max(fan_scores))
        vol = min(1.0, m["connection_attempts"] / (4 * max(c.horizontal_threshold, c.vertical_threshold)))
        conf = round(min(1.0, 0.55 * fan + 0.30 * m["failed_ratio"] + 0.15 * vol), 2)
        if conf < c.min_confidence:
            return None

        key = (f.src_ip, sub)
        last = self._last_alert.get(key)
        if last is not None and self.watermark - last < c.alert_cooldown:
            return None
        self._last_alert[key] = self.watermark

        top = [{"dst_ip": d, "flows": n} for d, n in st.dst_counts.most_common(3)]
        severity = ("critical" if conf >= 0.9 else "high" if conf >= 0.75
                    else "medium" if conf >= 0.6 else "low")
        self.alerts_emitted += 1
        return Alert(
            alert_id=uuid.uuid4().hex[:12],
            timestamp=datetime.fromtimestamp(f.ts, tz=timezone.utc).isoformat(),
            flow_id=f.fid(), sub_type=sub, severity=severity, confidence=conf,
            src_ip=f.src_ip, window_seconds=c.window_seconds,
            evidence={**m, "top_targets": top,
                      "thresholds": {"horizontal": c.horizontal_threshold,
                                     "vertical": c.vertical_threshold}},
        )

    def source_snapshot(self, ip: str) -> Optional[dict]:
        with self._lock:
            st = self.sources.get(ip)
            return st.metrics() if st else None

    def stats(self) -> dict:
        with self._lock:
            return {"flows_seen": self.flows_seen, "alerts_emitted": self.alerts_emitted,
                    "tracked_sources": len(self.sources), "pending_probes": len(self.pending),
                    "watermark": self.watermark}
