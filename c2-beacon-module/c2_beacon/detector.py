"""Streaming Botnet C2 beaconing detector.

Idea: a bot "phones home" to a small set of destinations at (nearly) regular
intervals, with small, similar-sized flows. For every (src, dst, dst_port, proto)
channel we keep a bounded window of flow timestamps/sizes and score:

  interval regularity  - robust CV of inter-arrival times (MAD-based, outlier-proof)
  period consistency   - share of intervals within +/-tol of the median period
                         (integer multiples count, so skipped beats don't hurt)
  size stability       - CV of outbound bytes (heartbeats are similar in size)
  persistence          - number of observations in the window
  destination rarity   - how few distinct sources talk to that destination
                         (many hosts polling one server = update/NTP, not C2)

Read-only: only consumes flow metadata, never contacts either endpoint.
Bounded: O(window) per channel, LRU-capped channel table, TTL purge.
"""
from __future__ import annotations
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple
import numpy as np

from .schema import Flow, Alert

THREAT_CLASS = "BOTNET_C2_BEACONING"
Key = Tuple[str, str, int, str]


@dataclass
class BeaconConfig:
    window: int = 64                 # max observations kept per channel
    min_events: int = 8              # need this many flows before scoring
    eval_every: int = 2              # re-score every N new flows (throughput knob)
    min_interval: float = 1.0        # ignore channels faster than this (bulk traffic)
    max_interval: float = 6 * 3600   # ignore channels slower than this
    tolerance: float = 0.25          # +/- fraction of period counted as "on beat"
    alert_threshold: float = 0.60
    cooldown: float = 300.0          # event-time secs between repeat alerts per channel
    rescore_delta: float = 0.10      # re-alert early if confidence rises by this much
    key_ttl: float = 6 * 3600        # purge channels idle this long (event time)
    max_keys: int = 200_000          # hard cap on tracked channels (LRU eviction)
    popular_dst_sources: int = 25    # dst contacted by >= this many srcs => likely benign
    allow_dst_ips: Set[str] = field(default_factory=set)     # e.g. internal update servers
    allow_dst_ports: Set[int] = field(default_factory=set)   # e.g. {123} NTP
    weights: Dict[str, float] = field(default_factory=lambda: dict(
        interval=0.35, consistency=0.30, size=0.15, persistence=0.10, rarity=0.10))


class _Chan:
    __slots__ = ("ts", "sz", "since_eval", "last_alert_ts", "last_conf", "last_seen")

    def __init__(self, window: int):
        self.ts: deque = deque(maxlen=window)
        self.sz: deque = deque(maxlen=window)
        self.since_eval = 0
        self.last_alert_ts = -1e18
        self.last_conf = 0.0
        self.last_seen = 0.0


def _clip01(x: float) -> float:
    return 0.0 if x < 0 else 1.0 if x > 1 else float(x)


class BeaconDetector:
    """Feed flows in (roughly) time order via `process_flow`; get alerts back."""
    name = "c2_beacon"

    def __init__(self, config: Optional[BeaconConfig] = None):
        self.cfg = config or BeaconConfig()
        self._chans: "OrderedDict[Key, _Chan]" = OrderedDict()
        self._dst_srcs: Dict[str, Set[str]] = {}
        self._n = 0
        self.stats = dict(flows=0, evaluations=0, alerts=0, evicted=0)

    # ------------------------------------------------------------------ API
    def process_flow(self, f: Flow) -> List[Alert]:
        c = self.cfg
        self.stats["flows"] += 1
        if f.dst_ip in c.allow_dst_ips or f.dst_port in c.allow_dst_ports:
            return []

        # destination popularity (bounded set per dst)
        s = self._dst_srcs.setdefault(f.dst_ip, set())
        if len(s) < c.popular_dst_sources * 4:
            s.add(f.src_ip)

        key: Key = (f.src_ip, f.dst_ip, f.dst_port, f.proto)
        ch = self._chans.get(key)
        if ch is None:
            ch = self._chans[key] = _Chan(c.window)
            if len(self._chans) > c.max_keys:
                self._chans.popitem(last=False)
                self.stats["evicted"] += 1
        else:
            self._chans.move_to_end(key)

        ch.ts.append(f.ts)
        ch.sz.append(f.bytes_out)
        ch.last_seen = f.ts
        ch.since_eval += 1

        self._n += 1
        if self._n % 20_000 == 0:
            self._purge(f.ts)

        if len(ch.ts) < c.min_events or ch.since_eval < c.eval_every:
            return []
        ch.since_eval = 0
        return self._evaluate(key, ch, f)

    def process_stream(self, flows: Iterable[Flow]) -> Iterator[Alert]:
        for f in flows:
            yield from self.process_flow(f)

    # ------------------------------------------------------------- internals
    def _evaluate(self, key: Key, ch: _Chan, f: Flow) -> List[Alert]:
        c = self.cfg
        self.stats["evaluations"] += 1
        ts = np.sort(np.fromiter(ch.ts, float, len(ch.ts)))
        iv = np.diff(ts)
        iv = iv[iv > 1e-3]
        if len(iv) < c.min_events - 1:
            return []
        med = float(np.median(iv))
        if not (c.min_interval <= med <= c.max_interval):
            return []

        mad = float(np.median(np.abs(iv - med)))
        rcv = 1.4826 * mad / med                                   # robust CV
        k = np.maximum(1.0, np.round(iv / med))                    # allow missed beats
        consistency = float(np.mean(np.abs(iv - k * med) <= c.tolerance * med))

        sz = np.fromiter(ch.sz, float, len(ch.sz))
        sz_mean = float(sz.mean())
        size_cv = float(sz.std() / sz_mean) if sz_mean > 0 else 1.0

        n_src = len(self._dst_srcs.get(key[1], ()))
        rarity = _clip01(1.0 - (n_src - 1) / max(1, c.popular_dst_sources - 1))

        parts = dict(
            interval=_clip01(1.0 - rcv / 0.4),
            consistency=consistency,
            size=_clip01(1.0 - size_cv / 0.5),
            persistence=_clip01(len(ts) / 20.0),
            rarity=rarity,
        )
        conf = sum(c.weights[k_] * v for k_, v in parts.items())
        if consistency < 0.6:
            conf *= 0.5                                            # not really periodic
        if n_src >= c.popular_dst_sources:
            conf *= 0.6                                            # popular destination
        conf = _clip01(conf)

        if conf < c.alert_threshold:
            return []
        now = f.ts
        if (now - ch.last_alert_ts < c.cooldown) and (conf - ch.last_conf < c.rescore_delta):
            return []
        ch.last_alert_ts, ch.last_conf = now, conf
        self.stats["alerts"] += 1

        evidence = dict(
            period_s=round(med, 3),
            mean_interval_s=round(float(iv.mean()), 3),
            robust_cv=round(rcv, 4),
            interval_cv=round(float(iv.std() / iv.mean()), 4),
            period_consistency=round(consistency, 3),
            size_cv=round(size_cv, 4),
            mean_bytes_out=round(sz_mean, 1),
            observations=int(len(ts)),
            observed_span_s=round(float(ts[-1] - ts[0]), 1),
            distinct_sources_to_dst=n_src,
            dst_port=key[2],
            proto=key[3],
            score_components={k_: round(v, 3) for k_, v in parts.items()},
        )
        sev = "HIGH" if conf >= 0.90 else "MEDIUM" if conf >= 0.75 else "LOW"
        return [Alert(timestamp=now, flow_id=f.flow_id, threat_class=THREAT_CLASS,
                      confidence=round(conf, 4), severity=sev, src_ip=key[0],
                      dst_ip=key[1], evidence=evidence, module=self.name)]

    def _purge(self, now: float) -> None:
        ttl = self.cfg.key_ttl
        dead = [k for k, ch in self._chans.items() if now - ch.last_seen > ttl]
        for k in dead:
            del self._chans[k]
        live_dsts = {k[1] for k in self._chans}
        for d in [d for d in self._dst_srcs if d not in live_dsts]:
            del self._dst_srcs[d]

    @property
    def tracked_channels(self) -> int:
        return len(self._chans)
