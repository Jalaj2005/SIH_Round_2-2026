import json
import time
from collections import Counter

from .config import Config
from .features import FeatureExtractor
from .flow import FlowBuilder
from .parser import parse_packet
from .window import WindowAggregator


class Module1:
    """capture -> parser -> flow builder -> feature extraction -> dispatcher"""

    def __init__(self, cfg=None, dispatcher=None, jsonl_path=None):
        self.cfg = cfg or Config()
        self.disp = dispatcher
        self.sink = open(jsonl_path, "w") if jsonl_path else None
        self.windows = WindowAggregator(self.cfg, self._emit)
        self.fx = FeatureExtractor(self.cfg, self.windows)
        self.flows = FlowBuilder(
            self.cfg,
            on_flow=lambda f, why: self._emit(self.fx.flow_record(f, why)),
            on_new=self.fx.pairs.note,
            on_early=lambda f: self._emit(self.fx.early_record(f)),
            on_tls=lambda f, t, ts: self._emit(self.fx.tls_record(f, t, ts)),
        )
        self.stats = Counter()
        self.t_start = None
        self._n = 0

    def _emit(self, rec):
        self.stats["rec_" + rec["record_type"]] += 1
        if self.disp is not None:
            self.disp.publish(rec)
        if self.sink is not None:
            self.sink.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def process(self, ts, buf, linktype=1):
        if ts is None:                                   # idle tick from a live source
            if self.disp:
                self.disp.tick()
            return
        self.stats["pkts"] += 1
        self.stats["bytes"] += len(buf)
        p = parse_packet(ts, buf, linktype)
        if p is None:
            self.stats["skipped"] += 1
            return
        self.windows.observe(p)
        if p.dns is not None and not p.dns.is_response:
            self._emit(self.fx.dns_record(p))
        self.flows.process(p)
        self._n += 1
        if self.disp and self._n % self.cfg.tick_every == 0:
            self.disp.tick()

    def run(self, source):
        self.t_start = time.perf_counter()
        for ts, buf in source:
            self.process(ts, buf, source.linktype)
        self.finish()
        return self.report()

    def finish(self):
        self.flows.flush()
        self.windows.flush()
        if self.disp:
            self.disp.close()
        if self.sink:
            self.sink.close()

    def report(self):
        el = max(time.perf_counter() - (self.t_start or time.perf_counter()), 1e-9)
        s = dict(self.stats)
        s.update(elapsed_s=round(el, 3), pps=round(s.get("pkts", 0) / el),
                 mbps=round(s.get("bytes", 0) * 8 / el / 1e6, 1),
                 flows_per_s=round(s.get("rec_flow", 0) / el),
                 flows_evicted=self.flows.evicted, window_key_overflow=self.windows.overflow)
        if self.disp:
            s["dispatch"] = self.disp.stats()
        return s
