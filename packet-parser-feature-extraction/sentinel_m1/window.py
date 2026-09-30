"""Tumbling-window aggregates for the features that only exist across flows:
source-IP entropy / PPS per victim (DDoS), destination-port entropy and fan-out per
source (scans), DNS velocity per source (tunnelling)."""
from collections import Counter

from .parser import TCP, UDP, ICMP, SYN, ACK
from .spectral import shannon_counts
import math


class WindowAggregator:
    def __init__(self, cfg, emit):
        self.cfg, self.emit = cfg, emit
        self.bucket = None
        self.dst, self.src = {}, {}
        self.prev_dst, self.prev_src = {}, {}     # last closed window summaries (flow-record context)
        self.overflow = 0

    def observe(self, p):
        cfg = self.cfg
        b = int(p.ts / cfg.window_s)
        if self.bucket is None:
            self.bucket = b
        elif b > self.bucket:
            self._roll()
            self.bucket = b
        d = self.dst.get(p.dst)
        if d is None:
            if len(self.dst) >= cfg.max_window_keys:
                self.overflow += 1
                return
            d = self.dst[p.dst] = [0, 0, 0, 0, 0, Counter()]
        d[0] += 1
        d[1] += p.ip_len
        proto = p.proto
        if proto == TCP:
            if p.flags & SYN and not p.flags & ACK:
                d[2] += 1
        elif proto == UDP:
            d[3] += 1
        elif proto == ICMP or proto == 58:
            d[4] += 1
        d[5][p.src] += 1

        s = self.src.get(p.src)
        if s is None:
            if len(self.src) >= cfg.max_window_keys:
                return
            s = self.src[p.src] = [0, 0, Counter(), set(), set(), 0, 0, set()]
        s[0] += 1
        s[1] += p.ip_len
        s[2][p.dport] += 1
        s[3].add(p.dst)
        if len(s[4]) < 20000:
            s[4].add((p.dst, p.dport))
        q = p.dns
        if q is not None and not q.is_response:
            s[5] += 1
            if q.qtype in (16, 10):                           # TXT / NULL
                s[6] += 1
            if len(s[7]) < 2000:
                s[7].add(q.name)

    def _roll(self):
        cfg, w = self.cfg, self.cfg.window_s
        t0 = self.bucket * w
        pd, ps = {}, {}
        for ip, d in self.dst.items():
            if d[0] < cfg.min_window_pkts:
                continue
            n = len(d[5])
            h = shannon_counts(d[5].values(), d[0])
            pd[ip] = (d[0] / w, h, n)
            self.emit({"record_type": "window", "scope": "dst", "ts": t0, "window_s": w, "ip": _ip(ip),
                       "pkts": d[0], "bytes": d[1], "pps": d[0] / w, "bytes_per_sec": d[1] / w,
                       "syn_pkts": d[2], "udp_pkts": d[3], "icmp_pkts": d[4],
                       "unique_src": n, "src_entropy": h,
                       "src_entropy_norm": h / math.log2(n) if n > 1 else 0.0,
                       "top_src_share": d[5].most_common(1)[0][1] / d[0]})
        for ip, s in self.src.items():
            if s[0] < cfg.min_window_pkts:
                continue
            nd, nt, npt = len(s[3]), len(s[4]), len(s[2])
            h = shannon_counts(s[2].values(), s[0])
            ps[ip] = (nd, h, nt)
            self.emit({"record_type": "window", "scope": "src", "ts": t0, "window_s": w, "ip": _ip(ip),
                       "pkts": s[0], "bytes": s[1], "pps": s[0] / w,
                       "unique_dst_ip": nd, "unique_dst_port": npt, "unique_targets": nt,
                       "dport_entropy": h, "fanout_ratio_ip": nd / s[0], "fanout_ratio_port": npt / s[0],
                       "ports_per_dst": nt / nd if nd else 0.0,
                       "dns_queries": s[5], "dns_txt_null": s[6], "dns_unique_names": len(s[7])})
        self.prev_dst, self.prev_src = pd, ps
        self.dst, self.src = {}, {}

    def flush(self):
        if self.bucket is not None:
            self._roll()


def _ip(b):
    import socket
    return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)
