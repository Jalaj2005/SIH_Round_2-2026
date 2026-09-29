"""Half-duplex-tolerant bidirectional flow builder (5-tuple, rolling timeouts)."""
from collections import OrderedDict

from .parser import SYN, FIN, RST, PSH, ACK
from .tls import parse_client_hello, NEED_MORE, TlsInfo


class Flow:
    __slots__ = ("id", "key", "proto", "init_src", "init_sport", "init_dst", "init_dport",
                 "start", "last", "pk_o", "pk_i", "by_o", "by_i", "pl_o", "pl_i",
                 "syn", "fin", "rst", "ack", "psh", "closed", "closed_at",
                 "n", "mean", "m2", "iats", "times", "splt_len", "splt_iat", "last_pl_ts",
                 "tls", "tls_state", "tls_buf", "early_sent")


class FlowBuilder:
    def __init__(self, cfg, on_flow, on_new=None, on_early=None, on_tls=None):
        self.cfg, self.flows = cfg, OrderedDict()
        self.on_flow, self.on_new, self.on_early, self.on_tls = on_flow, on_new, on_early, on_tls
        self._next_id, self._last_sweep = 1, 0.0
        self.evicted = 0

    # ------------------------------------------------------------------
    def process(self, p):
        a, b = (p.src, p.sport), (p.dst, p.dport)
        key = (p.proto, a, b) if a <= b else (p.proto, b, a)
        flows, ts = self.flows, p.ts
        f = flows.get(key)
        if f is not None:
            cfg = self.cfg
            if (ts - f.last > cfg.idle_timeout or ts - f.start > cfg.active_timeout
                    or (f.closed and p.flags & SYN and not p.flags & ACK)):
                del flows[key]
                self._emit(f, "idle" if ts - f.last > cfg.idle_timeout else
                           "active" if ts - f.start > cfg.active_timeout else "reuse")
                f = None
        if f is None:
            if len(flows) >= self.cfg.max_flows:
                _, old = flows.popitem(last=False)
                self.evicted += 1
                self._emit(old, "evict")
            f = self._new(key, p)
            flows[key] = f
            if self.on_new:
                self.on_new(f)
        else:
            flows.move_to_end(key)
        self._update(f, p)
        if ts - self._last_sweep > 0.25:
            self._sweep(ts)

    # ------------------------------------------------------------------
    def _new(self, key, p):
        f = Flow()
        f.id, self._next_id = self._next_id, self._next_id + 1
        f.key, f.proto = key, p.proto
        f.init_src, f.init_sport, f.init_dst, f.init_dport = p.src, p.sport, p.dst, p.dport
        f.start = f.last = p.ts
        f.pk_o = f.pk_i = f.by_o = f.by_i = f.pl_o = f.pl_i = 0
        f.syn = f.fin = f.rst = f.ack = f.psh = 0
        f.closed, f.closed_at = False, 0.0
        f.n, f.mean, f.m2 = 0, 0.0, 0.0
        f.iats, f.times, f.splt_len, f.splt_iat = [], [], [], []
        f.last_pl_ts = None
        f.tls, f.tls_state, f.tls_buf, f.early_sent = None, 0, b"", False
        return f

    def _update(self, f, p):
        cfg, ts = self.cfg, p.ts
        fwd = p.src == f.init_src and p.sport == f.init_sport
        if f.pk_o + f.pk_i:                                   # Welford running IAT stats
            d = ts - f.last
            if d < 0:
                d = 0.0
            f.n += 1
            dl = d - f.mean
            f.mean += dl / f.n
            f.m2 += dl * (d - f.mean)
            if len(f.iats) < cfg.iat_seq_len:
                f.iats.append(d)
        if ts > f.last:
            f.last = ts
        if len(f.times) < cfg.max_flow_times:
            f.times.append(ts)
        if fwd:
            f.pk_o += 1
            f.by_o += p.ip_len
            f.pl_o += p.payload_len
        else:
            f.pk_i += 1
            f.by_i += p.ip_len
            f.pl_i += p.payload_len
        fl = p.flags
        if fl:
            if fl & SYN: f.syn += 1
            if fl & ACK: f.ack += 1
            if fl & PSH: f.psh += 1
            if fl & FIN: f.fin += 1
            if fl & RST: f.rst += 1
            if not f.closed and (fl & RST or f.fin >= 2):
                f.closed, f.closed_at = True, ts
        if p.payload_len and len(f.splt_len) < cfg.splt_n:    # SPLT: first N payload packets
            f.splt_len.append(p.payload_len if fwd else -p.payload_len)
            f.splt_iat.append(0.0 if f.last_pl_ts is None else max(ts - f.last_pl_ts, 0.0) * 1000.0)
            f.last_pl_ts = ts
            if len(f.splt_len) == cfg.splt_n and not f.early_sent:
                f.early_sent = True
                if self.on_early:
                    self.on_early(f)
        if f.tls_state < 2 and fwd and p.payload_len and p.proto == 6:
            self._tls(f, p)

    def _tls(self, f, p):
        buf = f.tls_buf + p.payload if f.tls_state == 1 else p.payload
        r = parse_client_hello(buf)
        if r is NEED_MORE and len(buf) < 16384:
            f.tls_state, f.tls_buf = 1, buf
            return
        f.tls_state, f.tls_buf = 2, b""
        if isinstance(r, TlsInfo):
            f.tls = r
            if self.on_tls:
                self.on_tls(f, r, p.ts)

    # ------------------------------------------------------------------
    def _sweep(self, now):
        self._last_sweep = now
        flows, cfg = self.flows, self.cfg
        while flows:
            k = next(iter(flows))
            f = flows[k]
            if f.closed and now - f.closed_at > cfg.closed_grace:
                reason = "rst" if f.rst else "fin"
            elif now - f.last > cfg.idle_timeout:
                reason = "idle"
            else:
                break
            del flows[k]
            self._emit(f, reason)

    def _emit(self, f, reason):
        self.on_flow(f, reason)

    def flush(self):
        while self.flows:
            _, f = self.flows.popitem(last=False)
            self._emit(f, "flush")
