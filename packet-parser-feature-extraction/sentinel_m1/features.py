"""Builds the unified feature vectors (plain dicts) - the single place features are computed."""
import math
import socket
import time
from collections import OrderedDict, deque

import numpy as np

from .spectral import periodicity, shannon_str

_VOWELS = set("aeiou")


def ip_str(b):
    return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)


class PairTracker:
    """Start times of connections per (src, dst, dport, proto) -> beacon features across flows."""

    def __init__(self, cfg):
        self.cfg, self.pairs = cfg, OrderedDict()

    def note(self, f):
        k = (f.init_src, f.init_dst, f.init_dport, f.proto)
        e = self.pairs.get(k)
        if e is None:
            if len(self.pairs) >= self.cfg.max_pairs:
                self.pairs.popitem(last=False)
            e = self.pairs[k] = [deque(maxlen=self.cfg.pair_history), 0, None]
        else:
            self.pairs.move_to_end(k)
        e[0].append(f.start)

    def features(self, f):
        e = self.pairs.get((f.init_src, f.init_dst, f.init_dport, f.proto))
        out = {"pair_conn_count": 0, "pair_iat_mean": 0.0, "pair_iat_cv": 0.0,
               "pair_ls_peak_power": 0.0, "pair_ls_peak_period_s": 0.0, "pair_ls_snr": 0.0}
        if e is None:
            return out
        n = len(e[0])
        out["pair_conn_count"] = n
        if n < self.cfg.ls_min_events:
            return out
        if e[2] is None or n >= e[1] + 4:                   # recompute only when history grew a bit
            t = np.fromiter(e[0], dtype=np.float64, count=n)
            t.sort()
            d = np.diff(t)
            m = float(d.mean())
            ls = periodicity(t)
            e[1], e[2] = n, {"pair_iat_mean": m, "pair_iat_cv": float(d.std() / m) if m > 0 else 0.0,
                             "pair_ls_peak_power": ls["ls_peak_power"],
                             "pair_ls_peak_period_s": ls["ls_peak_period_s"], "pair_ls_snr": ls["ls_snr"]}
        out.update(e[2])
        return out


class FeatureExtractor:
    def __init__(self, cfg, windows):
        self.cfg, self.windows, self.pairs = cfg, windows, PairTracker(cfg)

    # ---------------------------------------------------------- flow
    def _flow_base(self, f, rtype):
        return {"record_type": rtype, "flow_id": f.id, "ts_start": f.start,
                "src_ip": ip_str(f.init_src), "dst_ip": ip_str(f.init_dst),
                "src_port": f.init_sport, "dst_port": f.init_dport, "protocol": f.proto}

    def _tls_fields(self, f, r):
        t = f.tls
        r.update({"ja3": t.ja3 if t else None, "ja4": t.ja4 if t else None,
                  "sni": t.sni if t else None, "tls_cipher_count": t.cipher_count if t else 0,
                  "tls_ext_count": t.ext_count if t else 0, "tls_version": t.version if t else 0,
                  "tls_alpn": t.alpn if t else None})
        r["splt_len"] = list(f.splt_len)
        r["splt_iat_ms"] = list(f.splt_iat)
        return r

    def flow_record(self, f, reason):
        cfg = self.cfg
        dur = f.last - f.start
        pk, by = f.pk_o + f.pk_i, f.by_o + f.by_i
        r = self._flow_base(f, "flow")
        r["ts_end"], r["duration"], r["end_reason"] = f.last, dur, reason
        r["half_duplex"] = f.pk_i == 0 or f.pk_o == 0
        r.update({"pkts_out": f.pk_o, "pkts_in": f.pk_i, "bytes_out": f.by_o, "bytes_in": f.by_i,
                  "bytes_total": by, "payload_out": f.pl_o, "payload_in": f.pl_i,
                  "pps": pk / dur if dur > 0 else float(pk),
                  "bytes_per_sec": by / dur if dur > 0 else float(by),
                  "out_in_byte_ratio": f.by_o / max(f.by_i, 1),        # diode: in==0 -> ratio == bytes_out
                  "syn_cnt": f.syn, "fin_cnt": f.fin, "rst_cnt": f.rst, "ack_cnt": f.ack, "psh_cnt": f.psh})
        var = f.m2 / (f.n - 1) if f.n > 1 else 0.0
        r.update({"iat_n": f.n, "iat_mean": f.mean, "iat_var": var, "iat_std": math.sqrt(var),
                  "iat_cv": math.sqrt(var) / f.mean if f.mean > 0 else 0.0, "iat_seq": list(f.iats)})
        if len(f.times) >= cfg.ls_min_events:
            r.update(periodicity(f.times))
        else:
            r.update({"ls_peak_power": 0.0, "ls_peak_period_s": 0.0, "ls_snr": 0.0, "ls_n_events": len(f.times)})
        r.update(self.pairs.features(f))
        self._tls_fields(f, r)
        w = self.windows
        pd = w.prev_dst.get(f.init_dst)
        ps = w.prev_src.get(f.init_src)
        r["dst_win_pps"], r["dst_win_src_entropy"], r["dst_win_unique_src"] = pd if pd else (0.0, 0.0, 0)
        r["src_win_unique_dst"], r["src_win_dport_entropy"], r["src_win_unique_targets"] = ps if ps else (0, 0.0, 0)
        r["m1_emit_wall"] = time.time()
        return r

    def early_record(self, f):
        r = self._flow_base(f, "flow_early")
        r["ts"] = f.last
        r["m1_emit_wall"] = time.time()
        return self._tls_fields(f, r)

    def tls_record(self, f, t, ts):
        r = self._flow_base(f, "tls_hello")
        r.update({"ts": ts, "ja3": t.ja3, "ja3_string": t.ja3_str, "ja4": t.ja4, "sni": t.sni,
                  "tls_cipher_count": t.cipher_count, "tls_ext_count": t.ext_count,
                  "tls_version": t.version, "tls_alpn": t.alpn, "m1_emit_wall": time.time()})
        return r

    # ---------------------------------------------------------- dns
    def dns_record(self, p):
        q = p.dns
        name = q.name
        labels = name.split(".") if name else [""]
        tld = labels[-1]
        sld = labels[-2] if len(labels) > 1 else labels[0]      # naive; swap in a PSL-aware split if needed
        alnum = [c for c in sld if c.isalpha()]
        v = sum(1 for c in alnum if c in _VOWELS)
        c = len(alnum) - v
        bi, tri = {}, {}
        for i in range(len(sld) - 1):
            g = sld[i:i + 2]
            bi[g] = bi.get(g, 0) + 1
            if i < len(sld) - 2:
                g3 = sld[i:i + 3]
                tri[g3] = tri.get(g3, 0) + 1
        return {"record_type": "dns", "ts": p.ts, "src_ip": ip_str(p.src), "dst_ip": ip_str(p.dst),
                "src_port": p.sport, "dst_port": p.dport, "protocol": p.proto,
                "domain": name, "sld": sld, "tld": tld, "is_response": q.is_response, "rcode": q.rcode,
                "qtype": q.qtype, "is_txt_null": q.qtype in (16, 10),
                "query_len": len(name), "label_count": len(labels),
                "max_label_len": max(len(x) for x in labels), "sld_len": len(sld),
                "char_entropy": shannon_str(name.replace(".", "")), "sld_entropy": shannon_str(sld),
                "digit_ratio": sum(ch.isdigit() for ch in sld) / len(sld) if sld else 0.0,
                "vowel_ratio": v / len(sld) if sld else 0.0,
                "vowel_consonant_ratio": v / c if c else float(v),
                "ngram2": bi, "ngram3": tri, "ngram2_unique_ratio": len(bi) / max(len(sld) - 1, 1),
                "m1_emit_wall": time.time()}
