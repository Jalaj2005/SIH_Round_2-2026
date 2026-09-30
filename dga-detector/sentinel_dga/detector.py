"""Streaming DGA detector.  Input: Module 1 `dns` records.  Output: Section 6 alert dicts.

Per-domain score  = trained model (if models/dga_model.joblib exists) or an explainable weighted heuristic.
Per-host context  = many distinct random-looking names from one host in a short window is what real DGA malware does,
                    so a burst raises confidence; a single odd name (CDN, hash-based subdomain) stays a low alert."""
from __future__ import annotations
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from sentinel_dga.features import FEATURES, extract_features, split_domain

_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_SKIP_SUFFIXES = (".arpa", ".local", ".lan", ".internal", ".localdomain", ".home", ".corp")


def _norm(v: float, lo: float, hi: float) -> float:
    return 0.0 if v <= lo else 1.0 if v >= hi else (v - lo) / (hi - lo)


@dataclass
class DGAConfig:
    alert_conf: float = 0.60           # minimum combined confidence to emit an alert
    burst_window_s: float = 60.0
    burst_target: int = 5              # distinct suspicious names in the window that count as a full burst
    domain_suspicious: float = 0.60    # per-domain score that counts toward the burst
    min_length: int = 7                # shorter labels carry too little signal
    dedupe_s: float = 300.0
    host_interval_s: float = 10.0      # per host: one alert per interval unless severity escalates
    max_hosts: int = 100_000
    allowlist: frozenset = field(default_factory=lambda: frozenset(
        {"google.com", "gstatic.com", "googleapis.com", "cloudfront.net", "amazonaws.com", "akamaiedge.net",
         "akamai.net", "microsoft.com", "windowsupdate.com", "office.com", "apple.com", "icloud.com", "cloudflare.com"}))
    # heuristic weights: the base signals sum to 1.0; digit_ratio / hex_like are bonuses that can only add
    weights: dict = field(default_factory=lambda: {
        "trigram_logp": 0.35, "word_coverage": 0.25, "max_consonant_run": 0.15, "entropy": 0.10, "length": 0.15,
        "digit_ratio": 0.15, "hex_like": 0.10})


class DGADetector:
    def __init__(self, cfg: DGAConfig | None = None, model_path: str | Path | None = None, clock=time.time):
        self.cfg, self.clock = cfg or DGAConfig(), clock
        self.model = self.threshold = None
        if model_path and Path(model_path).exists():
            import joblib
            art = joblib.load(model_path)
            self.model, self.threshold = art["model"], float(art.get("threshold", 0.5))
            self.features = art.get("features", FEATURES)
        self._hosts: OrderedDict[str, deque] = OrderedDict()
        self._sent: dict[tuple, float] = {}
        self._host_sent: dict[str, tuple] = {}
        self._seq = 0
        self.stats = {"seen": 0, "skipped": 0, "alerts": 0}
        self.score_domain = lru_cache(maxsize=200_000)(self._score_domain)

    # ---- per-domain scoring -----------------------------------------------------
    def _score_domain(self, sld: str) -> tuple[float, tuple]:
        f = extract_features(sld)
        if self.model is not None:
            import pandas as pd
            p = float(self.model.predict_proba(pd.DataFrame([[f[k] for k in self.features]], columns=self.features))[0][1])
            score = min(1.0, p * 0.5 / self.threshold) if p < self.threshold else 0.5 + 0.5 * (p - self.threshold) / (1 - self.threshold + 1e-9)
            return score, ()
        sig = {
            "trigram_logp": _norm(-f["trigram_logp"], 2.4, 3.3),
            "word_coverage": 1.0 - _norm(f["word_coverage"], 0.0, 0.85),
            "max_consonant_run": _norm(f["max_consonant_run"], 3, 6),
            "digit_ratio": _norm(f["digit_ratio"], 0.10, 0.40),
            "entropy": _norm(f["entropy"], 3.0, 3.9),
            "length": _norm(f["length"], 8, 14),
            "hex_like": f["hex_like"],
        }
        contrib = tuple((k, round(self.cfg.weights[k] * v, 3)) for k, v in sig.items())
        score = sum(v for _, v in contrib) * min(1.0, f["length"] / 10.0)
        return round(min(score, 1.0), 3), contrib

    # ---- streaming ----------------------------------------------------------------
    def process_dns(self, rec: dict) -> dict | None:
        t0 = time.perf_counter()
        fqdn = (rec.get("domain") or "").lower().strip().rstrip(".")
        self.stats["seen"] += 1
        if not fqdn or fqdn.endswith(_SKIP_SUFFIXES) or "_" in fqdn or "." not in fqdn:
            self.stats["skipped"] += 1
            return None
        sld, suffix, _sub = split_domain(fqdn)
        registered = f"{sld}.{suffix}"
        if registered in self.cfg.allowlist or len(sld) < self.cfg.min_length or sld.startswith("xn--"):
            self.stats["skipped"] += 1
            return None

        score, contrib = self.score_domain(sld)
        src, now = rec.get("src_ip", "?"), self.clock()
        burst = self._burst(src, registered, score, now)
        conf = round(min(1.0, 0.7 * score + 0.3 * burst), 2)
        if conf < self.cfg.alert_conf:
            return None
        key = (src, registered)
        if self._sent.get(key, 0) > now:
            return None
        rank = _RANK[self._sev(conf)]
        last = self._host_sent.get(src)
        if last and last[0] > now and rank <= last[1]:
            return None                                   # already reported this host recently, nothing worse to say
        self._host_sent[src] = (now + self.cfg.host_interval_s, rank)
        if len(self._host_sent) > self.cfg.max_hosts:
            self._host_sent = {k: v for k, v in self._host_sent.items() if v[0] > now}
        self._sent[key] = now + self.cfg.dedupe_s
        if len(self._sent) > 100_000:
            self._sent = {k: v for k, v in self._sent.items() if v > now}
        self.stats["alerts"] += 1
        return self._alert(rec, registered, sld, score, burst, conf, contrib, (time.perf_counter() - t0) * 1000)

    def _burst(self, src: str, registered: str, score: float, now: float) -> float:
        dq = self._hosts.get(src)
        if dq is None:
            dq = self._hosts[src] = deque(maxlen=64)
            if len(self._hosts) > self.cfg.max_hosts:
                self._hosts.popitem(last=False)
        else:
            self._hosts.move_to_end(src)
        if score >= self.cfg.domain_suspicious:
            dq.append((now, registered))
        while dq and dq[0][0] < now - self.cfg.burst_window_s:
            dq.popleft()
        return min(1.0, len({d for _, d in dq}) / self.cfg.burst_target)

    def _sev(self, conf: float) -> str:
        return "CRITICAL" if conf >= 0.92 else "HIGH" if conf >= 0.80 else "MEDIUM" if conf >= 0.68 else "LOW"

    def _alert(self, rec, registered, sld, score, burst, conf, contrib, ms) -> dict:
        self._seq += 1
        n = datetime.now(timezone.utc)
        reasons = [f"'{sld}' looks algorithmically generated (randomness score {score:.2f})"]
        f = extract_features(sld)
        if f["word_coverage"] < 0.3:
            reasons.append(f"only {f['word_coverage']:.0%} of the name is made of dictionary words")
        if f["max_consonant_run"] >= 5:
            reasons.append(f"unpronounceable run of {int(f['max_consonant_run'])} consonants")
        if burst >= 0.4:
            reasons.append(f"host queried ~{round(burst * self.cfg.burst_target)} distinct suspicious names within "
                           f"{int(self.cfg.burst_window_s)} s")
        return {
            "alert_id": f"ALT-DGA-{self._seq:06d}",
            "timestamp": n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z",
            "severity": self._sev(conf), "threat_class": "DGA Domain", "confidence_score": conf,
            "flow_identifier": {"src_ip": rec.get("src_ip", "?"), "dst_ip": rec.get("dst_ip", "?"),
                                "src_port": rec.get("src_port", 0), "dst_port": rec.get("dst_port", 53),
                                "protocol": rec.get("protocol", rec.get("proto", "UDP"))},
            "threat_intelligence": {},
            "supporting_evidence": {
                "primary_metric": "Domain Randomness Score",
                "feature_attributions": {**dict(contrib), "host_burst": round(burst, 2)},
                "reasons": reasons, "domain": registered},
            "system_telemetry": {"processing_latency_ms": round(ms, 3), "path_taken": "LEXICAL_DGA",
                                 "enclave_mode": "PASSIVE_UNIDIRECTIONAL"},
            "module": "dga_detector",
        }
