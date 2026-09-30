"""Fusion: combines module alerts with threat-intel verdicts (blueprint Section 5/6).
   * confirmed IoC        -> early-exit CRITICAL alert straight from TI (skips ML)
   * weaker IoC + ML alert -> confidence boosted, severity floored at HIGH
   Input alerts must already be Section 6 dicts (dashboard `core.adapters.normalize` does that)."""
from __future__ import annotations
import copy
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinel_ti.engine import TIVerdict, _is_private


@dataclass
class FusionConfig:
    partial_boost: float = 0.45         # share of the remaining doubt removed by a TI hit
    partial_floor_conf: float = 0.75    # boosted alerts never fall below this
    min_conf_for_boost: float = 0.30    # ignore hopeless ML alerts
    ti_memory_s: float = 60.0           # how long a TI hit stays attached to its IPs
    dedupe_s: float = 60.0              # one TI alert per (src,dst,indicator) per window
    cutoffs: tuple = (0.92, 0.75, 0.55)  # CRITICAL, HIGH, MEDIUM


def _now_iso() -> str:
    n = datetime.now(timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"


class Fusion:
    def __init__(self, cfg: FusionConfig = FusionConfig(), clock=time.monotonic):
        self.cfg, self.clock = cfg, clock
        self._recent: dict[str, tuple[float, TIVerdict]] = {}   # ip -> (expires, verdict)
        self._sent: dict[tuple, float] = {}
        self._seq = 0

    def severity(self, conf: float) -> str:
        c, h, m = self.cfg.cutoffs
        return "CRITICAL" if conf >= c else "HIGH" if conf >= h else "MEDIUM" if conf >= m else "LOW"

    # ---- TI side ------------------------------------------------------------
    def observe(self, verdict: TIVerdict, rec: dict) -> dict | None:
        """Feed every TI verdict. Returns a Section 6 alert for confirmed IoCs (rate-limited), else None."""
        if not verdict.matched:
            return None
        now = self.clock()
        src, dst = rec.get("src_ip"), rec.get("dst_ip")
        keys = [f"{src}>{dst}"] if src and dst else []
        keys += [ip for ip in (src, dst) if ip and not _is_private(ip)]      # the external (IoC) side only
        if rec.get("record_type") in ("dns", "tls_hello") and src:            # host-level: it asked for / spoke to a bad indicator
            keys.append(src)
        for k in keys:
            self._recent[k] = (now + self.cfg.ti_memory_s, verdict)
        if len(self._recent) > 50_000:
            self._recent = {k: v for k, v in self._recent.items() if v[0] > now}
        if not verdict.early_exit:
            return None
        key = (rec.get("src_ip"), rec.get("dst_ip"), tuple(sorted((m["kind"], m["value"]) for m in verdict.matches)))
        if self._sent.get(key, 0) > now:
            return None
        self._sent[key] = now + self.cfg.dedupe_s
        if len(self._sent) > 50_000:
            self._sent = {k: v for k, v in self._sent.items() if v > now}
        return self._ti_alert(verdict, rec)

    def _ti_alert(self, v: TIVerdict, rec: dict) -> dict:
        self._seq += 1
        top = max(v.matches, key=lambda m: m["confidence"])
        return {
            "alert_id": f"ALT-TI-{self._seq:06d}", "timestamp": _now_iso(), "severity": "CRITICAL",
            "threat_class": "Known IoC (TI)", "confidence_score": round(max(v.confidence, 0.95), 2),
            "flow_identifier": {"src_ip": rec.get("src_ip", "?"), "dst_ip": rec.get("dst_ip", "?"),
                                "src_port": rec.get("src_port", 0), "dst_port": rec.get("dst_port", 0),
                                "protocol": rec.get("protocol", rec.get("proto", "?"))},
            "threat_intelligence": {"cache_hit": v.cache_hit, "ioc_matched": top["value"],
                                    "ioc_category": top["category"], "ti_override_applied": True},
            "supporting_evidence": {
                "primary_metric": "Local IoC Database Match",
                "feature_attributions": {"ti_reputation_weight": top["confidence"]},
                "reasons": [f"{m['kind']} '{m['value']}' in IoC database ({m['category']}, source: {m['source']})"
                            for m in v.matches]},
            "system_telemetry": {"processing_latency_ms": round(v.latency_us / 1000, 3),
                                 "path_taken": "EARLY_EXIT_TI_OVERRIDE", "enclave_mode": "PASSIVE_UNIDIRECTIONAL"},
        }

    # ---- ML/detector side -------------------------------------------------------
    def fuse(self, alert: dict) -> dict:
        """Attach/apply recent TI knowledge to a detector alert."""
        fl, now = alert["flow_identifier"], self.clock()
        hit = None
        for key in (f"{fl.get('src_ip')}>{fl.get('dst_ip')}", fl.get("dst_ip"), fl.get("src_ip")):
            exp_v = self._recent.get(key)
            if exp_v and exp_v[0] > now:
                hit = exp_v[1]
                break
        if hit is None:
            return alert
        out = copy.deepcopy(alert)
        top = max(hit.matches, key=lambda m: m["confidence"])
        out["threat_intelligence"] = {"cache_hit": hit.cache_hit, "ioc_matched": top["value"],
                                      "ioc_category": top["category"], "ti_override_applied": False}
        base = out["confidence_score"]
        if base >= self.cfg.min_conf_for_boost:
            boosted = max(base + self.cfg.partial_boost * (1 - base), self.cfg.partial_floor_conf)
            out["confidence_score"] = round(min(boosted, 1.0), 2)
            out["severity"] = self.severity(out["confidence_score"])
            out["threat_intelligence"]["ti_override_applied"] = True
            ev = out.setdefault("supporting_evidence", {"primary_metric": "-", "feature_attributions": {}})
            ev.setdefault("feature_attributions", {})["ti_reputation_weight"] = self.cfg.partial_boost
            ev.setdefault("reasons", []).append(
                f"Threat intel: {top['kind']} '{top['value']}' is a known IoC ({top['category']}); "
                f"confidence raised {base:.2f} -> {out['confidence_score']:.2f}")
            out.setdefault("system_telemetry", {})["path_taken"] = "FUSION_TI_OVERRIDE"
        return out
