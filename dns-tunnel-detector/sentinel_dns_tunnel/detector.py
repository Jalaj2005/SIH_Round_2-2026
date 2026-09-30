"""Streaming DNS-tunnelling detector based on query patterns, not domain-name randomness."""
from __future__ import annotations

import math
import time
import uuid
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import fmean, pstdev

_MULTI_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "co.jp"}


@dataclass
class DNSTunnelConfig:
    window_seconds: float = 120.0
    window_queries: int = 256
    min_queries: int = 8
    min_confidence: float = 0.65
    cooldown_seconds: float = 300.0
    popular_source_threshold: int = 25
    popular_confidence_multiplier: float = 0.6
    max_channels: int = 100_000
    max_popularity_domains: int = 50_000
    max_sources_per_domain: int = 256
    weights: dict[str, float] = field(default_factory=lambda: {
        "label_length": 0.25,
        "label_entropy": 0.25,
        "uniqueness": 0.25,
        "query_rate": 0.10,
        "cadence": 0.10,
        "txt_ratio": 0.05,
    })


@dataclass
class _Query:
    timestamp: float
    label: str
    is_txt: bool


@dataclass
class _Channel:
    queries: deque
    last_alert: float = -math.inf
    last_confidence: float = 0.0


def _entropy(label: str) -> float:
    counts = Counter(label)
    length = max(len(label), 1)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _score(value: float, low: float, high: float) -> float:
    return max(0.0, min(1.0, (value - low) / (high - low)))


def _split_domain(fqdn: str) -> tuple[str, str, str]:
    labels = fqdn.split(".")
    if len(labels) < 2:
        return labels[0], "", ""
    suffix_size = 2 if ".".join(labels[-2:]) in _MULTI_SUFFIXES and len(labels) > 2 else 1
    return labels[-suffix_size - 1], ".".join(labels[-suffix_size:]), ".".join(labels[:-suffix_size - 1])


class DNSTunnelDetector:
    """Consume Module 1 DNS records and emit Section 6 alerts for tunnel-like patterns."""

    name = "dns_tunnel"

    def __init__(self, cfg: DNSTunnelConfig | None = None, clock=time.time):
        self.cfg = cfg or DNSTunnelConfig()
        self.clock = clock
        self._channels: OrderedDict[tuple[str, str], _Channel] = OrderedDict()
        self._domain_sources: OrderedDict[str, set[str]] = OrderedDict()
        self._sequence = 0
        self.stats = {"seen": 0, "skipped": 0, "alerts": 0}

    def process_dns(self, record: dict) -> dict | None:
        started = time.perf_counter()
        self.stats["seen"] += 1
        fqdn = str(record.get("domain") or "").lower().strip().rstrip(".")
        if not fqdn or record.get("is_response"):
            self.stats["skipped"] += 1
            return None
        sld, suffix, subdomain = _split_domain(fqdn)
        registered_domain = f"{sld}.{suffix}" if suffix else sld
        source_ip = str(record.get("src_ip") or "?")
        timestamp = float(record.get("ts", self.clock()))
        sources = self._domain_sources.get(registered_domain)
        if sources is None:
            sources = self._domain_sources[registered_domain] = set()
            if len(self._domain_sources) > self.cfg.max_popularity_domains:
                self._domain_sources.popitem(last=False)
        else:
            self._domain_sources.move_to_end(registered_domain)
        if len(sources) < self.cfg.max_sources_per_domain:
            sources.add(source_ip)

        labels = [label for label in subdomain.split(".") if label]
        if not labels:
            self.stats["skipped"] += 1
            return None
        payload_label = max(labels, key=len)
        if len(payload_label) < 8 or not payload_label.isalnum():
            self.stats["skipped"] += 1
            return None

        key = (source_ip, registered_domain)
        channel = self._channels.get(key)
        if channel is None:
            channel = _Channel(deque(maxlen=self.cfg.window_queries))
            self._channels[key] = channel
            if len(self._channels) > self.cfg.max_channels:
                self._channels.popitem(last=False)
        else:
            self._channels.move_to_end(key)

        channel.queries.append(_Query(timestamp, payload_label, bool(record.get("is_txt_null"))))
        while channel.queries and timestamp - channel.queries[0].timestamp > self.cfg.window_seconds:
            channel.queries.popleft()
        if len(channel.queries) < self.cfg.min_queries:
            return None

        samples = list(channel.queries)
        payload_labels = [sample.label for sample in samples]
        lengths = [len(label) for label in payload_labels]
        entropies = [_entropy(label) for label in payload_labels]
        unique_ratio = len(set(payload_labels)) / len(payload_labels)
        span = max(samples[-1].timestamp - samples[0].timestamp, 0.0)
        query_rate = len(samples) / max(span, 1.0)
        intervals = [
            later.timestamp - earlier.timestamp
            for earlier, later in zip(samples, samples[1:])
            if later.timestamp > earlier.timestamp
        ]
        interval_mean = fmean(intervals) if intervals else 0.0
        interval_cv = pstdev(intervals) / interval_mean if interval_mean else math.inf
        txt_ratio = sum(sample.is_txt for sample in samples) / len(samples)
        components = {
            "label_length": _score(fmean(lengths), 20.0, 50.0),
            "label_entropy": _score(fmean(entropies), 2.5, 3.8),
            "uniqueness": _score(unique_ratio, 0.5, 0.95),
            "query_rate": _score(query_rate, 0.1, 5.0),
            "cadence": max(0.0, 1.0 - interval_cv / 0.75),
            "txt_ratio": txt_ratio,
        }
        confidence = sum(self.cfg.weights[name] * value for name, value in components.items())
        source_count = len(sources)
        if source_count >= self.cfg.popular_source_threshold:
            confidence *= self.cfg.popular_confidence_multiplier
        confidence = round(min(1.0, confidence), 4)
        if confidence < self.cfg.min_confidence:
            return None
        if (timestamp - channel.last_alert < self.cfg.cooldown_seconds
                and confidence - channel.last_confidence < 0.1):
            return None

        channel.last_alert, channel.last_confidence = timestamp, confidence
        self._sequence += 1
        self.stats["alerts"] += 1
        severity = "CRITICAL" if confidence >= 0.92 else "HIGH" if confidence >= 0.80 else "MEDIUM"
        event_time = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return {
            "alert_id": f"ALT-DNST-{self._sequence:06d}-{uuid.uuid4().hex[:6]}",
            "timestamp": event_time.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "severity": severity,
            "threat_class": "DNS Tunnelling",
            "confidence_score": confidence,
            "flow_identifier": {
                "src_ip": source_ip,
                "dst_ip": record.get("dst_ip", "?"),
                "src_port": record.get("src_port", 0),
                "dst_port": record.get("dst_port", 53),
                "protocol": record.get("protocol", "UDP"),
            },
            "threat_intelligence": {},
            "supporting_evidence": {
                "primary_metric": "Encoded subdomain uniqueness and query cadence",
                "feature_attributions": {
                    **{name: round(value, 3) for name, value in components.items()},
                    "mean_label_length": round(fmean(lengths), 2),
                    "mean_label_entropy": round(fmean(entropies), 3),
                    "unique_subdomain_ratio": round(unique_ratio, 3),
                    "queries_per_second": round(query_rate, 3),
                    "interval_cv": round(interval_cv, 3) if math.isfinite(interval_cv) else None,
                    "distinct_sources_to_domain": source_count,
                },
            },
            "system_telemetry": {
                "processing_latency_ms": round((time.perf_counter() - started) * 1000, 3),
                "path_taken": "DNS_TUNNEL_PATTERN",
                "enclave_mode": "PASSIVE_UNIDIRECTIONAL",
            },
        }