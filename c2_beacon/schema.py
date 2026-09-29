"""Shared data contracts. Every module in the project (DDoS, DGA, scan, ...)
should consume `Flow` and emit `Alert`, so the dashboard needs no per-module code."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional
import json, uuid


@dataclass(slots=True)
class Flow:
    """One passively observed flow record (metadata only, no payload)."""
    ts: float                 # flow start time (epoch seconds, event time)
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "TCP"        # TCP / UDP / QUIC
    src_port: int = 0
    bytes_out: int = 0        # src -> dst
    bytes_in: int = 0         # dst -> src (if observed)
    pkts: int = 0
    flow_id: str = ""

    def __post_init__(self):
        if not self.flow_id:
            self.flow_id = f"{self.src_ip}:{self.src_port}>{self.dst_ip}:{self.dst_port}/{self.proto}@{self.ts:.3f}"


@dataclass(slots=True)
class Alert:
    """Standardised alert record (timestamp, flow id, class, confidence, evidence)."""
    timestamp: float
    flow_id: str
    threat_class: str
    confidence: float         # 0..1
    severity: str             # LOW / MEDIUM / HIGH
    src_ip: str
    dst_ip: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    module: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=float)
