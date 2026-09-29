import time
from typing import Optional
from pydantic import BaseModel, Field

TCP_FIN, TCP_SYN, TCP_RST, TCP_ACK = 0x01, 0x02, 0x04, 0x10


class Flow(BaseModel):
    """Parsed unidirectional flow record (NetFlow/IPFIX-like) from the ingest layer."""
    ts: float = Field(default_factory=time.time, description="flow start, epoch seconds")
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    tcp_flags: int = 0          # OR-ed TCP flags, 0 if unknown / non-TCP
    packets: int = 1
    bytes: int = 0
    flow_id: Optional[str] = None

    def fid(self) -> str:
        return self.flow_id or f"{self.src_ip}:{self.src_port}>{self.dst_ip}:{self.dst_port}/{self.protocol}"


class Alert(BaseModel):
    """Standardised alert schema shared by every module of the pipeline."""
    alert_id: str
    timestamp: str              # ISO-8601 UTC (event time)
    flow_id: str                # flow that tripped the threshold
    threat_class: str = "reconnaissance_port_scan"
    sub_type: str               # horizontal_scan | vertical_scan | combined_scan
    severity: str               # low | medium | high | critical
    confidence: float           # 0..1
    src_ip: str
    window_seconds: float
    evidence: dict
    module: str = "module6-recon-detector"
