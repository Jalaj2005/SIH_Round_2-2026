"""Bridge Module 1 feature records and local detectors to dashboard files."""
from __future__ import annotations

import json
import math
import os
import statistics
import sys
import tempfile
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any

import pandas as pd

import config

ROOT = Path(__file__).resolve().parents[2]
for _module_dir in (
    "c2-beacon-module",
    "DDos_Detector",
    "dga-detector",
    "dns-tunnel-detector",
    "exfiltration-detection",
    "recon-detector",
    "threat-intel-fusion",
):
    _path = str(ROOT / _module_dir)
    if _path not in sys.path:
        sys.path.insert(0, _path)

from c2_beacon import BeaconDetector, Flow as BeaconFlow
from ddos_detector.detector import DDoSDetector
from sentinel_dga import DGADetector
from sentinel_dns_tunnel import DNSTunnelDetector
from sentinel_ti import Fusion, IoCStore, TIEngine
from sentinel_ti.loader import load_csv
from detection.exfiltration_detector import ExfiltrationDetector
from evidence.evidence_generator import EvidenceGenerator
from features.features_pipeline import extract_features as extract_exfil_features
from schemas.flow_schema import FlowRecord
from app.detector import ReconDetector
from app.schemas import Flow as ReconFlow, TCP_SYN


class DashboardPipeline:
    """Consume Module 1 records and write the dashboard's alert/telemetry contract."""

    def __init__(self, alerts_file=None, telemetry_file=None, load_tls_model=True, ioc_db=None):
        self.alerts_file = Path(alerts_file or config.ALERTS_FILE)
        self.telemetry_file = Path(telemetry_file or config.TELEMETRY_FILE)
        self.beacon = BeaconDetector()
        self.ddos = DDoSDetector()
        self.dga = DGADetector()
        self.dns_tunnel = DNSTunnelDetector()
        self.exfil = ExfiltrationDetector()
        self.exfil_evidence = EvidenceGenerator()
        self.recon = ReconDetector()
        ioc_path = str(ioc_db or os.getenv("SENTINEL_IOC_DB", ":memory:"))
        if ioc_path != ":memory:":
            Path(ioc_path).parent.mkdir(parents=True, exist_ok=True)
        self.ioc_store = IoCStore(ioc_path)
        sample_iocs = ROOT / "threat-intel-fusion" / "data" / "sample_iocs.csv"
        if self.ioc_store.count() == 0 and sample_iocs.exists():
            load_csv(str(sample_iocs), self.ioc_store)
        self.ti_engine = TIEngine(self.ioc_store)
        self.ti_fusion = Fusion()
        self.destinations: dict[str, set[str]] = defaultdict(set)
        self.host_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=30))
        self.latencies: deque = deque(maxlen=500)
        self.module_counts = {name: 0 for name in config.THREAT_CLASSES}
        self._window_second: int | None = None
        self._window_bytes = 0
        self._window_flow_bytes = 0
        self._has_window_volume = False
        self._window_flows = 0
        self._window_packet_drops = 0
        self.alert_count = 0
        self.tls_model = None
        self.tls_features = []
        self.tls_threshold = 0.5
        self.tls_status = "disabled"
        if load_tls_model:
            self._load_tls_model()

    def _load_tls_model(self) -> None:
        model_path = ROOT / "tls-malware-detection" / "final_module5_malware_model.joblib"
        try:
            import joblib

            artifacts = joblib.load(model_path)
            self.tls_model = artifacts["model"]
            self.tls_features = artifacts["features"]
            self.tls_threshold = float(artifacts.get("threshold", 0.5))
            self.tls_status = "loaded"
        except (OSError, KeyError, ImportError, ValueError, TypeError) as exc:
            self.tls_status = f"unavailable: {exc}"

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
        return datetime.fromtimestamp(float(value), tz=timezone.utc)

    @staticmethod
    def _as_float(record: dict, key: str, default: float = 0.0) -> float:
        try:
            return float(record.get(key, default) or 0.0)
        except (TypeError, ValueError):
            return default

    def process_record(self, record: dict) -> None:
        started = time.perf_counter()
        record_type = record.get("record_type")
        alerts = []
        ti_alert = self._check_threat_intel(record)
        if ti_alert:
            alerts.append(ti_alert)
        if record_type == "dns":
            dga_alert = self.dga.process_dns(record)
            if dga_alert:
                alerts.append(dga_alert)
            tunnel_alert = self.dns_tunnel.process_dns(record)
            if tunnel_alert:
                alerts.append(tunnel_alert)
        elif record_type == "window" and record.get("scope") == "dst":
            alert = self._detect_ddos(record)
            if alert:
                alerts.append(alert)
            self._window_bytes += int(record.get("bytes", 0) or 0)
            self._has_window_volume = True
        elif record_type == "flow":
            alerts.extend(self._detect_flow(record))
            self._window_flows += 1
            self._window_flow_bytes += int(record.get("bytes_total", 0) or 0)

        for alert in alerts:
            self._write_alert(self.ti_fusion.fuse(alert))
        self.latencies.append((time.perf_counter() - started) * 1000)
        event_time = record.get("ts", record.get("ts_start"))
        if event_time is not None:
            self._advance_telemetry(float(event_time))

    def _check_threat_intel(self, record: dict) -> dict | None:
        verdict = self.ti_engine.check_record(record)
        return self.ti_fusion.observe(verdict, record)

    def _detect_ddos(self, record: dict) -> dict | None:
        duration = max(self._as_float(record, "window_s", 1.0), 1e-9)
        pps = self._as_float(record, "pps")
        features = {
            "packets_per_sec": pps,
            "packet_count": self._as_float(record, "pkts"),
            "unique_source_ips": self._as_float(record, "unique_src", 1),
            "unique_destination_ips": 1,
            "source_ip_entropy": self._as_float(record, "src_entropy"),
            "syn_rate": self._as_float(record, "syn_pkts") / duration,
            "syn_count": self._as_float(record, "syn_pkts") / duration,
            "udp_packet_rate": self._as_float(record, "udp_pkts") / duration,
            "udp_packet_count": self._as_float(record, "udp_pkts") / duration,
            "inbound_bytes": 0,
            "outbound_bytes": 0,
            "inbound_outbound_ratio": 1,
            "burstiness": 0,
            "std_inter_arrival_time": 1,
        }
        result = self.ddos.detect(features)
        if not result.get("detected"):
            return None
        return self._dashboard_alert(
            record,
            threat_class="DDoS Flood",
            confidence=result["confidence"],
            severity=result["severity"],
            src_ip="multiple",
            dst_ip=record.get("ip", "?"),
            primary_metric=result.get("type", "DDoS feature window"),
            evidence={"scores": result.get("scores", {}), "indicators": result.get("evidence", [])},
            module="ddos_detector",
        )

    def _detect_flow(self, record: dict) -> list[dict]:
        alerts = []
        ts = self._as_float(record, "ts_start", time.time())
        src_ip, dst_ip = record.get("src_ip", "?"), record.get("dst_ip", "?")
        src_port, dst_port = int(record.get("src_port", 0) or 0), int(record.get("dst_port", 0) or 0)
        protocol = str(record.get("protocol", "TCP")).upper()
        flow_id = str(record.get("flow_id", uuid.uuid4().hex))

        beacon_flow = BeaconFlow(
            ts=ts,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto=protocol,
            src_port=src_port,
            bytes_out=int(record.get("bytes_out", 0) or 0),
            bytes_in=int(record.get("bytes_in", 0) or 0),
            pkts=int(record.get("pkts_out", 0) or 0) + int(record.get("pkts_in", 0) or 0),
            flow_id=flow_id,
        )
        for detection in self.beacon.process_flow(beacon_flow):
            alerts.append(self._dashboard_alert(
                record, "Botnet C2 Beaconing", detection.confidence, detection.severity,
                detection.src_ip, detection.dst_ip, "Inter-flow periodicity", detection.evidence,
                "c2_beacon",
            ))

        recon_flow = ReconFlow(
            ts=ts, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
            protocol=protocol, tcp_flags=TCP_SYN if record.get("syn_cnt") else 0,
            packets=int(record.get("pkts_out", 0) or 0) + int(record.get("pkts_in", 0) or 0),
            bytes=int(record.get("bytes_total", 0) or 0), flow_id=flow_id,
        )
        detection = self.recon.process(recon_flow)
        if detection:
            alerts.append(self._dashboard_alert(
                record, "Port Scan", detection.confidence, detection.severity,
                detection.src_ip, dst_ip, detection.sub_type, detection.evidence,
                "recon_detector",
            ))

        exfil_alert = self._detect_exfil(record, ts, flow_id, src_ip, dst_ip, src_port, dst_port, protocol)
        if exfil_alert:
            alerts.append(exfil_alert)

        tls_alert = self._detect_tls(record)
        if tls_alert:
            alerts.append(tls_alert)
        return alerts

    def _detect_exfil(self, record, ts, flow_id, src_ip, dst_ip, src_port, dst_port, protocol):
        seen = dst_ip in self.destinations[src_ip]
        try:
            flow = FlowRecord(
                flow_id=flow_id,
                timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                duration=max(self._as_float(record, "duration"), 0),
                bytes_sent=int(record.get("bytes_out", 0) or 0),
                bytes_received=int(record.get("bytes_in", 0) or 0),
                packets_sent=int(record.get("pkts_out", 0) or 0),
                packets_received=int(record.get("pkts_in", 0) or 0),
                destination_is_external=not ip_address(dst_ip).is_private,
                destination_seen_before=seen,
            )
        except (ValueError, TypeError):
            return None

        history = self.host_history[src_ip]
        old_bytes = [item[0] for item in history]
        old_rates = [item[1] for item in history]
        baseline_bytes = statistics.fmean(old_bytes) if old_bytes else 0.0
        baseline_std = statistics.pstdev(old_bytes) if len(old_bytes) > 1 else 0.0
        baseline_rate = statistics.fmean(old_rates) if old_rates else 0.0
        duration = max(flow.duration, 1.0)
        features = extract_exfil_features(
            flow,
            flows=[flow],
            window_seconds=duration,
            historical_avg_outbound_bytes=baseline_bytes,
            historical_std_outbound_bytes=baseline_std,
            historical_avg_transfer_rate=baseline_rate,
        )
        if record.get("half_duplex"):
            features["byte_ratio"] = 0.0
            features["packet_ratio"] = 0.0
            features["byte_rate_ratio"] = 0.0
        result = self.exfil.detect(features)
        evidence = self.exfil_evidence.generate(features)
        self.destinations[src_ip].add(dst_ip)
        history.append((flow.bytes_sent, flow.bytes_sent / duration))
        if not result["is_suspicious"]:
            return None
        return self._dashboard_alert(
            record, "Data Exfiltration", result["risk_score"] / 100,
            result["severity"], src_ip, dst_ip, "Outbound volume and destination features",
            {"risk_score": result["risk_score"], "indicators": evidence}, "exfiltration_detector",
        )

    def _detect_tls(self, record: dict) -> dict | None:
        if (self.tls_model is None or not hasattr(self.tls_model, "predict_proba")
                or not record.get("ja3")):
            return None
        packet_count = max(1, int(record.get("pkts_out", 0) or 0) + int(record.get("pkts_in", 0) or 0))
        byte_count = self._as_float(record, "bytes_total")
        sizes = [abs(float(value)) for value in record.get("splt_len", []) if value is not None]
        iats = [float(value) / 1000 for value in record.get("iat_seq", []) if value is not None]
        mean_size = byte_count / packet_count
        size_std = statistics.pstdev(sizes) if len(sizes) > 1 else 0.0
        mean_iat = self._as_float(record, "iat_mean")
        data = {
            "duration": self._as_float(record, "duration"),
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packet_rate": self._as_float(record, "pps"),
            "byte_rate": self._as_float(record, "bytes_per_sec"),
            "packet_size_mean": mean_size,
            "packet_size_std": size_std,
            "packet_size_cv": size_std / mean_size if mean_size else 0.0,
            "first_packet_size": sizes[0] if sizes else 0.0,
            "last_packet_size": sizes[-1] if sizes else 0.0,
            "iat_mean": mean_iat,
            "iat_std": self._as_float(record, "iat_std"),
            "iat_max": max(iats, default=0.0),
            "iat_cv": self._as_float(record, "iat_cv"),
            "periodicity_score": self._as_float(record, "pair_ls_peak_power"),
            "tls_present": int(bool(record.get("ja3"))),
            "tls_version": self._as_float(record, "tls_version"),
            "server_hello": 0,
            "ja3_hash_freq": 0.0,
            "ja3s_hash_freq": 0.0,
        }
        features = pd.DataFrame(
            [{name: data.get(name, 0.0) for name in self.tls_features}],
            columns=self.tls_features,
        )
        probability = float(self.tls_model.predict_proba(features)[0][1])
        if probability < self.tls_threshold:
            return None
        severity = "HIGH" if probability >= 0.9 else "MEDIUM" if probability >= 0.7 else "LOW"
        return self._dashboard_alert(
            record, "TLS Malware", probability, severity, record.get("src_ip", "?"),
            record.get("dst_ip", "?"), "TLS flow classification",
            {"malware_probability": round(probability, 4), "ja3": record.get("ja3"),
             "ja4": record.get("ja4"), "sni": record.get("sni")}, "tls_malware_model",
        )

    def _dashboard_alert(self, source, threat_class, confidence, severity, src_ip, dst_ip,
                         primary_metric, evidence, module):
        timestamp = self._timestamp(source.get("ts", source.get("ts_start", time.time())))
        return {
            "alert_id": f"ALT-{timestamp:%Y%m%d}-{uuid.uuid4().hex[:10]}",
            "timestamp": timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "severity": str(severity).upper(),
            "threat_class": threat_class,
            "confidence_score": min(1.0, max(0.0, float(confidence))),
            "flow_identifier": {
                "src_ip": str(src_ip), "dst_ip": str(dst_ip),
                "src_port": int(source.get("src_port", 0) or 0),
                "dst_port": int(source.get("dst_port", 0) or 0),
                "protocol": str(source.get("protocol", "?")),
            },
            "threat_intelligence": {"cache_hit": False, "ioc_matched": None,
                                     "ioc_category": None, "ti_override_applied": False},
            "supporting_evidence": {
                "primary_metric": str(primary_metric),
                "feature_attributions": evidence if isinstance(evidence, dict) else {"indicators": evidence},
            },
            "system_telemetry": {
                "processing_latency_ms": round(self.latencies[-1], 3) if self.latencies else 0.0,
                "path_taken": module, "enclave_mode": "PASSIVE_UNIDIRECTIONAL",
            },
        }

    def _write_alert(self, alert: dict) -> None:
        self.alerts_file.parent.mkdir(parents=True, exist_ok=True)
        with self.alerts_file.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(alert, separators=(",", ":"), default=str) + "\n")
        self.module_counts[alert["threat_class"]] = self.module_counts.get(alert["threat_class"], 0) + 1
        self.alert_count += 1

    def _advance_telemetry(self, event_time: float) -> None:
        second = int(event_time)
        if self._window_second is not None and second > self._window_second:
            self._write_telemetry()
            self._window_bytes = 0
            self._window_flow_bytes = 0
            self._has_window_volume = False
            self._window_flows = 0
        self._window_second = max(second, self._window_second or second)

    def _write_telemetry(self, throughput_gbps=None, flows_per_sec=None) -> None:
        self.telemetry_file.parent.mkdir(parents=True, exist_ok=True)
        telemetry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "throughput_gbps": round(
                throughput_gbps if throughput_gbps is not None else
                (self._window_bytes if self._has_window_volume else self._window_flow_bytes)
                * 8 / 1_000_000_000, 6
            ),
            "flows_per_sec": self._window_flows if flows_per_sec is None else flows_per_sec,
            "p95_latency_ms": round(float(pd.Series(self.latencies).quantile(0.95)), 3) if self.latencies else 0.0,
            "packet_drops": self._window_packet_drops,
            "cache": self.ti_engine.stats(),
            "module_counts": dict(self.module_counts),
            "modules": {"c2": "loaded", "ddos": "loaded", "exfiltration": "loaded",
                        "recon": "loaded", "tls": self.tls_status, "dga": "loaded",
                        "dns_tunnel": "loaded", "ti": "loaded"},
        }
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.telemetry_file.parent,
                prefix=f".{self.telemetry_file.name}.", suffix=".tmp", delete=False,
            ) as stream:
                json.dump(telemetry, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
                temp_path = Path(stream.name)
            for attempt in range(6):
                try:
                    os.replace(temp_path, self.telemetry_file)
                    break
                except PermissionError:
                    if attempt == 5:
                        raise
                    time.sleep(0.05 * (attempt + 1))
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def finish(self, parser_report=None) -> None:
        if parser_report is not None:
            self._write_telemetry(
                throughput_gbps=float(parser_report.get("mbps", 0.0)) / 1000,
                flows_per_sec=int(parser_report.get("flows_per_s", 0)),
            )
        elif self._window_flows or self._window_bytes or self._window_flow_bytes:
            self._write_telemetry()