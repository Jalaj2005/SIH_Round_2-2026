import json

from core.pipeline import DashboardPipeline
from core.schema import validate_alert


def test_pipeline_writes_dashboard_contract(tmp_path):
    alerts_file = tmp_path / "alerts.jsonl"
    telemetry_file = tmp_path / "telemetry.json"
    pipeline = DashboardPipeline(alerts_file, telemetry_file, load_tls_model=False)

    pipeline.process_record({
        "record_type": "window",
        "scope": "dst",
        "ts": 1_790_000_000.0,
        "window_s": 1,
        "ip": "198.51.100.20",
        "pkts": 4,
        "bytes": 1500,
        "pps": 4,
        "syn_pkts": 1,
        "udp_pkts": 0,
        "unique_src": 1,
        "src_entropy": 0,
    })
    pipeline.process_record({
        "record_type": "flow",
        "flow_id": "flow-1",
        "ts_start": 1_790_000_000.0,
        "duration": 2.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "198.51.100.20",
        "src_port": 45000,
        "dst_port": 443,
        "protocol": "TCP",
        "pkts_out": 3,
        "pkts_in": 1,
        "bytes_out": 1200,
        "bytes_in": 300,
        "bytes_total": 1500,
        "pps": 2.0,
        "bytes_per_sec": 750.0,
        "syn_cnt": 1,
        "splt_len": [400, 500, 300],
        "iat_seq": [0.5, 0.5],
        "ja3": None,
        "tls_version": 0,
    })
    alert = pipeline._dashboard_alert(
        {"ts_start": 1_790_000_000.0}, "Port Scan", 0.8, "HIGH",
        "10.0.0.5", "198.51.100.20", "vertical_scan", {"ports": 24}, "recon_detector",
    )
    pipeline._write_alert(alert)
    pipeline.finish()

    written = json.loads(alerts_file.read_text(encoding="utf-8").splitlines()[0])
    telemetry = json.loads(telemetry_file.read_text(encoding="utf-8"))
    assert validate_alert(written) is not None
    assert telemetry["flows_per_sec"] == 1
    assert telemetry["throughput_gbps"] == 0.000012
    assert telemetry["modules"]["recon"] == "loaded"


def test_half_duplex_flow_is_not_exfiltration_by_ratio_alone(tmp_path):
    pipeline = DashboardPipeline(
        tmp_path / "alerts.jsonl", tmp_path / "telemetry.json", load_tls_model=False
    )
    pipeline.process_record({
        "record_type": "flow",
        "flow_id": "one-way-flow",
        "ts_start": 1_790_000_000.0,
        "duration": 2.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "8.8.8.8",
        "src_port": 45000,
        "dst_port": 443,
        "protocol": "TCP",
        "pkts_out": 3,
        "pkts_in": 0,
        "bytes_out": 1200,
        "bytes_in": 0,
        "bytes_total": 1200,
        "pps": 1.5,
        "bytes_per_sec": 600.0,
        "syn_cnt": 1,
        "half_duplex": True,
    })

    assert pipeline.alert_count == 0


def test_tls_model_skips_flows_without_client_hello(tmp_path):
    class AlwaysMalicious:
        def predict_proba(self, features):
            raise AssertionError("TLS model must not run without ClientHello evidence")

    pipeline = DashboardPipeline(
        tmp_path / "alerts.jsonl", tmp_path / "telemetry.json", load_tls_model=False
    )
    pipeline.tls_model = AlwaysMalicious()

    assert pipeline._detect_tls({"record_type": "flow", "ja3": None}) is None


def test_telemetry_replace_retries_transient_windows_lock(tmp_path, monkeypatch):
    import os

    telemetry_file = tmp_path / "telemetry.json"
    pipeline = DashboardPipeline(
        tmp_path / "alerts.jsonl", telemetry_file, load_tls_model=False
    )
    pipeline._window_flows = 1
    replace = os.replace
    attempts = 0

    def fail_once(source, target):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise PermissionError("temporary file lock")
        replace(source, target)

    monkeypatch.setattr("core.pipeline.os.replace", fail_once)
    pipeline.finish()

    assert attempts == 2
    assert telemetry_file.exists()


def test_final_telemetry_uses_flow_bytes_without_volume_window(tmp_path):
    telemetry_file = tmp_path / "telemetry.json"
    pipeline = DashboardPipeline(
        tmp_path / "alerts.jsonl", telemetry_file, load_tls_model=False
    )
    pipeline._window_second = 1
    pipeline._window_flows = 4
    pipeline._window_flow_bytes = 50_000
    pipeline.finish()

    telemetry = json.loads(telemetry_file.read_text(encoding="utf-8"))
    assert telemetry["flows_per_sec"] == 4
    assert telemetry["throughput_gbps"] == 0.0004


def test_replay_report_populates_dashboard_rates(tmp_path):
    telemetry_file = tmp_path / "telemetry.json"
    pipeline = DashboardPipeline(
        tmp_path / "alerts.jsonl", telemetry_file, load_tls_model=False
    )
    pipeline.finish({"flows_per_s": 1847, "mbps": 9.3})

    telemetry = json.loads(telemetry_file.read_text(encoding="utf-8"))
    assert telemetry["flows_per_sec"] == 1847
    assert telemetry["throughput_gbps"] == 0.0093


def test_dns_records_reach_dga_and_threat_intel(tmp_path):
    alerts_file = tmp_path / "alerts.jsonl"
    pipeline = DashboardPipeline(
        alerts_file, tmp_path / "telemetry.json", load_tls_model=False, ioc_db=":memory:"
    )
    pipeline.process_record({
        "record_type": "dns",
        "ts": 1_790_000_000.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.2",
        "src_port": 53000,
        "dst_port": 53,
        "protocol": "UDP",
        "domain": "xkqzvtwpmrbnhd.com",
    })
    pipeline.process_record({
        "record_type": "dns",
        "ts": 1_790_000_001.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.2",
        "src_port": 53001,
        "dst_port": 53,
        "protocol": "UDP",
        "domain": "evil-c2.example",
    })

    alerts = [json.loads(line) for line in alerts_file.read_text(encoding="utf-8").splitlines()]
    classes = {alert["threat_class"] for alert in alerts}
    assert "DGA Domain" in classes
    assert "Known IoC (TI)" in classes


def test_tunnel_pattern_reaches_dashboard_alerts(tmp_path):
    alerts_file = tmp_path / "alerts.jsonl"
    pipeline = DashboardPipeline(
        alerts_file, tmp_path / "telemetry.json", load_tls_model=False, ioc_db=":memory:"
    )
    for index in range(12):
        label = f"{index:02x}" + "abcdef0123456789" * 3
        pipeline.process_record({
            "record_type": "dns",
            "ts": 1_790_000_000.0 + index * 0.1,
            "src_ip": "10.0.0.32",
            "dst_ip": "10.0.0.53",
            "src_port": 53000 + index,
            "dst_port": 53,
            "protocol": "UDP",
            "domain": f"{label}.t.evil-tunnel.com",
            "is_txt_null": True,
        })

    alerts = [json.loads(line) for line in alerts_file.read_text(encoding="utf-8").splitlines()]
    tunnel_alerts = [alert for alert in alerts if alert["threat_class"] == "DNS Tunnelling"]
    assert tunnel_alerts
    assert validate_alert(tunnel_alerts[0]) is not None


def test_popular_domains_reduce_tunnel_confidence():
    from sentinel_dns_tunnel import DNSTunnelConfig, DNSTunnelDetector

    detector = DNSTunnelDetector(DNSTunnelConfig(
        min_confidence=0.1, popular_source_threshold=2, cooldown_seconds=0,
    ))
    first_alert = None
    for index in range(10):
        first_alert = detector.process_dns({
            "domain": f"{index:02x}" + "abcdef0123456789" * 3 + ".t.popular.example",
            "src_ip": "10.0.0.1",
            "ts": 1000 + index * 0.1,
        }) or first_alert
    baseline_confidence = first_alert["confidence_score"]
    second_alert = None
    for index in range(10):
        second_alert = detector.process_dns({
            "domain": f"{index:02x}" + "0123456789abcdef" * 3 + ".t.popular.example",
            "src_ip": "10.0.0.2",
            "ts": 1000 + index * 0.1,
        }) or second_alert

    assert first_alert is not None
    assert second_alert is not None
    assert second_alert["confidence_score"] < baseline_confidence


def test_looped_pcap_source_advances_timestamps(tmp_path, monkeypatch):
    import run_pipeline

    class FakePcapSource:
        linktype = 1

        def __init__(self, path, speed):
            self.path, self.speed = path, speed

        def __iter__(self):
            yield 1000.0, b"first"
            yield 1000.5, b"second"

    monkeypatch.setattr(run_pipeline, "PcapFileSource", FakePcapSource)
    first_pass = run_pipeline.OffsetPcapSource(str(tmp_path / "demo.pcap"), speed=0)
    first_records = list(first_pass)
    second_pass = run_pipeline.OffsetPcapSource(
        str(tmp_path / "demo.pcap"), speed=0, offset=first_pass.next_offset
    )
    second_records = list(second_pass)

    assert first_records == [(1000.0, b"first"), (1000.5, b"second")]
    assert second_records[0][0] > first_records[-1][0]
