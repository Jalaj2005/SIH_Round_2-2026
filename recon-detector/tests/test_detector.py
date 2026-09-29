from app.detector import ReconDetector
from app.schemas import Flow

SYN, SYNACK = 0x02, 0x12


def probe(ts, src, dst, dport, sport=40000, flags=SYN):
    return Flow(ts=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, tcp_flags=flags)


def run(det, flows):
    return [a for a in map(det.process, flows) if a]


def test_vertical_scan():
    d = ReconDetector()
    alerts = run(d, [probe(i * 0.02, "10.0.0.5", "192.168.1.10", 1 + i) for i in range(150)])
    assert alerts and alerts[0].sub_type == "vertical_scan"
    assert alerts[0].evidence["max_ports_single_dst"] >= 20
    assert alerts[0].confidence >= 0.5


def test_horizontal_scan():
    d = ReconDetector()
    alerts = run(d, [probe(i * 0.02, "10.0.0.6", f"192.168.{i // 250}.{i % 250 + 1}", 445) for i in range(200)])
    assert alerts and alerts[0].sub_type == "horizontal_scan"


def test_normal_client_not_flagged():
    d = ReconDetector()
    flows = []
    for i in range(10):
        flows.append(probe(i * 0.1, "10.0.0.7", "8.8.8.8", 443, sport=50000 + i))
        flows.append(Flow(ts=i * 0.1 + 0.01, src_ip="8.8.8.8", dst_ip="10.0.0.7",
                          src_port=443, dst_port=50000 + i, tcp_flags=SYNACK))
    assert run(d, flows) == []


def test_busy_server_replies_not_flagged():
    d = ReconDetector()
    flows = [Flow(ts=i * 0.01, src_ip="192.168.1.10", dst_ip=f"10.9.{i // 200}.{i % 200}",
                  src_port=80, dst_port=50000 + i, tcp_flags=SYNACK) for i in range(300)]
    assert run(d, flows) == []


def test_answered_fanout_has_lower_confidence_than_unanswered():
    def scan(answer):
        d = ReconDetector()
        out = []
        for i in range(60):
            out.append(probe(i * 0.02, "10.0.0.8", "192.168.1.10", 1000 + i, sport=41000))
            if answer:
                out.append(Flow(ts=i * 0.02 + 0.005, src_ip="192.168.1.10", dst_ip="10.0.0.8",
                                src_port=1000 + i, dst_port=41000, tcp_flags=SYNACK))
        a = run(d, out)
        return a[0].confidence if a else 0.0
    assert scan(False) > scan(True)


def test_window_expiry_and_cooldown():
    d = ReconDetector()
    a1 = run(d, [probe(i * 0.02, "10.0.0.9", "192.168.1.10", 1 + i) for i in range(100)])
    assert len(a1) == 1
    assert d.process(probe(60, "10.0.0.9", "192.168.1.10", 22)) is None
    assert d.source_snapshot("10.0.0.9")["connection_attempts"] == 1
