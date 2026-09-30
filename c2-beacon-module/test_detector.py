import random
from c2_beacon import BeaconDetector, Flow

def run(intervals, size=200, sizejit=0.05, dst="192.0.2.1", src="10.0.0.5"):
    d, t, out = BeaconDetector(), 1e9, []
    for iv in intervals:
        t += iv
        out += d.process_flow(Flow(t, src, dst, 443, "TCP", 40000,
                                   int(size * random.uniform(1 - sizejit, 1 + sizejit))))
    return out

def test_regular_beacon_detected():
    assert run([60] * 30)

def test_jittered_beacon_detected():
    random.seed(1)
    assert run([60 * random.uniform(0.8, 1.2) for _ in range(40)])

def test_poisson_browsing_not_flagged():
    random.seed(2)
    assert not run([random.expovariate(1 / 30) for _ in range(60)], sizejit=0.9)

def test_fast_bulk_traffic_ignored():
    assert not run([0.05] * 200)

def test_alert_schema():
    a = run([60] * 30)[0]
    for k in ("timestamp", "flow_id", "threat_class", "confidence", "severity", "evidence"):
        assert k in a.to_dict()
