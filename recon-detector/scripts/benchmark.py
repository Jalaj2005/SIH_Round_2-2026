"""In-process throughput test (no HTTP overhead): python -m scripts.benchmark"""
import random
import time

from app.detector import ReconDetector
from app.schemas import Flow

N = 300_000
det = ReconDetector()
flows = []
for i in range(N):
    t = i / 50_000                                     # simulate 50k flows/s of event time
    if i % 20 == 0:                                    # 5% scanner traffic
        flows.append(Flow(ts=t, src_ip=f"203.0.113.{i % 50}", dst_ip="192.168.1.10",
                          src_port=44000, dst_port=random.randint(1, 65535), tcp_flags=2))
    else:
        c = random.randint(0, 5000)                    # each benign client talks to ONE server
        flows.append(Flow(ts=t, src_ip=f"10.0.{c // 250}.{c % 250 + 1}",
                          dst_ip=f"172.16.0.{c % 50 + 1}", src_port=random.randint(1024, 65000),
                          dst_port=random.choice([80, 443]), tcp_flags=2))
s = time.perf_counter()
alerts = sum(1 for f in flows if det.process(f))
e = time.perf_counter() - s
print(f"{N} flows in {e:.2f}s -> {N / e:,.0f} flows/s, alerts={alerts}, stats={det.stats()}")
