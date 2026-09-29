"""Replay demo traffic into a running service: benign + vertical + horizontal scans."""
import random
import sys
import time

import httpx

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
now = time.time()
flows = []
for i in range(200):                                   # benign browsing
    flows.append(dict(ts=now + i * .05, src_ip="10.0.0.20", dst_ip=f"93.184.216.{i % 4}",
                      src_port=50000 + i, dst_port=443, tcp_flags=0x12))
for i in range(150):                                   # nmap-style vertical scan
    flows.append(dict(ts=now + i * .02, src_ip="203.0.113.7", dst_ip="192.168.1.10",
                      src_port=44444, dst_port=random.randint(1, 65535), tcp_flags=0x02))
for i in range(200):                                   # horizontal sweep on 445
    flows.append(dict(ts=now + i * .02, src_ip="203.0.113.9", dst_ip=f"192.168.{i // 250}.{i % 250 + 1}",
                      src_port=44445, dst_port=445, tcp_flags=0x02))
flows.sort(key=lambda f: f["ts"])
r = httpx.post(f"{URL}/ingest/batch", json=flows, timeout=30).json()
print("processed:", r["processed"])
for a in r["alerts"]:
    print(a["severity"], a["sub_type"], a["src_ip"], a["confidence"], a["evidence"]["unique_ports_scanned"])
