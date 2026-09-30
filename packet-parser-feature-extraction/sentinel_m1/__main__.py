import argparse
import json

from .capture import LiveSource, PcapFileSource
from .config import Config
from .pipeline import Module1


def main():
    ap = argparse.ArgumentParser(prog="sentinel_m1", description="SIH-26145 Module 1 (passive, read-only)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--pcap")
    g.add_argument("--iface")
    ap.add_argument("--jsonl", help="write every feature record here (dev / debugging)")
    ap.add_argument("--speed", type=float, default=0.0, help="pcap replay speed, 0 = max")
    ap.add_argument("--idle-timeout", type=float, default=15.0)
    ap.add_argument("--window", type=float, default=1.0)
    a = ap.parse_args()
    cfg = Config(idle_timeout=a.idle_timeout, window_s=a.window)
    m1 = Module1(cfg, jsonl_path=a.jsonl)
    if a.pcap:
        rep = m1.run(PcapFileSource(a.pcap, a.speed))
    else:
        with LiveSource(a.iface) as src:
            try:
                rep = m1.run(src)
            except KeyboardInterrupt:
                m1.finish()
                rep = m1.report()
    print(json.dumps(rep, indent=2))


main()
