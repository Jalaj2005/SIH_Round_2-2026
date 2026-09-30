"""Throughput benchmark: synthetic pcap (many flows) -> Module 1 core, optionally with consumers.

python -m sentinel_m1.bench --flows 50000 --pkts 10 [--consumers 4]
"""
import argparse, json, os, random, struct, sys, tempfile, time, multiprocessing as mp

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import traffic  # noqa: E402
from .capture import PcapFileSource  # noqa: E402
from .config import Config  # noqa: E402
from .dispatch import Dispatcher, iter_records  # noqa: E402
from .pipeline import Module1  # noqa: E402


def make_pcap(path, flows, pkts, size=600):
    rnd, t = random.Random(1), 0.0
    tmpl_c = traffic.tcp("10.0.0.1", "10.1.0.1", 1000, 443, 0x18, b"x" * size)
    ip_off, l4_off = 14, 34
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(flows):
            src = struct.pack("!I", 0x0A000000 + (i % 65000) + 1)
            dst = struct.pack("!I", 0x0A010000 + (i * 7 % 250) + 1)
            sport = 1024 + (i % 60000)
            for k in range(pkts):
                fr = bytearray(tmpl_c)
                fr[ip_off + 12:ip_off + 16], fr[ip_off + 16:ip_off + 20] = src, dst
                fr[l4_off:l4_off + 2] = struct.pack("!H", sport)
                t += 0.00002
                f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)))
                f.write(fr)


def sink(q, name, out):
    n = 0
    for _ in iter_records(q):
        n += 1
    out.put((name, n))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", type=int, default=50000)
    ap.add_argument("--pkts", type=int, default=10)
    ap.add_argument("--consumers", type=int, default=0)
    a = ap.parse_args()
    path = tempfile.mktemp(suffix=".pcap")
    make_pcap(path, a.flows, a.pkts)
    disp, procs, outq = None, [], mp.Queue()
    if a.consumers:
        disp = Dispatcher(use_processes=True)
        names = ["ddos", "c2", "dga", "dns_tunnel", "tls", "portscan", "exfil", "ti"][:a.consumers]
        for n in names:
            q = disp.subscribe(n)
            p = mp.Process(target=sink, args=(q, n, outq), daemon=True)
            p.start(); procs.append(p)
    m1 = Module1(Config(), dispatcher=disp)
    rep = m1.run(PcapFileSource(path))
    if procs:
        for p in procs: p.join(10)
        rep["consumer_received"] = dict(outq.get() for _ in procs)
    print(json.dumps(rep, indent=1))
    os.unlink(path)


main()
