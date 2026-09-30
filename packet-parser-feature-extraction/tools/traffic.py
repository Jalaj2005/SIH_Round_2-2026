"""Synthetic traffic builder (raw struct, fast) - used by tests and the benchmark."""
import random
import socket
import struct

ETH = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"


def ip4(s):
    return socket.inet_aton(s)


def _ip_hdr(src, dst, proto, l4len):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + l4len, 0, 0, 64, proto, 0, ip4(src), ip4(dst))


def tcp(src, dst, sport, dport, flags=0x10, payload=b""):
    seg = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    return ETH + _ip_hdr(src, dst, 6, len(seg)) + seg


def udp(src, dst, sport, dport, payload=b""):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ETH + _ip_hdr(src, dst, 17, len(seg)) + seg


def dns_query(name, qtype=1, txid=0x1234):
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def client_hello(ciphers, exts_spec, sni=None):
    """exts_spec: list of (type, bytes). Builds a TLS 1.2-style ClientHello record."""
    body = struct.pack("!H", 0x0301) + b"\x00" * 32 + b"\x00"
    body += struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    body += b"\x01\x00"
    ext = b""
    for t, d in exts_spec:
        ext += struct.pack("!HH", t, len(d)) + d
    body += struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def sni_ext(name):
    n = name.encode()
    return (0, struct.pack("!HBH", len(n) + 3, 0, len(n)) + n)


def write_pcap(path, packets):
    """packets: iterable of (ts, frame bytes)."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, fr in packets:
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(fr), len(fr)))
            f.write(fr)


def tcp_session(t0, src, dst, sport, dport, n_data=4, size=200, gap=0.02, payload=None):
    pk = [(t0, tcp(src, dst, sport, dport, 0x02)), (t0 + 0.001, tcp(dst, src, dport, sport, 0x12)),
          (t0 + 0.002, tcp(src, dst, sport, dport, 0x10))]
    t = t0 + 0.003
    for i in range(n_data):
        pl = payload if (payload and i == 0) else b"x" * size
        pk.append((t, tcp(src, dst, sport, dport, 0x18, pl)))
        pk.append((t + 0.001, tcp(dst, src, dport, sport, 0x10)))
        t += gap
    pk += [(t, tcp(src, dst, sport, dport, 0x11)), (t + 0.001, tcp(dst, src, dport, sport, 0x11)),
           (t + 0.002, tcp(src, dst, sport, dport, 0x10))]
    return pk


def scenario_mix(seed=7):
    rnd = random.Random(seed)
    pk = []
    # 1) C2 beacon: 60 connections / 30 s with +-40 % jitter
    t = 1000.0
    for i in range(60):
        pk += tcp_session(t, "10.0.4.15", "198.51.100.89", 40000 + i, 443, n_data=2, size=120)
        t += 30 * (1 + rnd.uniform(-0.4, 0.4))
    # 2) benign web browsing: same host, random (Poisson) timing
    t = 1000.0
    for i in range(60):
        pk += tcp_session(t, "10.0.4.20", "93.184.216.34", 41000 + i, 443, n_data=3)
        t += rnd.expovariate(1 / 30)
    # 3) DNS: benign, DGA-like, tunnelling (TXT + long labels)
    d = 1010.0
    for nm in ["www.google.com", "mail.example.org", "github.com"]:
        pk.append((d, udp("10.0.4.30", "10.0.0.53", 5353 + int(d) % 100, 53, dns_query(nm)))); d += 0.1
    for nm in ["xkqvjzpwhtrb.com", "qwzxvbnmlkjh.net", "pzqtkxjwvfdl.biz"]:
        pk.append((d, udp("10.0.4.31", "10.0.0.53", 6000, 53, dns_query(nm)))); d += 0.1
    for i in range(30):
        lab = "".join(rnd.choice("abcdef0123456789") for _ in range(56))
        pk.append((1012 + i * 0.03, udp("10.0.4.32", "10.0.0.53", 7000 + i, 53,
                                         dns_query(lab + ".t.evil-tunnel.com", qtype=16))))
    # 4) TLS ClientHello - the classic JA3 reference example
    ja3_ciphers = [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4]
    ch = client_hello(ja3_ciphers, [
        (0, b"\x00\x00\x00"[:0] + struct.pack("!HBH", 14, 0, 11) + b"example.com"),
        (10, struct.pack("!HHHH", 6, 23, 24, 25)), (11, b"\x01\x00")])
    pk += tcp_session(1020.0, "10.0.4.40", "203.0.113.7", 50000, 443, payload=ch)
    # 5) SYN flood: 3000 spoofed sources -> one victim inside 1 s
    for i in range(3000):
        s = "172.%d.%d.%d" % (16 + rnd.randrange(16), rnd.randrange(256), rnd.randrange(1, 255))
        pk.append((1030 + i / 3000.0, tcp(s, "10.0.0.80", rnd.randrange(1024, 65535), 80, 0x02)))
    # 6) vertical port scan: one source, 600 ports
    for i in range(600):
        pk.append((1040 + i / 1000.0, tcp("10.0.4.99", "10.0.0.10", 55555, 1 + i, 0x02)))
    # 7) exfil: 2 MB out, ~nothing back
    for i in range(1400):
        pk.append((1050 + i * 0.001, tcp("10.0.4.50", "203.0.113.99", 52000, 443, 0x18, b"z" * 1400)))
    pk.sort(key=lambda x: x[0])
    return pk
