"""Fast-path header parser (struct-based; dpkt is only used to read pcaps)."""
import struct

TCP, UDP, ICMP = 6, 17, 1
SYN, FIN, RST, PSH, ACK = 0x02, 0x01, 0x04, 0x08, 0x10


class DnsInfo:
    __slots__ = ("name", "qtype", "is_response", "rcode")


class Packet:
    """IPs are raw bytes (4 or 16) in the hot path; text conversion happens on emit."""
    __slots__ = ("ts", "src", "dst", "sport", "dport", "proto", "ip_len",
                 "payload_len", "flags", "payload", "dns")


def parse_packet(ts, buf, linktype=1):
    try:
        return _parse(ts, buf, linktype)
    except (struct.error, IndexError):
        return None


def _parse_dns(buf, o, plen):
    if plen < 17:
        return None
    flags = (buf[o + 2] << 8) | buf[o + 3]
    if ((buf[o + 4] << 8) | buf[o + 5]) < 1:
        return None
    i, end, labels = o + 12, o + plen, []
    while i < end:
        ln = buf[i]
        if ln == 0:
            break
        if ln & 0xC0 or i + 1 + ln > end:
            return None
        labels.append(bytes(buf[i + 1:i + 1 + ln]))
        i += 1 + ln
    else:
        return None
    if i + 3 > end:
        return None
    d = DnsInfo()
    d.name = b".".join(labels).decode("ascii", "replace").lower()
    d.qtype = (buf[i + 1] << 8) | buf[i + 2]
    d.is_response, d.rcode = bool(flags & 0x8000), flags & 0xF
    return d


def _parse(ts, buf, linktype):
    n = len(buf)
    if linktype == 1:
        et, off = (buf[12] << 8) | buf[13], 14
        while et in (0x8100, 0x88A8) and n >= off + 4:
            et, off = (buf[off + 2] << 8) | buf[off + 3], off + 4
    elif linktype in (101, 12, 14):
        et, off = {4: 0x0800, 6: 0x86DD}.get(buf[0] >> 4, 0), 0
    elif linktype == 113:
        et, off = (buf[14] << 8) | buf[15], 16
    elif linktype == 0:
        et, off = (0x0800 if buf[0] == 2 else 0x86DD), 4
    else:
        return None

    p = Packet()
    p.ts, p.flags, p.payload, p.dns = ts, 0, b"", None
    if et == 0x0800:
        ihl = (buf[off] & 15) << 2
        tot = (buf[off + 2] << 8) | buf[off + 3] or (n - off)
        frag = ((buf[off + 6] & 0x1F) << 8) | buf[off + 7]
        proto = buf[off + 9]
        p.src, p.dst = bytes(buf[off + 12:off + 16]), bytes(buf[off + 16:off + 20])
        l4, l4len = off + ihl, tot - ihl
    elif et == 0x86DD:
        plen = (buf[off + 4] << 8) | buf[off + 5]
        proto, tot = buf[off + 6], 40 + plen
        p.src, p.dst = bytes(buf[off + 8:off + 24]), bytes(buf[off + 24:off + 40])
        l4, l4len, frag = off + 40, plen, 0
        while proto in (0, 43, 60) and l4len > 8:            # skip simple extension headers
            hl = (buf[l4 + 1] + 1) << 3
            proto, l4, l4len = buf[l4], l4 + hl, l4len - hl
        if proto == 44:
            frag = 1
    else:
        return None

    p.proto, p.ip_len, p.sport, p.dport, p.payload_len = proto, tot, 0, 0, 0
    if frag == 0:
        if proto == TCP and l4len >= 20:
            p.sport, p.dport = struct.unpack_from("!HH", buf, l4)
            doff = (buf[l4 + 12] >> 4) << 2
            p.flags = buf[l4 + 13]
            p.payload_len = max(l4len - doff, 0)
            if p.payload_len:
                p.payload = bytes(buf[l4 + doff:l4 + l4len])
        elif proto == UDP and l4len >= 8:
            p.sport, p.dport = struct.unpack_from("!HH", buf, l4)
            p.payload_len = max(l4len - 8, 0)
            if p.sport in (53, 5353) or p.dport in (53, 5353):
                p.dns = _parse_dns(buf, l4 + 8, p.payload_len)
    return p
