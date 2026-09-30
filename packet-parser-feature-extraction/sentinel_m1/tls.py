"""ClientHello metadata: JA3, JA4, SNI, ALPN. No decryption, handshake bytes only."""
import hashlib

GREASE = frozenset(0x0A0A + 0x1010 * i for i in range(16))
NEED_MORE = object()


class TlsInfo:
    __slots__ = ("version", "cipher_count", "ext_count", "sni", "alpn", "ja3", "ja3_str", "ja4", "max_version")


def _u16(p, i):
    return (p[i] << 8) | p[i + 1]


def parse_client_hello(p):
    """Return TlsInfo, NEED_MORE (segment incomplete) or None (not a ClientHello)."""
    if len(p) < 6 or p[0] != 0x16 or p[1] != 3 or p[5] != 1:
        return None
    if len(p) < 9:
        return NEED_MORE
    hs_len = (p[6] << 16) | (p[7] << 8) | p[8]
    if hs_len > 16384:
        return None
    if len(p) < 9 + hs_len:
        return NEED_MORE
    try:
        pos = 9
        client_ver = _u16(p, pos)
        pos += 2 + 32
        pos += 1 + p[pos]                                   # session id
        cs_len = _u16(p, pos)
        pos += 2
        ciphers = [_u16(p, i) for i in range(pos, pos + cs_len - 1, 2)]
        pos += cs_len
        pos += 1 + p[pos]                                   # compression
        end = min(pos + 2 + _u16(p, pos), len(p))
        pos += 2
        exts, curves, pf, sigalgs, versions = [], [], [], [], []
        sni = alpn = None
        while pos + 4 <= end:
            et, el = _u16(p, pos), _u16(p, pos + 2)
            d = p[pos + 4: pos + 4 + el]
            pos += 4 + el
            exts.append(et)
            if et == 0 and len(d) >= 5:
                sni = d[5:5 + _u16(d, 3)].decode("ascii", "ignore").lower()
            elif et == 10 and len(d) >= 2:
                curves = [_u16(d, i) for i in range(2, min(len(d) - 1, 2 + _u16(d, 0)), 2)]
            elif et == 11 and d:
                pf = list(d[1:1 + d[0]])
            elif et == 13 and len(d) >= 2:
                sigalgs = [_u16(d, i) for i in range(2, min(len(d) - 1, 2 + _u16(d, 0)), 2)]
            elif et == 16 and len(d) >= 3 and d[2]:
                alpn = d[3:3 + d[2]].decode("ascii", "ignore")
            elif et == 43 and d:
                versions = [_u16(d, i) for i in range(1, min(len(d) - 1, 1 + d[0]), 2)]
    except IndexError:
        return None

    c = [x for x in ciphers if x not in GREASE]
    e = [x for x in exts if x not in GREASE]
    cv = [x for x in curves if x not in GREASE]
    ja3_str = "%d,%s,%s,%s,%s" % (client_ver, "-".join(map(str, c)), "-".join(map(str, e)),
                                  "-".join(map(str, cv)), "-".join(map(str, pf)))
    t = TlsInfo()
    t.version, t.cipher_count, t.ext_count = client_ver, len(c), len(e)
    t.sni, t.alpn = sni, alpn
    t.ja3_str, t.ja3 = ja3_str, hashlib.md5(ja3_str.encode()).hexdigest()
    vs = [v for v in versions if v not in GREASE]
    t.max_version = max(vs) if vs else client_ver
    t.ja4 = _ja4(t.max_version, sni, alpn, c, e, sigalgs)
    return t


_VER = {0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3"}


def _ja4(ver, sni, alpn, ciphers, exts, sigalgs):
    """JA4 (TCP): t<ver><d|i><ncipher><next><alpn>_<sha256(sorted ciphers)[:12]>_<sha256(sorted exts_sigalgs)[:12]>"""
    a = "t%s%s%02d%02d%s" % (_VER.get(ver, "00"), "d" if sni else "i", min(len(ciphers), 99),
                             min(len(exts), 99), (alpn[0] + alpn[-1]) if alpn else "00")
    b = hashlib.sha256(",".join("%04x" % x for x in sorted(ciphers)).encode()).hexdigest()[:12]
    ce = ",".join("%04x" % x for x in sorted(exts) if x not in (0, 16))
    if sigalgs:
        ce += "_" + ",".join("%04x" % x for x in sigalgs)
    c = hashlib.sha256(ce.encode()).hexdigest()[:12]
    return "%s_%s_%s" % (a, b, c)
