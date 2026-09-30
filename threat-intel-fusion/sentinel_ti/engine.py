"""Threat-intel lookup engine with a two-tier cache:
   positive cache (known-bad, long TTL)  |  negative cache (not in DB, short TTL)  |  disk IoC store."""
from __future__ import annotations
import ipaddress
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache

from sentinel_ti.ioc_store import IoCStore


class TTLLRU:
    """Bounded LRU whose entries also expire after `ttl` seconds."""

    def __init__(self, maxsize: int, ttl: float, clock=time.monotonic):
        self.maxsize, self.ttl, self.clock = maxsize, ttl, clock
        self._d: OrderedDict = OrderedDict()

    def get(self, key):
        item = self._d.get(key)
        if item is None:
            return False, None
        expires, val = item
        if expires < self.clock():
            del self._d[key]
            return False, None
        self._d.move_to_end(key)
        return True, val

    def put(self, key, val) -> None:
        self._d[key] = (self.clock() + self.ttl, val)
        self._d.move_to_end(key)
        while len(self._d) > self.maxsize:
            self._d.popitem(last=False)

    def clear(self) -> None:
        self._d.clear()

    def __len__(self) -> int:
        return len(self._d)


@dataclass
class TIVerdict:
    matches: list = field(default_factory=list)   # [{kind, value, category, confidence, source}]
    cache_hit: bool = True                        # True if no lookup had to touch the disk DB
    early_exit: bool = False                      # confirmed IoC -> skip ML, alert immediately
    confidence: float = 0.0
    lookups: int = 0
    latency_us: float = 0.0

    @property
    def matched(self) -> bool:
        return bool(self.matches)


_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4",
    "0.0.0.0/8", "fc00::/7", "::1/128", "fe80::/10", "ff00::/8")]


@lru_cache(maxsize=65536)
def _is_private(ip: str) -> bool:
    """True for internal/multicast addresses that can never be a threat-intel IoC."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparsable -> don't waste a lookup
    return any(addr.version == n.version and addr in n for n in _INTERNAL)


def domain_candidates(domain: str, limit: int = 4) -> list[str]:
    """a.b.evil.com -> [a.b.evil.com, b.evil.com, evil.com] (never the bare TLD)."""
    labels = domain.lower().rstrip(".").split(".")
    return [".".join(labels[i:]) for i in range(max(1, len(labels) - 1))][:limit]


class TIEngine:
    def __init__(self, store: IoCStore, pos_ttl: float = 3600, neg_ttl: float = 300, maxsize: int = 200_000,
                 early_exit_conf: float = 0.9, clock=time.monotonic):
        self.store, self.early_exit_conf = store, early_exit_conf
        self.pos, self.neg = TTLLRU(maxsize, pos_ttl, clock), TTLLRU(maxsize, neg_ttl, clock)
        self._lock = threading.Lock()
        self.hits = self.misses = self.negative_hits = 0

    # ---- single indicator ---------------------------------------------------
    def lookup(self, kind: str, value: str) -> tuple[dict | None, bool]:
        """-> (ioc row or None, served_from_cache)"""
        key = (kind, value.lower())
        with self._lock:
            found, val = self.pos.get(key)
            if found:
                self.hits += 1
                return val, True
            found, _ = self.neg.get(key)
            if found:
                self.negative_hits += 1
                return None, True
            self.misses += 1
        ioc = self.store.get(*key)                       # disk access outside the cache lock
        with self._lock:
            (self.pos if ioc else self.neg).put(key, ioc if ioc else True)
        return ioc, False

    # ---- Module 1 records ---------------------------------------------------
    @staticmethod
    def indicators(rec: dict) -> list[tuple[str, str]]:
        t, out = rec.get("record_type"), []
        if t == "dns" and rec.get("domain"):
            out += [("domain", d) for d in domain_candidates(rec["domain"])]
        elif t in ("tls_hello", "flow_early", "flow"):
            out += [(k, rec[k]) for k in ("ja3", "ja4") if rec.get(k)]
            if rec.get("sni"):
                out += [("domain", d) for d in domain_candidates(rec["sni"])]
            out += [("ip", rec[k]) for k in ("dst_ip", "src_ip") if rec.get(k) and not _is_private(rec[k])]
        return out

    def check_record(self, rec: dict) -> TIVerdict:
        t0 = time.perf_counter()
        v = TIVerdict()
        for kind, value in self.indicators(rec):
            ioc, cached = self.lookup(kind, value)
            v.lookups += 1
            v.cache_hit &= cached
            if ioc:
                v.matches.append(ioc)
        if v.matches:
            v.confidence = max(m["confidence"] for m in v.matches)
            kinds = {m["kind"] for m in v.matches}
            v.early_exit = v.confidence >= self.early_exit_conf or len(kinds) >= 2
        v.latency_us = (time.perf_counter() - t0) * 1e6
        return v

    # ---- housekeeping ---------------------------------------------------------
    def flush(self) -> None:
        """Call after every IoC import so stale 'clean' entries can't hide new threats."""
        with self._lock:
            self.pos.clear()
            self.neg.clear()

    def stats(self) -> dict:
        """Shape the dashboard's telemetry.json expects under the `cache` key."""
        return {"hits": self.hits, "misses": self.misses, "negative_hits": self.negative_hits}
