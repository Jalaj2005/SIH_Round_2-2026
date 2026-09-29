"""Per-source sliding-window state. Everything is O(1) amortised per flow."""
from collections import Counter, deque


class Ev:
    __slots__ = ("ts", "dst", "dport", "answered")

    def __init__(self, ts, dst, dport):
        self.ts, self.dst, self.dport, self.answered = ts, dst, dport, False


class SourceState:
    __slots__ = ("events", "dst_counts", "port_counts", "dst_ports",
                 "answered", "_max_ports", "_dirty", "last_flow_id")

    def __init__(self):
        self.events = deque()
        self.dst_counts = Counter()          # dst ip -> flows
        self.port_counts = Counter()         # dst port -> flows
        self.dst_ports = {}                  # dst ip -> Counter(port)
        self.answered = 0
        self._max_ports = 0
        self._dirty = False
        self.last_flow_id = ""

    def add(self, ev: Ev):
        self.events.append(ev)
        self.dst_counts[ev.dst] += 1
        self.port_counts[ev.dport] += 1
        c = self.dst_ports.setdefault(ev.dst, Counter())
        c[ev.dport] += 1
        if len(c) > self._max_ports:
            self._max_ports = len(c)

    def evict(self, cutoff: float, on_evict=None):
        ev_q = self.events
        while ev_q and ev_q[0].ts < cutoff:
            ev = ev_q.popleft()
            if on_evict:
                on_evict(ev)
            if ev.answered:
                self.answered -= 1
            self.dst_counts[ev.dst] -= 1
            if self.dst_counts[ev.dst] <= 0:
                del self.dst_counts[ev.dst]
            self.port_counts[ev.dport] -= 1
            if self.port_counts[ev.dport] <= 0:
                del self.port_counts[ev.dport]
            c = self.dst_ports[ev.dst]
            c[ev.dport] -= 1
            if c[ev.dport] <= 0:
                del c[ev.dport]
            if not c:
                del self.dst_ports[ev.dst]
            self._dirty = True

    def max_ports_single_dst(self) -> int:
        if self._dirty:
            self._max_ports = max((len(c) for c in self.dst_ports.values()), default=0)
            self._dirty = False
        return self._max_ports

    def metrics(self) -> dict:
        attempts = len(self.events)
        failed = attempts - self.answered
        return {
            "unique_dst_ips": len(self.dst_counts),
            "unique_ports_scanned": len(self.port_counts),
            "max_ports_single_dst": self.max_ports_single_dst(),
            "connection_attempts": attempts,
            "failed_connections": failed,
            "failed_ratio": round(failed / attempts, 3) if attempts else 0.0,
        }
