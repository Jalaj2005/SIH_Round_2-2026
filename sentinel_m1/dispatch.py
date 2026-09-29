"""Fan-out of feature records to the parallel detection modules.

Records are batched per subscriber (bounded latency via tick()) and pushed with
put_nowait: the capture path NEVER blocks on a slow consumer - it counts drops instead,
which matches the passive-sensor rule that the tap can't push back on the network.
"""
import multiprocessing as mp
import queue as _q
import time

# who needs what (blueprint section 3 table). Use route="all" to send everything to everyone.
ROUTES = {
    "ddos":       {"window", "flow"},
    "c2":         {"flow"},
    "dga":        {"dns"},
    "dns_tunnel": {"dns", "window"},
    "tls":        {"tls_hello", "flow_early", "flow"},
    "portscan":   {"window", "flow"},
    "exfil":      {"flow"},
    "ti":         {"flow", "dns", "tls_hello"},
}


class Subscription:
    def __init__(self, name, types, q):
        self.name, self.types, self.q = name, types, q
        self.buf, self.sent, self.dropped, self.last = [], 0, 0, time.monotonic()


class Dispatcher:
    def __init__(self, use_processes=True, queue_batches=2000, batch_size=256, flush_s=0.05):
        self.use_processes, self.queue_batches = use_processes, queue_batches
        self.batch_size, self.flush_s = batch_size, flush_s
        self.subs = {}

    def subscribe(self, name, types=None, route="table"):
        """Returns the queue the consumer reads batches (list[dict]) from; None ends the stream."""
        if types is None and route == "table":
            types = ROUTES.get(name)
        q = mp.Queue(self.queue_batches) if self.use_processes else _q.Queue(self.queue_batches)
        self.subs[name] = Subscription(name, set(types) if types else None, q)
        return q

    def publish(self, rec):
        t = rec["record_type"]
        for s in self.subs.values():
            if s.types is None or t in s.types:
                s.buf.append(rec)
                if len(s.buf) >= self.batch_size:
                    self._flush(s)

    def _flush(self, s):
        if not s.buf:
            return
        try:
            s.q.put_nowait(s.buf)
            s.sent += len(s.buf)
        except _q.Full:
            s.dropped += len(s.buf)
        s.buf, s.last = [], time.monotonic()

    def tick(self):
        now = time.monotonic()
        for s in self.subs.values():
            if s.buf and now - s.last >= self.flush_s:
                self._flush(s)

    def close(self):
        for s in self.subs.values():
            self._flush(s)
            try:
                s.q.put(None, timeout=2)
            except _q.Full:
                pass

    def stats(self):
        return {n: {"sent": s.sent, "dropped": s.dropped} for n, s in self.subs.items()}


def iter_records(q):
    """Consumer helper: yields individual records until the stream is closed."""
    while True:
        batch = q.get()
        if batch is None:
            return
        yield from batch
