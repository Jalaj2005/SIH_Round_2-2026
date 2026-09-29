"""Egress: in-memory ring buffer (for REST/SSE), optional Redis stream + dashboard webhook."""
import json
import logging
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import httpx

from .config import settings
from .schemas import Alert

log = logging.getLogger("sink")


class AlertSink:
    def __init__(self):
        self.buffer: deque = deque(maxlen=2000)
        self.seq = 0
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=1)   # never block the hot path
        self._redis = None
        if settings.redis_url:
            import redis
            self._redis = redis.Redis.from_url(settings.redis_url)

    def emit(self, alert: Alert):
        payload = alert.model_dump()
        with self._lock:
            self.seq += 1
            self.buffer.append((self.seq, payload))
        if self._redis or settings.dashboard_webhook:
            self._pool.submit(self._forward, payload)

    def _forward(self, payload: dict):
        try:
            if self._redis:
                self._redis.xadd(settings.redis_alert_stream, {"data": json.dumps(payload)}, maxlen=10000)
            if settings.dashboard_webhook:
                httpx.post(settings.dashboard_webhook, json=payload, timeout=2)
        except Exception as e:                      # egress failure must never kill detection
            log.warning("alert forward failed: %s", e)

    def recent(self, limit=100):
        with self._lock:
            return [a for _, a in list(self.buffer)[-limit:]][::-1]

    def since(self, seq: int):
        with self._lock:
            return [(s, a) for s, a in self.buffer if s > seq]
