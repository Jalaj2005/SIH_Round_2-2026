"""Optional Redis Streams consumer: the team's ingest layer XADDs parsed flows
to stream `flows` as {"data": "<flow json>"}. Read-only from our side."""
import json
import logging
import threading

from .config import settings
from .schemas import Flow

log = logging.getLogger("consumer")


class RedisFlowConsumer(threading.Thread):
    def __init__(self, detector, sink):
        super().__init__(daemon=True)
        self.detector, self.sink = detector, sink
        self._halt = threading.Event()

    def run(self):
        import redis
        r = redis.Redis.from_url(settings.redis_url)
        last_id = "$"                                # only new flows
        while not self._halt.is_set():
            try:
                resp = r.xread({settings.redis_flow_stream: last_id}, count=1000, block=1000)
                for _, entries in resp or []:
                    for entry_id, fields in entries:
                        last_id = entry_id
                        try:
                            raw = fields.get(b"data") or json.dumps({k.decode(): v.decode() for k, v in fields.items()})
                            alert = self.detector.process(Flow.model_validate_json(raw))
                            if alert:
                                self.sink.emit(alert)
                        except Exception as e:
                            log.warning("bad flow skipped: %s", e)
            except Exception as e:
                log.error("redis read error: %s", e)
                self._halt.wait(2)

    def stop(self):
        self._halt.set()
