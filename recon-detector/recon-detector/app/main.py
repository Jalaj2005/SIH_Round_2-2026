import asyncio
import json
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .config import settings
from .consumer import RedisFlowConsumer
from .detector import ReconDetector
from .schemas import Alert, Flow
from .sink import AlertSink

detector = ReconDetector()
sink = AlertSink()


@asynccontextmanager
async def lifespan(app: FastAPI):
    consumer = None
    if settings.redis_url:
        consumer = RedisFlowConsumer(detector, sink)
        consumer.start()
    yield
    if consumer:
        consumer.stop()


app = FastAPI(title="Module 6 - Recon / Port-Scan Detector", version="1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {"status": "ok", "module": "module6-recon-detector", "redis": bool(settings.redis_url)}


@app.post("/ingest")
def ingest(flow: Flow):
    """Push one parsed flow. Returns the alert if this flow tripped a threshold."""
    alert = detector.process(flow)
    if alert:
        sink.emit(alert)
    return {"alert": alert}


@app.post("/ingest/batch")
def ingest_batch(flows: List[Flow]):
    alerts = []
    for f in flows:
        a = detector.process(f)
        if a:
            sink.emit(a)
            alerts.append(a)
    return {"processed": len(flows), "alerts": alerts}


@app.get("/alerts", response_model=List[Alert])
def alerts(limit: int = Query(100, le=1000)):
    return sink.recent(limit)


@app.get("/alerts/stream")
async def alerts_stream():
    """Server-Sent Events feed for the Next.js SOC dashboard (EventSource)."""
    async def gen():
        seq = sink.seq
        while True:
            for s, a in sink.since(seq):
                seq = s
                yield f"data: {json.dumps(a)}\n\n"
            await asyncio.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/sources/{ip}")
def source(ip: str):
    snap = detector.source_snapshot(ip)
    if snap is None:
        raise HTTPException(404, "source not in active window")
    return {"src_ip": ip, "window_seconds": settings.window_seconds, **snap}


@app.get("/stats")
def stats():
    return detector.stats()


@app.get("/config")
def config():
    return settings.__dict__ | {"redis_url": "***" if settings.redis_url else ""}
