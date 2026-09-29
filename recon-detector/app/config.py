"""All tunables come from environment variables so the master pipeline can
reconfigure the container without a rebuild."""
import os
from dataclasses import dataclass


def _f(name, default):
    return float(os.getenv(name, default))


@dataclass(frozen=True)
class Settings:
    window_seconds: float = _f("WINDOW_SECONDS", 5)          # sliding window length
    horizontal_threshold: int = int(_f("HORIZ_THRESHOLD", 20))  # unique dst IPs
    vertical_threshold: int = int(_f("VERT_THRESHOLD", 20))     # unique ports on ONE dst
    min_confidence: float = _f("MIN_CONFIDENCE", 0.5)
    alert_cooldown: float = _f("ALERT_COOLDOWN", 10)          # s (event time) between repeats
    max_tracked_sources: int = int(_f("MAX_TRACKED_SOURCES", 100000))  # memory guard
    redis_url: str = os.getenv("REDIS_URL", "")               # empty => Redis disabled
    redis_flow_stream: str = os.getenv("REDIS_FLOW_STREAM", "flows")
    redis_alert_stream: str = os.getenv("REDIS_ALERT_STREAM", "alerts")
    dashboard_webhook: str = os.getenv("DASHBOARD_WEBHOOK", "")  # e.g. http://soc:3000/api/alerts


settings = Settings()
