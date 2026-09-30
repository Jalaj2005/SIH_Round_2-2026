"""Replay a PCAP through Module 1 and the local detector modules."""
import argparse
import json
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PARSER_DIR = ROOT / "packet-parser-feature-extraction"
if str(PARSER_DIR) not in sys.path:
    sys.path.insert(0, str(PARSER_DIR))

from sentinel_m1.capture import PcapFileSource
from sentinel_m1.dispatch import Dispatcher, iter_records
from sentinel_m1.pipeline import Module1

from core.pipeline import DashboardPipeline


class OffsetPcapSource:
    """Replay the same PCAP while keeping event timestamps monotonic between passes."""

    def __init__(self, path: str, speed: float, offset: float = 0.0):
        self.source = PcapFileSource(path, speed=speed)
        self.offset = offset
        self.next_offset = offset

    @property
    def linktype(self):
        return self.source.linktype

    def __iter__(self):
        first_ts = last_ts = None
        for timestamp, packet in self.source:
            if timestamp is not None:
                first_ts = timestamp if first_ts is None else first_ts
                last_ts = timestamp
                timestamp += self.offset
            yield timestamp, packet
        if first_ts is not None:
            self.next_offset = self.offset + max(0.0, last_ts - first_ts) + 1.0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Sentinel detection pipeline over a PCAP")
    parser.add_argument("pcap", help="Path to a .pcap or .pcapng capture")
    parser.add_argument("--speed", type=float, default=0.0, help="Replay speed; 0 processes as fast as possible")
    parser.add_argument("--loop", action="store_true", help="Replay continuously until Ctrl+C")
    parser.add_argument("--loop-delay", type=float, default=0.5, help="Seconds between replay passes")
    args = parser.parse_args()

    dashboard = DashboardPipeline()
    offset = 0.0
    while True:
        dispatcher = Dispatcher(use_processes=False)
        records = dispatcher.subscribe("dashboard", types={"window", "flow", "dns", "tls_hello"})
        consumer_errors = []

        def consume() -> None:
            try:
                for record in iter_records(records):
                    dashboard.process_record(record)
            except Exception as exc:
                consumer_errors.append(exc)

        consumer = threading.Thread(target=consume, name="dashboard-detectors", daemon=True)
        consumer.start()
        source = OffsetPcapSource(args.pcap, args.speed, offset)
        pipeline = Module1(dispatcher=dispatcher)
        try:
            report = pipeline.run(source)
        except BaseException:
            pipeline.finish()
            raise
        finally:
            consumer.join()

        dashboard.finish(report)
        if consumer_errors:
            raise RuntimeError("A detector failed while consuming parser records") from consumer_errors[0]
        print(json.dumps({
            "parser": report,
            "alerts_written": dashboard.alert_count,
            "telemetry_file": str(dashboard.telemetry_file),
            "alerts_file": str(dashboard.alerts_file),
            "tls_model": dashboard.tls_status,
        }, indent=2), flush=True)
        if not args.loop:
            break
        offset = source.next_offset
        time.sleep(max(0.0, args.loop_delay))


if __name__ == "__main__":
    main()