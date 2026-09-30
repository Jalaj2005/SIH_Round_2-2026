"""Replay simulated traffic through the detector; report accuracy + throughput."""
import json, time, argparse
from c2_beacon import BeaconDetector, BeaconConfig
from c2_beacon.simulator import generate

ap = argparse.ArgumentParser()
ap.add_argument("--duration", type=float, default=3600)
ap.add_argument("--hosts", type=int, default=300)
ap.add_argument("--infected", type=int, default=8)
ap.add_argument("--out", default="alerts.jsonl")
a = ap.parse_args()

flows, truth = generate(a.duration, a.hosts, a.infected)
det = BeaconDetector(BeaconConfig())
alerts, first_alert = [], {}
t_start = time.perf_counter()
for f in flows:
    for al in det.process_flow(f):
        alerts.append(al)
        first_alert.setdefault((al.src_ip, al.dst_ip), al)
elapsed = time.perf_counter() - t_start

flagged = set(first_alert)
tp, fp, fn = flagged & truth, flagged - truth, truth - flagged
prec = len(tp) / max(1, len(flagged)); rec = len(tp) / max(1, len(truth))
with open(a.out, "w") as fh:
    for al in alerts:
        fh.write(al.to_json() + "\n")

print(f"flows processed : {len(flows):,}")
print(f"wall time       : {elapsed:.2f}s  ->  {len(flows)/elapsed:,.0f} flows/sec (single core)")
print(f"channels tracked: {det.tracked_channels:,}   alerts: {len(alerts)}")
print(f"true beacons    : {len(truth)}  detected: {len(tp)}  missed: {len(fn)}  false pos: {len(fp)}")
print(f"precision {prec:.2f}  recall {rec:.2f}")
for k in sorted(tp):
    al = first_alert[k]; e = al.evidence
    print(f"  {k[0]:>10} -> {k[1]:<11} conf {al.confidence:.2f} {al.severity:<6} "
          f"period {e['period_s']}s after {e['observations']} obs")
if fp: print("false positives:", sorted(fp))
print(f"alerts written to {a.out}")
