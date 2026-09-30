# Botnet C2 Beaconing Module

Streaming, read-only, metadata-only detector for periodic "phone-home" traffic.

## Integration contract (same for every module)
```python
from c2_beacon import BeaconDetector, Flow
det = BeaconDetector()
for flow in your_ingest():            # Flow(ts, src_ip, dst_ip, dst_port, proto, bytes_out, ...)
    for alert in det.process_flow(flow):
        dashboard.push(alert.to_dict())   # standard Alert schema
```
Other modules should expose the same `process_flow(Flow) -> list[Alert]` method, so one
loop can fan each flow out to all detectors.

## Alert schema
`alert_id, timestamp, flow_id, threat_class ("BOTNET_C2_BEACONING"), confidence (0-1),
severity (LOW/MEDIUM/HIGH), src_ip, dst_ip, module, evidence{...}`

## Features (per src, dst, dst_port, proto channel; sliding window of 64 flows)
| Feature | Meaning |
|---|---|
| period_s / robust_cv | median inter-arrival time; MAD-based CV (outlier-proof jitter measure) |
| period_consistency | share of intervals within ±25% of period (integer multiples allowed = missed beats) |
| size_cv | variation in outbound bytes (heartbeats are similar in size) |
| observations / span | persistence of the behaviour |
| distinct_sources_to_dst | popular destinations (NTP, updates) are down-weighted |

Confidence = weighted sum (interval .35, consistency .30, size .15, persistence .10, rarity .10),
halved if not periodic, ×0.6 for popular destinations. Alert at ≥0.60; HIGH ≥0.90, MEDIUM ≥0.75.

## Model / training approach
Unsupervised statistical scoring with explainable evidence (no training data needed).
Weights and thresholds are in `BeaconConfig`; tune them on labelled replay data
(e.g. CTU-13 botnet captures, Stratosphere) with a grid search over precision/recall.
Optional upgrade: feed the feature vector (evidence) into a Random Forest / Isolation Forest.

## Constraints satisfied
- Read-only ingest: only consumes flow records; no probes or return path
- No decryption: uses timing and byte counts only
- Streaming: incremental, alert fires after `min_events` (8) flows on a channel
- Bounded memory: 64 samples/channel, LRU cap 200k channels, TTL purge
- Throughput: ~70k flows/sec single core (simulated 72k-flow replay; run `python run_demo.py`)

## Run
```
pip install -r requirements.txt pytest
pytest -q
python run_demo.py --duration 3600 --hosts 300 --infected 8
```
