# Module 6 – Reconnaissance & Port-Scan Detection

## 1. Constraints honoured (SIH 2026 #145)
- **Read-only ingest:** the service only consumes flow records; it never probes, replies or pushes anything back.
- **No payload access:** only flow metadata (IPs, ports, flags, timestamps) is used.
- **Streaming:** each flow is processed on arrival with O(1) amortised work; alerts fire the moment a threshold is crossed.
- **Standard alert schema:** see `alert_schema.json`.

## 2. Model
Rule-based behavioural detector over a per-source sliding window (default 5 s, event-time clock).
No training set is needed; thresholds are tuned on lab traffic (see section 6).

## 3. Features (per source IP, per window)
| Feature | Meaning |
|---|---|
| unique_dst_ips | distinct destination hosts contacted (horizontal signal) |
| unique_ports_scanned | distinct destination ports contacted |
| max_ports_single_dst | most distinct ports on any one host (vertical signal) |
| connection_attempts | connection-initiating flows |
| failed_connections / failed_ratio | probes with no reverse-direction answer (or answered only by RST) |

## 4. Detection logic
- Horizontal scan: unique_dst_ips >= HORIZ_THRESHOLD.
- Vertical scan: max_ports_single_dst >= VERT_THRESHOLD.
- Both: combined_scan.
- Failed connections are inferred passively: each probe is held as pending until the reverse flow (dst -> src, src_port = probed port) is seen. A bare RST reply counts as failed.
- Confidence = 0.55 * fan-out score + 0.30 * failed_ratio + 0.15 * volume score, clipped to [0,1]. Alert only if >= MIN_CONFIDENCE.
- Severity: >=0.9 critical, >=0.75 high, >=0.6 medium, otherwise low.
- Per-(source, sub_type) cooldown suppresses duplicate alerts.

## 5. False-positive controls
- Reverse-leg flows matched to a tracked probe are not counted as initiations.
- Well-known-port to ephemeral-port flows are treated as server responses.
- Mid-stream TCP flows without SYN are ignored.
- Fully answered fan-out (e.g. a monitoring system) scores lower and often stays below MIN_CONFIDENCE.

## 6. Validation plan (fill in with your measured results)
| Test | Tool | Expected | Measured |
|---|---|---|---|
| Vertical scan | nmap -sS -p 1-1000 | vertical_scan alert | |
| Horizontal sweep | nmap -p 445 <subnet> | horizontal_scan alert | |
| SYN flood (should NOT be scan) | hping3 --flood | no scan alert or low confidence | |
| Benign traffic | iperf3 / TRex | no alerts | |

## 7. Throughput
- In-process (`python -m scripts.benchmark`): ~135,000 flows/s on a 300k-flow synthetic run, 5 alerts, no false alerts on benign clients.
- HTTP path: measure and add here.

## 8. Limitations
- Scans slower than one per window are missed; run a second long-window instance for low-and-slow scans.
- Detection state is in one process; scale by sharding sources across instances.
- Distributed scans from many sources are out of scope for this module.
