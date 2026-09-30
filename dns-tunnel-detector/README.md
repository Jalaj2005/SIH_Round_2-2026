# DNS Tunnelling Detector

Streaming, metadata-only detector for DNS tunnelling patterns. It consumes Module 1 `dns`
records and emits dashboard Section 6 alerts.

```python
from sentinel_dns_tunnel import DNSTunnelDetector

detector = DNSTunnelDetector()
alert = detector.process_dns(dns_record)
```

The bounded per-host/domain window scores encoded-label length and entropy, label uniqueness,
query rate, cadence regularity, and TXT/NULL query share. Confidence is reduced for domains
queried by many distinct sources. No DNS payload decoding or active network traffic is used.

Run tests with `pytest tests -q` from this directory.