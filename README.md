# SIH 26145 - Module 1: Ingest -> Parser -> Flow Builder -> Feature Extraction -> Dispatcher

Strictly passive. No send path exists in the code (a test greps for it); run it on an RX-only
tap / SPAN port behind the diode.

    pip install -r requirements.txt
    python -m pytest tests -q                                   # 9 tests, ~2 s
    python -m sentinel_m1 --pcap some.pcap --jsonl out.jsonl    # dev run, see every record
    sudo python -m sentinel_m1 --iface eth1                     # live (AF_PACKET, receive only)
    python -m sentinel_m1.bench --flows 50000 --pkts 10 --consumers 8

## Record types (what Members 2-6 consume)

| record_type  | emitted                          | key fields | default consumers |
|--------------|----------------------------------|------------|-------------------|
| `dns`        | immediately per DNS query        | domain, sld, query_len, char/sld entropy, vowel ratios, ngram2/3, qtype, is_txt_null | dga, dns_tunnel, ti |
| `tls_hello`  | immediately on ClientHello       | ja3, ja3_string, ja4, sni, cipher/ext count, alpn | tls, ti |
| `flow_early` | when 20 payload pkts seen        | SPLT (signed len + iat_ms), ja3/ja4 | tls |
| `window`     | every `window_s` (1 s)           | scope=dst: pps/bps, syn/udp/icmp, unique_src, **src_entropy**; scope=src: **dport_entropy**, fan-out, ports_per_dst (vertical vs horizontal), dns_queries, dns_txt_null | ddos, portscan, dns_tunnel |
| `flow`       | on FIN/RST/idle/active/evict     | pkts/bytes/ratio, pps, bytes_per_sec, IAT seq/mean/var/cv, **Lomb-Scargle** (intra-flow + per host-pair connection history), TLS, SPLT, last-window entropy context | c2, exfil, ddos, portscan, tls, ti |

Routing table: `dispatch.ROUTES`. Consumers read `q = disp.subscribe("c2")` then `for rec in iter_records(q)`.

## Design decisions worth knowing
* **Sub-second alerting**: DNS/TLS records fire per packet, window records every 1 s; only the final `flow`
  record waits for flow end. Don't build the DDoS/scan detectors on `flow` alone.
* **Never blocks capture**: dispatcher uses `put_nowait` + batching; slow consumers => counted drops (`stats()`).
* **Memory bounded**: `max_flows` (evicts oldest), `max_window_keys`, `max_pairs`, capped per-flow arrays.
* **Half-duplex**: direction = who sent the first packet. With no reverse traffic `out_in_byte_ratio == bytes_out`
  (divides by max(bytes_in,1)) - Member 5's ">10" rule will fire on any one-way flow, so use `half_duplex` too.
* Beaconing works across *connections* (`pair_*` fields) as well as inside one long flow (`ls_*`).

## Known gaps
* QUIC: flows/SPLT work, but JA3/JA4 for QUIC needs Initial-packet decryption (derivable from public
  keys, still no payload decryption) - not implemented.
* TLS ClientHello split across >1 TCP segments is reassembled; out-of-order/retransmitted segments are not.
* SLD/TLD split is naive (`co.uk` -> sld `co`). Swap in an offline public-suffix list.
* No IPv4 fragment reassembly (non-first fragments get ports 0).

## Measured throughput (1 vCPU sandbox, pure Python, single process)
| load | pps | Mbps | flows/s |
|---|---|---|---|
| 10 pkts/flow, 650 B | 82k | ~430 | 8k |
| 2 pkts/flow | 37k | ~200 | 19k |
| 10 pkts/flow + 8 consumer procs (same 1 vCPU) | 53k | ~275 | 5k, 0 drops |

**This does not meet the blueprint's >=1 Gbps / 50k flows/s target on one core.** Path to it: shard by
hash(canonical 5-tuple) across N worker processes (each runs this exact pipeline), use `AF_PACKET`
`PACKET_FANOUT_HASH` so the kernel does the sharding for live capture, then re-benchmark on the real
demo machine.
