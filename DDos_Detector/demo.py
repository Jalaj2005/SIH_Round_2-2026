from ddos_detector.detector import DDoSDetector
from ddos_detector.config import DDoSDetectorConfig
def run_demo():
    detector = DDoSDetector(DDoSDetectorConfig())

    scenarios = [
        (
            "SCENARIO A: Normal Browsing",
            {
                "packets_per_sec": 1020,
                "bytes_per_sec": 450000,
                "syn_rate": 15,
                "syn_ack_count": 14,
                "ack_count": 15,
                "unique_source_ips": 85,
                "source_ip_entropy": 4.1,
            },
            1,
        ),
        (
            "SCENARIO B: Legitimate High-Traffic Event (Flash Crowd)",
            {
                "packets_per_sec": 12000,
                "bytes_per_sec": 9800000,
                "syn_rate": 450,
                "syn_ack_count": 440,
                "ack_count": 450,
                "unique_source_ips": 3200,
                "source_ip_entropy": 7.8,
            },
            3,
        ),
        (
            "SCENARIO C: SYN Flood Attack",
            {
                "packets_per_sec": 52000,
                "bytes_per_sec": 3120000,
                "syn_rate": 51000,
                "syn_ack_count": 4,
                "ack_count": 2,
                "unique_source_ips": 1800,
                "source_ip_entropy": 6.9,
            },
            3,
        ),
        (
            "SCENARIO D: UDP Flood / Amplification Pattern",
            {
                "packets_per_sec": 42000,
                "udp_packet_rate": 41500,
                "inbound_bytes": 55000000,
                "outbound_bytes": 120000,
                "inbound_outbound_ratio": 458.3,
                "unique_source_ips": 120,
            },
            3,
        ),
        (
            "SCENARIO E: Spoofed-Source Flood",
            {
                "packets_per_sec": 48000,
                "unique_source_ips": 45000,
                "unique_destination_ips": 1,
                "source_fanout": 45000,
                "source_ip_entropy": 11.2,
                "syn_rate": 200,
                "udp_packet_rate": 300,
            },
            3,
        ),
        (
            "SCENARIO F: High Source Entropy But Legitimate Traffic",
            {
                "packets_per_sec": 1100,
                "unique_source_ips": 1050,
                "source_ip_entropy": 9.8,
                "syn_rate": 20,
                "ack_count": 20,
            },
            1,
        ),
    ]

    print("=" * 80)
    print("DDoS DETECTION ENGINE - SCENARIO BENCHMARK")
    print("=" * 80)

    for title, features, repeat in scenarios:
        print(f"\n>>> {title} (Windows: {repeat})")
        verdict = None
        for _ in range(repeat):
            verdict = detector.detect(features)

        print(f"Detected       : {verdict['detected']}")
        print(f"Classification : {verdict['type']}")
        print(f"Confidence     : {verdict['confidence']}")
        print(f"Severity       : {verdict['severity']}")
        print(f"Scores         : {verdict['scores']}")
        print("Evidence:")
        for ev in verdict["evidence"]:
            feat = ev.get("feature", "general")
            val = ev.get("value", "")
            reason = ev.get("reason", "")
            print(f"  • [{feat} = {val}] -> {reason}")
        print("-" * 80)


if __name__ == "__main__":
    run_demo()