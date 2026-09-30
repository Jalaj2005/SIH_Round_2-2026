"""
Deterministic Unit Tests covering all 18 cases.
"""
import unittest
from ddos_detector.baseline import RollingTrafficBaseline
from ddos_detector.config import DDoSDetectorConfig
from ddos_detector.detector import DDoSDetector
from ddos_detector.entropy import calculate_shannon_entropy

class TestDDoSDetector(unittest.TestCase):
    def setUp(self):
        self.cfg = DDoSDetectorConfig(
            minimum_samples_for_baseline=3, baseline_window_size=5
        )
        self.detector = DDoSDetector(self.cfg)
        for _ in range(5):
            self.detector.detect(
                {
                    "packets_per_sec": 1000.0,
                    "syn_rate": 20.0,
                    "syn_ack_count": 20.0,
                    "ack_count": 20.0,
                    "unique_source_ips": 100,
                    "source_ip_entropy": 4.5,
                }
            )

    # 1. Normal traffic
    def test_01_normal_traffic(self):
        res = self.detector.detect(
            {
                "packets_per_sec": 1050.0,
                "syn_rate": 25.0,
                "syn_ack_count": 24.0,
                "ack_count": 25.0,
                "unique_source_ips": 110,
                "source_ip_entropy": 4.6,
            }
        )
        self.assertFalse(res["detected"])
        self.assertEqual(res["type"], "NORMAL")

    # 2. Legitimate traffic spike
    def test_02_legitimate_traffic_spike(self):
        res = self.detector.detect(
            {
                "packets_per_sec": 4000.0,
                "syn_rate": 80.0,
                "syn_ack_count": 78.0,
                "ack_count": 80.0,
                "unique_source_ips": 450,
                "source_ip_entropy": 5.2,
            }
        )
        self.assertFalse(res["detected"])
        self.assertEqual(res["type"], "NORMAL")

    # 3. SYN flood
    def test_03_syn_flood(self):
        payload = {
            "packets_per_sec": 25000.0,
            "syn_rate": 24000.0,
            "syn_ack_count": 10.0,
            "ack_count": 5.0,
            "unique_source_ips": 1500,
            "source_ip_entropy": 6.8,
        }
        for _ in range(3):
            res = self.detector.detect(payload)
        self.assertTrue(res["detected"])
        self.assertEqual(res["type"], "SYN_FLOOD")

    # 4. UDP flood
    def test_04_udp_flood(self):
        payload = {
            "packets_per_sec": 30000.0,
            "udp_packet_rate": 29000.0,
            "inbound_bytes": 1000000.0,
            "outbound_bytes": 800000.0,
            "inbound_outbound_ratio": 1.25,
            "unique_source_ips": 800,
        }
        for _ in range(3):
            res = self.detector.detect(payload)
        self.assertTrue(res["detected"])
        self.assertEqual(res["type"], "UDP_FLOOD")

    # 5. UDP reflection-like traffic
    def test_05_udp_reflection_like(self):
        payload = {
            "packets_per_sec": 35000.0,
            "udp_packet_rate": 34000.0,
            "inbound_bytes": 45000000.0,
            "outbound_bytes": 200000.0,
            "inbound_outbound_ratio": 225.0,
            "unique_source_ips": 50,
        }
        for _ in range(3):
            res = self.detector.detect(payload)
        self.assertTrue(res["detected"])
        self.assertEqual(res["type"], "UDP_REFLECTION_AMPLIFICATION")

    # 6. Spoofed-source flood
    def test_06_spoofed_source_flood(self):
        payload = {
            "packets_per_sec": 28000.0,
            "unique_source_ips": 20000,
            "unique_destination_ips": 1,
            "source_fanout": 20000.0,
            "source_ip_entropy": 9.5,
            "syn_rate": 500.0,
            "udp_packet_rate": 500.0,
        }
        for _ in range(3):
            res = self.detector.detect(payload)
        self.assertTrue(res["detected"])
        self.assertEqual(res["type"], "SPOOFED_SOURCE_FLOOD")

    # 7. High source entropy but legitimate traffic
    def test_07_high_source_entropy_legitimate(self):
        res = self.detector.detect(
            {
                "packets_per_sec": 1200.0,
                "unique_source_ips": 1100,
                "source_ip_entropy": 8.9,
                "syn_rate": 10.0,
                "ack_count": 10.0,
            }
        )
        self.assertFalse(res["detected"])
        self.assertEqual(res["type"], "NORMAL")

    # 8. High traffic without protocol anomaly
    def test_08_high_traffic_without_protocol_anomaly(self):
        res = self.detector.detect(
            {
                "packets_per_sec": 8000.0,
                "syn_rate": 100.0,
                "syn_ack_count": 100.0,
                "ack_count": 100.0,
                "udp_packet_rate": 50.0,
            }
        )
        self.assertFalse(res["detected"])

    # 9. One-window spike
    def test_09_one_window_spike(self):
        res = self.detector.detect(
            {
                "packets_per_sec": 45000.0,
                "syn_rate": 44000.0,
                "syn_ack_count": 0.0,
            }
        )
        self.assertNotEqual(res["severity"], "CRITICAL")
        self.assertLess(res["scores"]["persistence"], 0.50)

    # 10. Persistent attack
    def test_10_persistent_attack(self):
        payload = {
            "packets_per_sec": 45000.0,
            "syn_rate": 44000.0,
            "syn_ack_count": 0.0,
        }
        for _ in range(4):
            res = self.detector.detect(payload)
        self.assertTrue(res["detected"])
        self.assertGreaterEqual(res["scores"]["persistence"], 0.70)
        self.assertEqual(res["severity"], "CRITICAL")

    # 11. Empty input
    def test_11_empty_input(self):
        res = self.detector.detect({})
        self.assertFalse(res["detected"])
        self.assertEqual(res["type"], "NORMAL")

    # 12. Missing feature fields
    def test_12_missing_fields(self):
        res = self.detector.detect({"packets_per_sec": 1200.0})
        self.assertFalse(res["detected"])
        self.assertEqual(res["scores"]["tcp"], 0.0)

    # 13. Invalid values
    def test_13_invalid_values(self):
        res = self.detector.detect(
            {
                "packets_per_sec": -50.0,
                "syn_rate": "invalid",
                "ack_count": None,
            }
        )
        self.assertFalse(res["detected"])

    # 14. Zero standard deviation in baseline
    def test_14_zero_std_baseline(self):
        baseline = RollingTrafficBaseline(min_samples=2)
        baseline.update(100.0)
        baseline.update(100.0)
        z, _, std = baseline.compute_z_score(100.0)
        self.assertEqual(z, 0.0)
        self.assertEqual(std, 1.0)

    # 15. Entropy edge cases
    def test_15_entropy_edge_cases(self):
        self.assertEqual(calculate_shannon_entropy({}), 0.0)
        self.assertEqual(calculate_shannon_entropy({"1.1.1.1": 100}), 0.0)
        self.assertAlmostEqual(
            calculate_shannon_entropy({"A": 10, "B": 10, "C": 10, "D": 10}),
            2.0,
            places=2,
        )

    # 16. Confidence calculation
    def test_16_confidence_calculation(self):
        payload = {
            "packets_per_sec": 30000.0,
            "syn_rate": 28000.0,
            "syn_ack_count": 1.0,
        }
        self.detector.detect(payload)
        res = self.detector.detect(payload)
        self.assertTrue(0.0 <= res["confidence"] <= 1.0)

    # 17. Severity calculation
    def test_17_severity_calculation(self):
        res = self.detector.detect({"packets_per_sec": 1000.0})
        self.assertEqual(res["severity"], "LOW")

    # 18. Evidence generation
    def test_18_evidence_generation(self):
        res = self.detector.detect(
            {
                "packets_per_sec": 48000.0,
                "syn_rate": 45000.0,
                "syn_ack_count": 1.0,
                "ack_count": 0.0,
            }
        )
        features = [e["feature"] for e in res["evidence"]]
        self.assertIn("packets_per_sec", features)
        self.assertIn("syn_ack_ratio", features)


if __name__ == "__main__":
    unittest.main()