"""
Explainable, Multi-Signal Rule/Statistical DDoS Detector.
NO ML - Fully deterministic and lightweight.
"""
from typing import Any, Dict, List, Tuple
from .baseline import RollingTrafficBaseline
from .config import DDoSDetectorConfig
from .entropy import calculate_shannon_entropy


class DDoSDetector:
    def __init__(self, config: DDoSDetectorConfig = DDoSDetectorConfig()):
        self.cfg = config
        self.baseline = RollingTrafficBaseline(
            window_size=self.cfg.baseline_window_size,
            min_samples=self.cfg.minimum_samples_for_baseline,
            default_mean=self.cfg.default_baseline_pps,
        )
        self.consecutive_suspicious_windows = 0
        self.smoothed_persistence_score = 0.0

    def _safe_float(self, val: Any, default: float = 0.0) -> float:
        try:
            if val is None:
                return default
            return float(val)
        except (ValueError, TypeError):
            return default
        
    def _normalize_score(self, val: float, min_val: float, max_val: float) -> float:
        if val <= min_val:
            return 0.0
        if val >= max_val:
            return 1.0
        return round((val - min_val) / (max_val - min_val), 4)

    def _evaluate_rate_signal(
        self, features: Dict[str, Any]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        evidence = []
        pps = float(features.get("packets_per_sec", 0.0))
        z_score, mean_pps, std_pps = self.baseline.compute_z_score(pps)

        rate_score = self._normalize_score(
            z_score, 1.5, self.cfg.rate_deviation_threshold * 2.0
        )

        if z_score >= self.cfg.rate_deviation_threshold:
            evidence.append(
                {
                    "feature": "packets_per_sec",
                    "value": pps,
                    "baseline": mean_pps,
                    "reason": f"Traffic rate is significantly above baseline (+{z_score} sigma)",
                }
            )
        return rate_score, evidence

    def _evaluate_source_signal(
        self, features: Dict[str, Any]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        evidence = []
        unique_src = self._safe_float(features.get("unique_source_ips", 1))
        unique_dst = self._safe_float(features.get("unique_destination_ips", 1))

        entropy = features.get("source_ip_entropy")
        if entropy is None:
            raw_sources = features.get("source_distribution", {})
            entropy = calculate_shannon_entropy(raw_sources)
        else:
            entropy = self._safe_float(entropy)

        fanout = unique_src / max(1.0, unique_dst)

        entropy_score = self._normalize_score(
            entropy, 3.0, self.cfg.entropy_high_threshold
        )
        fanout_score = self._normalize_score(
            fanout, 5.0, self.cfg.spoofed_fanout_threshold
        )
        source_score = round(0.6 * entropy_score + 0.4 * fanout_score, 4)

        if entropy >= self.cfg.entropy_high_threshold:
            evidence.append(
                {
                    "feature": "source_ip_entropy",
                    "value": entropy,
                    "reason": "Traffic is distributed across an unusually large source population",
                }
            )
        if fanout >= self.cfg.spoofed_fanout_threshold:
            evidence.append(
                {
                    "feature": "source_fanout",
                    "value": round(fanout, 2),
                    "reason": "Excessive source-to-destination fanout indicates targeted convergence",
                }
            )

        return source_score, evidence

    def _evaluate_tcp_signal(
        self, features: Dict[str, Any]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        evidence = []
        syn_rate = self._safe_float(features.get("syn_rate", features.get("syn_count", 0.0)))
        syn_ack = self._safe_float(features.get("syn_ack_count", 0.0))
        ack = self._safe_float(features.get("ack_count", 0.0))
        total_packets = max(
            1.0,
            self._safe_float(features.get("packets_per_sec", features.get("packet_count", 1.0))),
        )

        syn_ratio = syn_rate / total_packets
        completion_ratio = syn_rate / max(1.0, (syn_ack + ack))

        syn_vol_score = self._normalize_score(
            syn_rate, 500.0, self.cfg.syn_rate_threshold
        )
        imbalance_score = self._normalize_score(
            completion_ratio, 1.5, self.cfg.syn_ack_ratio_threshold
        )
        pct_score = self._normalize_score(
            syn_ratio, 0.4, self.cfg.syn_percentage_threshold
        )

        tcp_score = round(
            0.4 * imbalance_score + 0.35 * syn_vol_score + 0.25 * pct_score, 4
        )

        if completion_ratio >= self.cfg.syn_ack_ratio_threshold and syn_rate >= 500:
            evidence.append(
                {
                    "feature": "syn_ack_ratio",
                    "value": round(completion_ratio, 2),
                    "reason": "Strong SYN/SYN-ACK imbalance indicates half-open flood",
                }
            )
        return tcp_score, evidence

    def _evaluate_udp_signal(
        self, features: Dict[str, Any]
    ) -> Tuple[float, List[Dict[str, Any]]]:
        evidence = []
        udp_rate = float(
            features.get("udp_packet_rate", features.get("udp_packet_count", 0.0))
        )
        total_pps = max(1.0, float(features.get("packets_per_sec", 1.0)))
        inbound_bytes = float(features.get("inbound_bytes", 0.0))
        outbound_bytes = float(features.get("outbound_bytes", 1.0))

        udp_ratio = udp_rate / total_pps
        asymmetry = inbound_bytes / max(1.0, outbound_bytes)

        udp_vol_score = self._normalize_score(
            udp_rate, 1000.0, self.cfg.udp_packet_rate_threshold
        )
        udp_pct_score = self._normalize_score(
            udp_ratio, 0.3, self.cfg.udp_percentage_threshold
        )
        asym_score = self._normalize_score(
            asymmetry, 1.5, self.cfg.udp_asymmetry_ratio_threshold
        )

        udp_score = round(
            0.45 * udp_vol_score + 0.35 * udp_pct_score + 0.20 * asym_score, 4
        )

        if (
            udp_rate >= self.cfg.udp_packet_rate_threshold
            and udp_ratio >= self.cfg.udp_percentage_threshold
        ):
            evidence.append(
                {
                    "feature": "udp_packet_rate",
                    "value": udp_rate,
                    "reason": "Abnormal UDP packet rate dominating aggregate window bandwidth",
                }
            )
        return udp_score, evidence

    def _evaluate_temporal_signal(self, features: Dict[str, Any]) -> float:
        burstiness = float(features.get("burstiness", 0.0))
        std_iat = float(features.get("std_inter_arrival_time", 1.0))
        iat_collapse = 1.0 - min(1.0, std_iat)
        return round(0.5 * min(1.0, burstiness) + 0.5 * max(0.0, iat_collapse), 4)

    def _update_persistence(self, composite_score: float) -> float:
        if composite_score >= self.cfg.severity_low_cutoff:
            self.consecutive_suspicious_windows += 1
            gain = min(
                1.0,
                self.consecutive_suspicious_windows
                / self.cfg.persistence_window_count,
            )
            self.smoothed_persistence_score = round(
                self.smoothed_persistence_score * (1.0 - self.cfg.score_decay)
                + gain * self.cfg.score_decay,
                2,
            )
        else:
            self.consecutive_suspicious_windows = max(
                0, self.consecutive_suspicious_windows - 1
            )
            self.smoothed_persistence_score = round(
                self.smoothed_persistence_score * (1.0 - self.cfg.score_decay),
                2,
            )

        return min(1.0, self.smoothed_persistence_score)

    def _classify_attack(
        self, scores: Dict[str, float], features: Dict[str, Any]
    ) -> Tuple[str, float]:
        rate = scores["rate"]
        tcp = scores["tcp"]
        udp = scores["udp"]
        src = scores["source"]

        # Rule 1: SYN Flood
        if tcp >= 0.70 and rate >= 0.50:
            return "SYN_FLOOD", round(0.6 * tcp + 0.4 * rate, 2)

        # Rule 2: UDP Reflection / Amplification or UDP Flood
        if udp >= 0.70 and rate >= 0.50:
            inbound_outbound = float(features.get("inbound_outbound_ratio", 1.0))
            if inbound_outbound >= self.cfg.udp_asymmetry_ratio_threshold:
                return "UDP_REFLECTION_AMPLIFICATION", round(
                    0.6 * udp + 0.4 * rate, 2
                )
            return "UDP_FLOOD", round(0.55 * udp + 0.45 * rate, 2)

        # Rule 3: Spoofed Source Flood
        if src >= 0.75 and rate >= 0.65:
            return "SPOOFED_SOURCE_FLOOD", round(0.55 * src + 0.45 * rate, 2)

        # Rule 4: Ambiguous volumetric condition (Do NOT force classification)
        if rate >= 0.60:
            return "SUSPICIOUS_FLOOD", round(rate, 2)

        return "NORMAL", 0.0

    def _calculate_severity(
        self, confidence: float, pps: float, subtype: str
    ) -> str:
        if subtype == "NORMAL" or confidence < self.cfg.severity_low_cutoff:
            return "LOW"
        if confidence >= self.cfg.severity_crit_cutoff or (
            confidence >= 0.80 and pps >= 50000
        ):
            return "CRITICAL"
        if confidence >= self.cfg.severity_high_cutoff:
            return "HIGH"
        if confidence >= self.cfg.severity_med_cutoff:
            return "MEDIUM"
        return "LOW"

    def detect(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Processes one feature window and outputs structured explainable verdict."""
        if not features:
            return {
                "threat": "DDOS",
                "detected": False,
                "type": "NORMAL",
                "confidence": 0.0,
                "severity": "LOW",
                "scores": {},
                "evidence": [{"reason": "Empty window features supplied"}],
            }

        # 1. Independent signal scores
        rate_score, rate_ev = self._evaluate_rate_signal(features)
        src_score, src_ev = self._evaluate_source_signal(features)
        tcp_score, tcp_ev = self._evaluate_tcp_signal(features)
        udp_score, udp_ev = self._evaluate_udp_signal(features)
        temp_score = self._evaluate_temporal_signal(features)

        # 2. Instantaneous weighted score
        instantaneous_score = (
            self.cfg.rate_weight * rate_score
            + self.cfg.source_weight * src_score
            + self.cfg.tcp_weight * tcp_score
            + self.cfg.udp_weight * udp_score
            + self.cfg.temporal_weight * temp_score
        )

        # 3. Temporal persistence tracking
        persist_score = self._update_persistence(instantaneous_score)

        # 4. Total DDoS Score
        total_ddos_score = round(
            (1.0 - self.cfg.persistence_weight) * instantaneous_score
            + self.cfg.persistence_weight * persist_score,
            2,
        )

        scores = {
            "rate": round(rate_score, 2),
            "source": round(src_score, 2),
            "tcp": round(tcp_score, 2),
            "udp": round(udp_score, 2),
            "temporal": round(temp_score, 2),
            "persistence": round(persist_score, 2),
        }

        # 5. Rule-based Subtype Classification
        subtype, subtype_conf = self._classify_attack(scores, features)
        detected = (subtype != "NORMAL") and (
            total_ddos_score >= self.cfg.severity_low_cutoff
        )

        confidence = (
            round(min(1.0, (0.7 * subtype_conf + 0.3 * persist_score)), 2)
            if detected
            else 0.0
        )

        # Baseline update with poisoning protection
        pps = float(features.get("packets_per_sec", 0.0))
        is_attack = detected or rate_score >= 0.5
        self.baseline.update(pps, is_attack=is_attack)

        # 6. Aggregate Evidence
        all_evidence = rate_ev + src_ev + tcp_ev + udp_ev
        if not all_evidence and detected:
            all_evidence.append(
                {
                    "feature": "composite_score",
                    "value": total_ddos_score,
                    "reason": "Multiple sub-critical indicators breached combined threshold",
                }
            )

        severity = self._calculate_severity(confidence, pps, subtype)

        return {
            "threat": "DDOS",
            "detected": detected,
            "type": subtype if detected else "NORMAL",
            "confidence": confidence,
            "severity": severity,
            "scores": scores,
            "evidence": all_evidence,
        }
    