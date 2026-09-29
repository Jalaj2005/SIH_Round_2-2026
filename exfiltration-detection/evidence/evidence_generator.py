from typing import Dict, List


class EvidenceGenerator:
    def __init__(
        self,
        outbound_baseline_ratio_threshold: float = 10.0,
        byte_ratio_threshold: float = 20.0,
        baseline_deviation_threshold: float = 3.0,
        transfer_rate_ratio_threshold: float = 5.0,
        burst_count_threshold: int = 2
    ):
        self.outbound_baseline_ratio_threshold = (
            outbound_baseline_ratio_threshold
        )

        self.byte_ratio_threshold = byte_ratio_threshold

        self.baseline_deviation_threshold = (
            baseline_deviation_threshold
        )

        self.transfer_rate_ratio_threshold = (
            transfer_rate_ratio_threshold
        )

        self.burst_count_threshold = burst_count_threshold

    def generate(
        self,
        features: Dict[str, float]
    ) -> List[str]:

        evidence = []

        outbound_baseline_ratio = features.get(
            "outbound_vs_baseline_ratio",
            0.0
        )

        byte_ratio = features.get(
            "byte_ratio",
            0.0
        )

        baseline_deviation = features.get(
            "baseline_deviation",
            0.0
        )

        transfer_rate_ratio = features.get(
            "transfer_rate_vs_baseline",
            0.0
        )

        burst_count = features.get(
            "burst_count",
            0
        )

        destination_novelty = features.get(
            "destination_novelty",
            0
        )

        destination_external = features.get(
            "destination_is_external",
            0
        )

        # --------------------------------------------------
        # Outbound traffic compared with host baseline
        # --------------------------------------------------

        if (
            outbound_baseline_ratio
            >= self.outbound_baseline_ratio_threshold
        ):
            evidence.append(
                "Outbound traffic is "
                + f"{outbound_baseline_ratio:.1f}x "
                + "above the host baseline"
            )

        # --------------------------------------------------
        # Outbound / inbound byte ratio
        # --------------------------------------------------

        if byte_ratio >= self.byte_ratio_threshold:
            evidence.append(
                "High outbound/inbound byte ratio: "
                + f"{byte_ratio:.1f}:1"
            )

        # --------------------------------------------------
        # Baseline deviation
        # --------------------------------------------------

        if (
            baseline_deviation
            >= self.baseline_deviation_threshold
        ):
            evidence.append(
                "Outbound traffic is "
                + f"{baseline_deviation:.1f} standard deviations "
                + "from the host baseline"
            )

        # --------------------------------------------------
        # Transfer rate
        # --------------------------------------------------

        if (
            transfer_rate_ratio
            >= self.transfer_rate_ratio_threshold
        ):
            evidence.append(
                "Transfer rate is "
                + f"{transfer_rate_ratio:.1f}x "
                + "above the historical rate"
            )

        # --------------------------------------------------
        # Large/repeated transfers
        # --------------------------------------------------

        if burst_count >= self.burst_count_threshold:
            evidence.append(
                "Multiple large outbound transfers detected: "
                + f"{burst_count}"
            )

        # --------------------------------------------------
        # Destination behaviour
        # --------------------------------------------------

        if destination_external == 1:
            evidence.append(
                "Traffic is being sent to an external destination"
            )

        if destination_novelty == 1:
            evidence.append(
                "Destination has not been observed previously"
            )

        # --------------------------------------------------
        # No evidence
        # --------------------------------------------------

        if len(evidence) == 0:
            evidence.append(
                "No individual exfiltration indicator "
                + "crossed its configured threshold"
            )

        return evidence