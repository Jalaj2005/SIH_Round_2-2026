from typing import Dict

from detection.threshold import ExfiltrationThresholds


class ExfiltrationDetector:

    def check_outbound_baseline_ratio(
        self,
        features: Dict[str, float]
    ) -> bool:

        value = features.get(
            "outbound_vs_baseline_ratio",
            0.0
        )

        return (
            value >=
            ExfiltrationThresholds.OUTBOUND_BASELINE_RATIO
        )

    def check_byte_ratio(
        self,
        features: Dict[str, float]
    ) -> bool:

        value = features.get(
            "byte_ratio",
            0.0
        )

        return (
            value >=
            ExfiltrationThresholds.BYTE_RATIO
        )

    def check_baseline_deviation(
        self,
        features: Dict[str, float]
    ) -> bool:

        value = features.get(
            "baseline_deviation",
            0.0
        )

        return (
            value >=
            ExfiltrationThresholds.BASELINE_DEVIATION
        )

    def check_transfer_rate(
        self,
        features: Dict[str, float]
    ) -> bool:

        value = features.get(
            "transfer_rate_vs_baseline",
            0.0
        )

        return (
            value >=
            ExfiltrationThresholds.TRANSFER_RATE_BASELINE_RATIO
        )

    def check_burst_count(
        self,
        features: Dict[str, float]
    ) -> bool:

        value = features.get(
            "burst_count",
            0
        )

        return (
            value >=
            ExfiltrationThresholds.BURST_COUNT
        )

    def check_new_external_destination(
        self,
        features: Dict[str, float]
    ) -> bool:

        novelty = features.get(
            "destination_novelty",
            0
        )

        external = features.get(
            "destination_is_external",
            0
        )

        return (
            novelty == 1
            and external == 1
        )

    def calculate_score(
        self,
        features: Dict[str, float]
    ) -> int:

        score = 0

        if self.check_outbound_baseline_ratio(features):
            score += (
                ExfiltrationThresholds
                .OUTBOUND_BASELINE_WEIGHT
            )

        if self.check_byte_ratio(features):
            score += (
                ExfiltrationThresholds
                .BYTE_RATIO_WEIGHT
            )

        if self.check_baseline_deviation(features):
            score += (
                ExfiltrationThresholds
                .BASELINE_DEVIATION_WEIGHT
            )

        if self.check_transfer_rate(features):
            score += (
                ExfiltrationThresholds
                .TRANSFER_RATE_WEIGHT
            )

        if self.check_burst_count(features):
            score += (
                ExfiltrationThresholds
                .BURST_WEIGHT
            )

        if self.check_new_external_destination(features):
            score += (
                ExfiltrationThresholds
                .DESTINATION_WEIGHT
            )

        return score

    def get_severity(
        self,
        score: int
    ) -> str:

        if score >= 80:
            return "CRITICAL"

        if score >= 60:
            return "HIGH"

        if score >= 30:
            return "MEDIUM"

        return "LOW"

    def is_suspicious(
        self,
        score: int
    ) -> bool:

        return (
            score >=
            ExfiltrationThresholds.DETECTION_SCORE
        )

    def detect(
        self,
        features: Dict[str, float]
    ) -> Dict[str, object]:

        score = self.calculate_score(features)

        severity = self.get_severity(score)

        suspicious = self.is_suspicious(score)

        return {
            "is_suspicious": suspicious,
            "risk_score": score,
            "severity": severity
        }