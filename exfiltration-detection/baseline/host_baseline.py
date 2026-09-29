from typing import Dict, List
from schemas.flow_schema import FlowRecord


class HostBaseline:
    def __init__(self):
        # Stores historical statistics for each source host.
        #
        # Example:
        # {
        #     "10.0.0.42": {
        #         "window_count": 5,
        #         "avg_outbound_bytes": 2500000.0,
        #         "avg_transfer_rate": 120000.0
        #     }
        # }
        self.baselines: Dict[str, Dict[str, float]] = {}

    def calculate_window_values(
        self,
        flows: List[FlowRecord],
        window_seconds: float
    ) -> Dict[str, float]:
        """
        Calculate traffic statistics for one completed window.
        """

        if len(flows) == 0:
            return {
                "outbound_bytes": 0.0,
                "transfer_rate": 0.0
            }

        total_outbound_bytes = 0

        for flow in flows:
            total_outbound_bytes += flow.bytes_sent

        transfer_rate = (
            total_outbound_bytes / window_seconds
            if window_seconds > 0
            else 0.0
        )

        return {
            "outbound_bytes": float(total_outbound_bytes),
            "transfer_rate": transfer_rate
        }

    def update(
        self,
        source_ip: str,
        flows: List[FlowRecord],
        window_seconds: float
    ) -> None:
        """
        Update the historical baseline for a source host.
        """

        current_values = self.calculate_window_values(
            flows,
            window_seconds
        )

        current_outbound_bytes = current_values["outbound_bytes"]
        current_transfer_rate = current_values["transfer_rate"]

        if source_ip not in self.baselines:

            self.baselines[source_ip] = {
                "window_count": 1,
                "avg_outbound_bytes": current_outbound_bytes,
                "avg_transfer_rate": current_transfer_rate,
                "outbound_bytes_values": [
                    current_outbound_bytes
                ]
            }

            return

        baseline = self.baselines[source_ip]

        baseline["window_count"] += 1

        baseline["outbound_bytes_values"].append(
            current_outbound_bytes
        )

        values = baseline["outbound_bytes_values"]

        baseline["avg_outbound_bytes"] = (
            sum(values) / len(values)
        )

        # Recalculate average transfer rate.
        previous_avg = baseline["avg_transfer_rate"]

        window_count = baseline["window_count"]

        baseline["avg_transfer_rate"] = (
            (
                previous_avg * (window_count - 1)
            ) + current_transfer_rate
        ) / window_count

    def get_baseline(
        self,
        source_ip: str
    ) -> Dict[str, float]:
        """
        Return the current baseline of a source host.
        """

        if source_ip not in self.baselines:
            return {
                "window_count": 0,
                "avg_outbound_bytes": 0.0,
                "avg_transfer_rate": 0.0,
                "outbound_std": 0.0
            }

        baseline = self.baselines[source_ip]

        values = baseline["outbound_bytes_values"]

        average = baseline["avg_outbound_bytes"]

        if len(values) <= 1:
            standard_deviation = 0.0
        else:
            squared_difference_sum = 0.0

            for value in values:
                difference = value - average
                squared_difference_sum += difference * difference

            variance = (
                squared_difference_sum / len(values)
            )

            standard_deviation = variance ** 0.5

        return {
            "window_count": baseline["window_count"],
            "avg_outbound_bytes": baseline["avg_outbound_bytes"],
            "avg_transfer_rate": baseline["avg_transfer_rate"],
            "outbound_std": standard_deviation
        }

    def has_baseline(self, source_ip: str) -> bool:
        """
        Check whether enough baseline information exists
        for a source host.
        """

        if source_ip not in self.baselines:
            return False

        return self.baselines[source_ip]["window_count"] > 0

    def get_all_baselines(self) -> Dict[str, Dict[str, float]]:
        """
        Return all stored host baselines.
        """

        all_baselines = {}

        for source_ip in self.baselines:
            all_baselines[source_ip] = self.get_baseline(
                source_ip
            )

        return all_baselines

    def reset_host(self, source_ip: str) -> None:
        """
        Remove the baseline of one source host.
        """

        if source_ip in self.baselines:
            del self.baselines[source_ip]

    def reset_all(self) -> None:
        """
        Remove all stored baselines.
        """

        self.baselines.clear()