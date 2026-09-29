from datetime import datetime
from typing import List, Dict

from schemas.flow_schema import FlowRecord


def calculate_transfer_count(flows: List[FlowRecord]) -> int:
    """
    Number of flows/transfers observed in the given time window.
    """
    return len(flows)


def calculate_transfers_per_minute(
    flows: List[FlowRecord],
    window_seconds: float
) -> float:
    """
    Calculates the number of transfers per minute.
    """

    if window_seconds <= 0:
        return 0.0

    transfers_per_second = len(flows) / window_seconds

    return transfers_per_second * 60


def calculate_inter_transfer_times(
    flows: List[FlowRecord]
) -> List[float]:
    """
    Calculates the time gap between consecutive flows.

    Returns:
        List of time differences in seconds.
    """

    if len(flows) < 2:
        return []

    sorted_flows = sorted(
        flows,
        key=lambda flow: flow.timestamp
    )

    intervals = []

    for i in range(1, len(sorted_flows)):
        previous_time = sorted_flows[i - 1].timestamp
        current_time = sorted_flows[i].timestamp

        difference = (
            current_time - previous_time
        ).total_seconds()

        intervals.append(difference)

    return intervals


def calculate_mean_inter_transfer_time(
    flows: List[FlowRecord]
) -> float:
    """
    Calculates the average time between consecutive transfers.
    """

    intervals = calculate_inter_transfer_times(flows)

    if len(intervals) == 0:
        return 0.0

    return sum(intervals) / len(intervals)


def calculate_std_inter_transfer_time(
    flows: List[FlowRecord]
) -> float:
    """
    Calculates the standard deviation of the
    time between consecutive transfers.
    """

    intervals = calculate_inter_transfer_times(flows)

    if len(intervals) <= 1:
        return 0.0

    mean = sum(intervals) / len(intervals)

    squared_difference_sum = 0.0

    for interval in intervals:
        difference = interval - mean
        squared_difference_sum += difference * difference

    variance = squared_difference_sum / len(intervals)

    return variance ** 0.5


def calculate_burst_bytes(
    flows: List[FlowRecord]
) -> int:
    """
    Calculates total outbound bytes observed
    in the given time window.

    This can be used as a simple measure of
    outbound traffic bursts.
    """

    total_bytes = 0

    for flow in flows:
        total_bytes += flow.bytes_sent

    return total_bytes


def calculate_burst_count(
    flows: List[FlowRecord],
    burst_threshold: int
) -> int:
    """
    Counts how many individual flows have outbound
    data greater than the specified burst threshold.
    """

    count = 0

    for flow in flows:
        if flow.bytes_sent >= burst_threshold:
            count += 1

    return count


def calculate_time_of_day(
    timestamp: datetime
) -> float:
    """
    Converts the time of day into minutes since midnight.

    Example:
        01:30 -> 90
        12:00 -> 720
        23:00 -> 1380
    """

    return timestamp.hour * 60 + timestamp.minute


def calculate_temporal_features(
    flows: List[FlowRecord],
    window_seconds: float,
    burst_threshold: int = 10_000_000
) -> Dict[str, float]:
    """
    Extracts all temporal features for a group of flows.
    """

    transfer_count = calculate_transfer_count(flows)

    transfers_per_minute = calculate_transfers_per_minute(
        flows,
        window_seconds
    )

    mean_inter_transfer_time = (
        calculate_mean_inter_transfer_time(flows)
    )

    std_inter_transfer_time = (
        calculate_std_inter_transfer_time(flows)
    )

    burst_bytes = calculate_burst_bytes(flows)

    burst_count = calculate_burst_count(
        flows,
        burst_threshold
    )

    if len(flows) > 0:
        first_timestamp = min(
            flow.timestamp for flow in flows
        )

        time_of_day = calculate_time_of_day(
            first_timestamp
        )
    else:
        time_of_day = 0.0

    features = {
        "transfer_count": transfer_count,
        "transfers_per_minute": transfers_per_minute,
        "mean_inter_transfer_time": mean_inter_transfer_time,
        "std_inter_transfer_time": std_inter_transfer_time,
        "window_outbound_bytes": burst_bytes,
        "burst_count": burst_count,
        "time_of_day": time_of_day
    }

    return features