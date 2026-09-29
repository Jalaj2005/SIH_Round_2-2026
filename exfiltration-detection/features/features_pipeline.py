from typing import Dict, List, Optional

from schemas.flow_schema import FlowRecord

from features.volume_features import calculate_volume_features
from features.ratio_features import calculate_ratio_features
from features.destination_features import calculate_destination_features
from features.temporal_features import calculate_temporal_features
from features.baseline_features import calculate_baseline_features


def extract_features(
    flow: FlowRecord,
    flows: Optional[List[FlowRecord]] = None,
    window_seconds: float = 300.0,
    historical_avg_outbound_bytes: float = 0.0,
    historical_std_outbound_bytes: float = 0.0,
    historical_avg_transfer_rate: float = 0.0
) -> Dict[str, float]:
    """
    Extract all exfiltration-related features.

    The current flow is used for flow-level features.
    The complete flow list is used for window-level features.
    Historical values are used for baseline features.
    """

    # If no window is provided, use the current flow.
    if flows is None:
        flows = [flow]

    # ---------------------------------------------------------
    # 1. Volume features
    # ---------------------------------------------------------

    volume_features = calculate_volume_features(flow)

    # ---------------------------------------------------------
    # 2. Ratio features
    # ---------------------------------------------------------

    ratio_features = calculate_ratio_features(flow)

    # ---------------------------------------------------------
    # 3. Destination features
    # ---------------------------------------------------------

    destination_features = calculate_destination_features(flow)

    # ---------------------------------------------------------
    # 4. Temporal / window features
    # ---------------------------------------------------------

    temporal_features = calculate_temporal_features(
        flows=flows,
        window_seconds=window_seconds
    )

    # ---------------------------------------------------------
    # 5. Current transfer rate
    # ---------------------------------------------------------

    current_transfer_rate = 0.0

    if window_seconds > 0:
        total_outbound_bytes = 0

        for current_flow in flows:
            total_outbound_bytes += current_flow.bytes_sent

        current_transfer_rate = (
            total_outbound_bytes / window_seconds
        )

    # ---------------------------------------------------------
    # 6. Baseline features
    # ---------------------------------------------------------

    baseline_features = calculate_baseline_features(
        current_outbound_bytes=(
            sum(flow.bytes_sent for flow in flows)
        ),
        current_transfer_rate=current_transfer_rate,
        historical_avg_outbound_bytes=(
            historical_avg_outbound_bytes
        ),
        historical_std_outbound_bytes=(
            historical_std_outbound_bytes
        ),
        historical_avg_transfer_rate=(
            historical_avg_transfer_rate
        )
    )

    # ---------------------------------------------------------
    # 7. Combine everything
    # ---------------------------------------------------------

    features = {}

    features.update(volume_features)
    features.update(ratio_features)
    features.update(destination_features)
    features.update(temporal_features)
    features.update(baseline_features)

    return features