from typing import Dict

from schemas.flow_schema import FlowRecord


def calculate_total_bytes(flow: FlowRecord) -> int:
    """
    Calculates total bytes transferred in both directions.
    """

    return flow.bytes_sent + flow.bytes_received


def calculate_total_packets(flow: FlowRecord) -> int:
    """
    Calculates total packets transferred in both directions.
    """

    return flow.packets_sent + flow.packets_received


def calculate_outbound_bytes_per_second(
    flow: FlowRecord
) -> float:
    """
    Calculates outbound data transfer rate.
    """

    if flow.duration <= 0:
        return 0.0

    return flow.bytes_sent / flow.duration


def calculate_inbound_bytes_per_second(
    flow: FlowRecord
) -> float:
    """
    Calculates inbound data transfer rate.
    """

    if flow.duration <= 0:
        return 0.0

    return flow.bytes_received / flow.duration


def calculate_outbound_packets_per_second(
    flow: FlowRecord
) -> float:
    """
    Calculates outbound packet rate.
    """

    if flow.duration <= 0:
        return 0.0

    return flow.packets_sent / flow.duration


def calculate_inbound_packets_per_second(
    flow: FlowRecord
) -> float:
    """
    Calculates inbound packet rate.
    """

    if flow.duration <= 0:
        return 0.0

    return flow.packets_received / flow.duration


def calculate_volume_features(
    flow: FlowRecord
) -> Dict[str, float]:
    """
    Extracts all volume and rate-related features
    from a single flow.
    """

    total_bytes = calculate_total_bytes(flow)

    total_packets = calculate_total_packets(flow)

    outbound_bytes_per_second = (
        calculate_outbound_bytes_per_second(flow)
    )

    inbound_bytes_per_second = (
        calculate_inbound_bytes_per_second(flow)
    )

    outbound_packets_per_second = (
        calculate_outbound_packets_per_second(flow)
    )

    inbound_packets_per_second = (
        calculate_inbound_packets_per_second(flow)
    )

    features = {
        "outbound_bytes": flow.bytes_sent,

        "inbound_bytes": flow.bytes_received,

        "total_bytes": total_bytes,

        "outbound_packets": flow.packets_sent,

        "inbound_packets": flow.packets_received,

        "total_packets": total_packets,

        "flow_duration": flow.duration,

        "outbound_bytes_per_sec":
            outbound_bytes_per_second,

        "inbound_bytes_per_sec":
            inbound_bytes_per_second,

        "outbound_packets_per_sec":
            outbound_packets_per_second,

        "inbound_packets_per_sec":
            inbound_packets_per_second
    }

    return features