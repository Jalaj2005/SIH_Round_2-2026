from typing import Dict

from schemas.flow_schema import FlowRecord


# Prevent extremely large values when the denominator is zero
# or very small.
MAX_RATIO = 1000.0


def calculate_byte_ratio(flow: FlowRecord) -> float:
    """
    Calculate outbound bytes / inbound bytes.
    """

    if flow.bytes_received <= 0:

        if flow.bytes_sent > 0:
            return MAX_RATIO

        return 0.0

    ratio = flow.bytes_sent / flow.bytes_received

    if ratio > MAX_RATIO:
        return MAX_RATIO

    return ratio


def calculate_packet_ratio(flow: FlowRecord) -> float:
    """
    Calculate outbound packets / inbound packets.
    """

    if flow.packets_received <= 0:

        if flow.packets_sent > 0:
            return MAX_RATIO

        return 0.0

    ratio = flow.packets_sent / flow.packets_received

    if ratio > MAX_RATIO:
        return MAX_RATIO

    return ratio


def calculate_outbound_byte_ratio(flow: FlowRecord) -> float:
    """
    Calculate the percentage of total bytes that are outbound.
    """

    total_bytes = (
        flow.bytes_sent +
        flow.bytes_received
    )

    if total_bytes <= 0:
        return 0.0

    return flow.bytes_sent / total_bytes


def calculate_average_outbound_packet_size(
    flow: FlowRecord
) -> float:
    """
    Calculate average outbound packet size.
    """

    if flow.packets_sent <= 0:
        return 0.0

    return flow.bytes_sent / flow.packets_sent


def calculate_average_inbound_packet_size(
    flow: FlowRecord
) -> float:
    """
    Calculate average inbound packet size.
    """

    if flow.packets_received <= 0:
        return 0.0

    return flow.bytes_received / flow.packets_received


def calculate_packet_size_ratio(
    flow: FlowRecord
) -> float:
    """
    Calculate average outbound packet size /
    average inbound packet size.
    """

    outbound_size = (
        calculate_average_outbound_packet_size(flow)
    )

    inbound_size = (
        calculate_average_inbound_packet_size(flow)
    )

    if inbound_size <= 0:

        if outbound_size > 0:
            return MAX_RATIO

        return 0.0

    ratio = outbound_size / inbound_size

    if ratio > MAX_RATIO:
        return MAX_RATIO

    return ratio


def calculate_byte_rate_ratio(
    flow: FlowRecord
) -> float:
    """
    Calculate outbound byte rate /
    inbound byte rate.
    """

    if flow.duration <= 0:
        return 0.0

    outbound_rate = (
        flow.bytes_sent / flow.duration
    )

    inbound_rate = (
        flow.bytes_received / flow.duration
    )

    if inbound_rate <= 0:

        if outbound_rate > 0:
            return MAX_RATIO

        return 0.0

    ratio = outbound_rate / inbound_rate

    if ratio > MAX_RATIO:
        return MAX_RATIO

    return ratio


def calculate_ratio_features(
    flow: FlowRecord
) -> Dict[str, float]:
    """
    Calculate all ratio-based features
    for a flow.
    """

    byte_ratio = calculate_byte_ratio(flow)

    packet_ratio = calculate_packet_ratio(flow)

    outbound_byte_ratio = (
        calculate_outbound_byte_ratio(flow)
    )

    avg_outbound_packet_size = (
        calculate_average_outbound_packet_size(flow)
    )

    avg_inbound_packet_size = (
        calculate_average_inbound_packet_size(flow)
    )

    packet_size_ratio = (
        calculate_packet_size_ratio(flow)
    )

    byte_rate_ratio = (
        calculate_byte_rate_ratio(flow)
    )

    features = {
        "byte_ratio": byte_ratio,
        "packet_ratio": packet_ratio,
        "outbound_byte_ratio": outbound_byte_ratio,
        "avg_outbound_packet_size":
            avg_outbound_packet_size,
        "avg_inbound_packet_size":
            avg_inbound_packet_size,
        "packet_size_ratio":
            packet_size_ratio,
        "byte_rate_ratio":
            byte_rate_ratio
    }

    return features