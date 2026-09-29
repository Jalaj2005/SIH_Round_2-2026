from ipaddress import ip_address
from typing import Dict

from schemas.flow_schema import FlowRecord


def is_external_destination(flow: FlowRecord) -> int:
    """
    Returns:
        1 -> destination is external
        0 -> destination is private/internal
    """

    try:
        ip = ip_address(flow.dst_ip)

        if ip.is_private:
            return 0

        return 1

    except ValueError:
        return 0


def destination_seen_before(flow: FlowRecord) -> int:
    """
    Returns whether the destination has been seen before.

    For now, this uses the value supplied by the upstream pipeline.
    If the value is unavailable, returns 0.

    Returns:
        1 -> destination was seen before
        0 -> destination is new/not seen before
    """

    if flow.destination_seen_before is True:
        return 1

    return 0


def destination_novelty(flow: FlowRecord) -> int:
    """
    Indicates whether the destination is new.

    Returns:
        1 -> new destination
        0 -> previously seen destination
    """

    if flow.destination_seen_before is False:
        return 1

    return 0


def calculate_destination_features(flow: FlowRecord) -> Dict[str, float]:
    """
    Extract destination-related features from a flow.
    """

    external = is_external_destination(flow)

    seen_before = destination_seen_before(flow)

    novelty = destination_novelty(flow)

    features = {
        "destination_is_external": external,
        "destination_seen_before": seen_before,
        "destination_novelty": novelty
    }

    return features