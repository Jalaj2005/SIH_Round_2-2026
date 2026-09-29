from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class FlowRecord(BaseModel):
    """
    Represents one network flow received by the
    Data Exfiltration Detection Layer.
    """

    # -----------------------------
    # Flow identification
    # -----------------------------

    flow_id: str = Field(..., description="Unique identifier for the flow")

    timestamp: datetime = Field(
        ...,
        description="Timestamp when the flow was observed"
    )

    # -----------------------------
    # Network information
    # -----------------------------

    src_ip: str = Field(..., description="Source IP address")

    dst_ip: str = Field(..., description="Destination IP address")

    src_port: Optional[int] = Field(
        None,
        ge=0,
        le=65535,
        description="Source port"
    )

    dst_port: Optional[int] = Field(
        None,
        ge=0,
        le=65535,
        description="Destination port"
    )

    protocol: str = Field(
        ...,
        description="Network protocol such as TCP, UDP, ICMP"
    )

    # -----------------------------
    # Flow statistics
    # -----------------------------

    duration: float = Field(
        ...,
        ge=0,
        description="Flow duration in seconds"
    )

    bytes_sent: int = Field(
        ...,
        ge=0,
        description="Bytes sent from source to destination"
    )

    bytes_received: int = Field(
        ...,
        ge=0,
        description="Bytes received from destination to source"
    )

    packets_sent: int = Field(
        ...,
        ge=0,
        description="Packets sent from source to destination"
    )

    packets_received: int = Field(
        ...,
        ge=0,
        description="Packets received from destination to source"
    )

    # -----------------------------
    # Optional packet statistics
    # -----------------------------

    avg_packet_size_sent: Optional[float] = Field(
        None,
        ge=0,
        description="Average outbound packet size in bytes"
    )

    avg_packet_size_received: Optional[float] = Field(
        None,
        ge=0,
        description="Average inbound packet size in bytes"
    )

    # -----------------------------
    # Destination context
    # -----------------------------

    destination_is_external: Optional[bool] = Field(
        None,
        description="Whether destination is outside the monitored network"
    )

    destination_seen_before: Optional[bool] = Field(
        None,
        description="Whether this destination was previously observed"
    )