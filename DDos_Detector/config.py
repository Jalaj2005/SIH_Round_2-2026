"""
All thresholds, scoring weights, and baseline settings are externalized here.
Zero hardcoded magic numbers in detection logic.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class DDoSDetectorConfig:
    # --- Multi-Signal Weights (Sum to 1.0) ---
    rate_weight: float = 0.25
    source_weight: float = 0.20
    tcp_weight: float = 0.20
    udp_weight: float = 0.15
    temporal_weight: float = 0.10
    persistence_weight: float = 0.10

    # --- Baseline Configuration ---
    baseline_window_size: int = 30
    minimum_samples_for_baseline: int = 5
    default_baseline_pps: float = 1000.0
    rate_deviation_threshold: float = 3.0  # Z-score cutoff for abnormal rate

    # --- Protocol Anomalies ---
    syn_rate_threshold: float = 2000.0
    syn_ack_ratio_threshold: float = 5.0
    syn_percentage_threshold: float = 0.70
    udp_packet_rate_threshold: float = 3000.0
    udp_percentage_threshold: float = 0.75
    udp_asymmetry_ratio_threshold: float = 4.0

    # --- Source Dispersion Anomalies ---
    entropy_high_threshold: float = 6.5
    top_source_percentage_threshold: float = 0.60
    spoofed_fanout_threshold: float = 50.0  # unique sources per target destination

    # --- Temporal Persistence ---
    persistence_window_count: int = 3
    score_decay: float = 0.65

    # --- Severity Cutoffs ---
    severity_low_cutoff: float = 0.45
    severity_med_cutoff: float = 0.65
    severity_high_cutoff: float = 0.82
    severity_crit_cutoff: float = 0.92