from typing import Dict


def calculate_ratio(
    current_value: float,
    baseline_value: float
) -> float:
    """
    Calculates how many times the current value
    is compared to the historical baseline.

    Example:
        current = 800 MB
        baseline = 20 MB

        ratio = 40
    """

    if baseline_value <= 0:
        return 0.0

    return current_value / baseline_value


def calculate_deviation(
    current_value: float,
    baseline_mean: float,
    baseline_std: float
) -> float:
    """
    Calculates how far the current value is from
    the historical mean using standard deviation.

    Formula:

        deviation =
        (current - mean) / standard_deviation

    The absolute value is returned because we are
    interested in how abnormal the value is.
    """

    if baseline_std <= 0:
        return 0.0

    deviation = (
        current_value - baseline_mean
    ) / baseline_std

    return abs(deviation)


def calculate_outbound_baseline_ratio(
    current_outbound_bytes: float,
    historical_avg_outbound_bytes: float
) -> float:
    """
    Calculates the current outbound traffic relative
    to the historical average outbound traffic.
    """

    return calculate_ratio(
        current_outbound_bytes,
        historical_avg_outbound_bytes
    )


def calculate_transfer_rate_ratio(
    current_transfer_rate: float,
    historical_avg_transfer_rate: float
) -> float:
    """
    Calculates how much larger the current transfer
    rate is compared with the historical average.
    """

    return calculate_ratio(
        current_transfer_rate,
        historical_avg_transfer_rate
    )


def calculate_baseline_features(
    current_outbound_bytes: float,
    current_transfer_rate: float,

    historical_avg_outbound_bytes: float,
    historical_std_outbound_bytes: float,

    historical_avg_transfer_rate: float
) -> Dict[str, float]:
    """
    Calculates all baseline-related features.

    Parameters
    ----------
    current_outbound_bytes:
        Outbound bytes observed in the current window.

    current_transfer_rate:
        Current outbound transfer rate.

    historical_avg_outbound_bytes:
        Average outbound bytes for this host
        from historical observations.

    historical_std_outbound_bytes:
        Standard deviation of historical outbound bytes.

    historical_avg_transfer_rate:
        Historical average outbound transfer rate.
    """

    baseline_deviation = calculate_deviation(
        current_outbound_bytes,
        historical_avg_outbound_bytes,
        historical_std_outbound_bytes
    )

    outbound_vs_baseline_ratio = (
        calculate_outbound_baseline_ratio(
            current_outbound_bytes,
            historical_avg_outbound_bytes
        )
    )

    transfer_rate_vs_baseline = (
        calculate_transfer_rate_ratio(
            current_transfer_rate,
            historical_avg_transfer_rate
        )
    )

    features = {
        "baseline_deviation": baseline_deviation,

        "outbound_vs_baseline_ratio":
            outbound_vs_baseline_ratio,

        "transfer_rate_vs_baseline":
            transfer_rate_vs_baseline
    }

    return features