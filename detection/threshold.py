class ExfiltrationThresholds:

    # Host behaviour thresholds
    OUTBOUND_BASELINE_RATIO = 10.0
    BASELINE_DEVIATION = 3.0
    TRANSFER_RATE_BASELINE_RATIO = 5.0

    # Flow behaviour thresholds
    BYTE_RATIO = 20.0

    # Window behaviour thresholds
    BURST_COUNT = 2

    # Destination behaviour
    NEW_EXTERNAL_DESTINATION = True

    # Risk score weights
    OUTBOUND_BASELINE_WEIGHT = 30
    BYTE_RATIO_WEIGHT = 20
    BASELINE_DEVIATION_WEIGHT = 20
    TRANSFER_RATE_WEIGHT = 15
    BURST_WEIGHT = 15
    DESTINATION_WEIGHT = 10

    # Final detection threshold
    DETECTION_SCORE = 60