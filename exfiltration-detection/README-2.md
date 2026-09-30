# SIH Phase 2 - Exfiltration Detection Module

A prototype passive network-traffic analysis module for detecting behavior that may indicate **data exfiltration** from a monitored host.

This module is designed as part of a larger cybersecurity threat-detection pipeline. It works on flow-level network metadata and does **not** inspect encrypted payload contents or actively interact with network endpoints.

## Overview

The exfiltration detector analyzes network-flow behavior using:

- Outbound and inbound traffic volume
- Packet and byte ratios
- Transfer rates
- Destination characteristics
- Transfer timing and bursts
- Historical host baselines
- Explicit detection thresholds
- Evidence generation
- Standardized security alerts

The current implementation is a **rule/threshold-based prototype**. An ML-based classifier can be integrated later after a suitable labeled dataset and evaluation pipeline are available.

## Detection Pipeline

```text
Network Traffic
      |
      v
Flow Records
      |
      v
Window Manager
      |
      v
Feature Extraction
      |
      +-----------------------------+
      |                             |
      v                             v
Volume / Ratio Features      Destination Features
      |                             |
      +-------------+---------------+
                    |
                    v
             Temporal Features
                    |
                    v
              Host Baseline
                    |
                    v
          Threshold-Based Detection
                    |
                    v
             Evidence Generator
                    |
                    v
               Alert Builder
                    |
                    v
          Main Threat Correlation
                    |
                    v
                Dashboard
```

## Project Structure

```text
sih_phase2/
|
├── alerts/
│   └── alert_builder.py
|
├── baseline/
│   └── host_baseline.py
|
├── detection/
│   ├── exfiltration_detector.py
│   └── threshold.py
|
├── evidence/
│   └── evidence_generator.py
|
├── features/
│   ├── baseline_features.py
│   ├── destination_features.py
│   ├── features_pipeline.py
│   ├── ratio_features.py
│   ├── temporal_features.py
│   └── volume_features.py
|
├── schemas/
│   └── flow_schema.py
|
└── windows/
    └── windows_manager.py
```

## Module Responsibilities

### `schemas/`

Defines the standard structure of incoming flow records, including flow ID, timestamp, IP addresses, ports, protocol, duration, bytes, and packets.

### `windows/`

Maintains time-based flow windows so that traffic can be analyzed using temporal and multi-flow context instead of isolated packets.

### `features/`

Extracts indicators used by the detector.

**Volume features**
- Outbound/inbound bytes
- Total bytes
- Outbound/inbound packets
- Bytes per second
- Packets per second

**Ratio features**
- Outbound/inbound byte ratio
- Outbound/inbound packet ratio
- Outbound byte percentage
- Average packet-size ratio
- Byte-rate ratio

**Destination features**
- External destination
- Previously observed destination
- Destination novelty

**Temporal features**
- Transfer count
- Transfers per minute
- Mean inter-transfer time
- Inter-transfer-time deviation
- Burst activity
- Time of day

**Baseline features**
- Outbound traffic versus historical average
- Baseline deviation
- Transfer-rate deviation

### `baseline/`

Maintains historical traffic characteristics for a host and provides context for identifying unusual outbound behavior.

### `detection/`

Applies explicit thresholds to the extracted features and produces a potential exfiltration decision.

### `evidence/`

Converts suspicious feature values into human-readable explanations for an alert.

### `alerts/`

Builds standardized alert records for integration with the larger threat-detection pipeline.

## Detection Logic

The prototype combines multiple behavioral signals rather than treating large outbound traffic alone as proof of exfiltration.

```text
High outbound volume
        +
High outbound/inbound ratio
        +
Large baseline deviation
        +
New external destination
        +
Abnormal transfer pattern
        |
        v
Potential Data Exfiltration
```

Legitimate backups, synchronization, and file transfers can also generate high outbound traffic, so multiple signals and baseline context are important.

## Alert Format

Example standardized alert:

```json
{
  "timestamp": "2026-09-30T08:00:00",
  "flow_id": "F10291",
  "threat_class": "DATA_EXFILTRATION",
  "confidence": 0.93,
  "severity": "HIGH",
  "source_ip": "10.0.0.42",
  "destination_ip": "185.x.x.x",
  "evidence": [
    "High outbound volume",
    "High outbound/inbound byte ratio",
    "Traffic significantly exceeds baseline",
    "New external destination"
  ]
}
```

## Design Principles

### Passive Analysis
Analyzes observed traffic without actively communicating with endpoints.

### Metadata-Based Detection
Uses flow metadata and behavioral characteristics rather than application payload contents.

### Encrypted-Traffic Compatible
Does not require TLS or QUIC payload decryption.

### Streaming-Oriented
Uses flow aggregation and time windows instead of requiring a complete batch before analysis.

### Explainable Alerts
Produces supporting evidence with detection results.

## Current Prototype Scope

The current version includes:

- Flow-level processing
- Time-window aggregation
- Feature extraction
- Host baseline comparison
- Explicit threshold-based detection
- Evidence generation
- Standardized alert construction

## Future ML Extension

An ML model can later be added as an additional detection layer:

```text
Features
   |
   +----> Rule/Threshold Detector
   |
   +----> ML Detector
              |
              v
       Combined Decision
              |
              v
            Alert
```

The current prototype intentionally uses explicit thresholds so that the feature pipeline and detection logic can be validated before introducing a trained model.

## Integration

The module is intended to receive standardized flow records from an upstream traffic-processing pipeline:

```text
Packet Capture / Traffic Source
              |
              v
        Packet Parser
              |
              v
        Flow Aggregator
              |
              v
     Exfiltration Module
              |
              v
      Correlation Engine
              |
              v
          Dashboard
```

The exfiltration module should operate on flow records rather than independently parsing the same raw packets again.

## Limitations

This is a prototype detection module. It does not:

- Read or reconstruct stolen file contents
- Decrypt TLS/QUIC payloads
- Actively probe remote systems
- Block network traffic inline
- Prove that a transfer is malicious solely from volume
- Replace investigation by a security analyst

The module identifies **behavior consistent with possible data exfiltration** based on observable traffic characteristics.

## Future Improvements

- ML-based classification
- More robust host profiling
- Destination reputation integration
- Sliding-window analysis
- Adaptive thresholds
- Improved burst detection
- Cross-flow correlation
- Historical alert correlation
- False-positive evaluation
- Precision, recall, and F1-score evaluation
- Dashboard integration

## Technologies

- **Python**
- **Pydantic** for flow-data validation
- Standard Python libraries for feature calculations
- **Git/GitHub** for version control

## Status

**Prototype - SIH Phase 2**

The current implementation establishes the feature extraction, baseline, windowing, threshold detection, evidence, and alert-generation pipeline for the exfiltration detection layer.
