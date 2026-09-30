# Vigilant: Passive Network Threat Detection

Vigilant is a passive network-traffic analysis prototype. Module 1 parses packet captures into metadata records, eight detector modules analyze those records, and the Vigilant Streamlit dashboard displays normalized alerts and pipeline telemetry.

The system is intended for demonstrations and development. Detection thresholds and bundled sample data are not a substitute for validation against representative, labeled production traffic.

## Architecture

```text
PCAP / PCAPNG
    |
    v
Module 1: capture, parse, build flows, extract features, dispatch records
    |
    +--> C2 beacon detector
    +--> DDoS detector
    +--> DGA detector
    +--> DNS tunnelling detector
    +--> Data exfiltration detector
    +--> Reconnaissance / port-scan detector
    +--> Threat-intelligence fusion
    +--> TLS malware classifier
    |
    v
Dashboard pipeline: normalize alerts and write telemetry
    |
    +--> alerts.jsonl (append-only)
    +--> telemetry.json (atomic snapshot)
    |
    v
Vigilant Streamlit dashboard
```

Module 1 emits DNS and TLS records as they are observed, periodic traffic-window records, and flow records when flows close or expire. The dispatcher routes each record type to the appropriate consumers. The dashboard-side runner connects the available detectors and writes the dashboard's Section 6 alert format.

## Modules

| Directory | Role |
|---|---|
| `packet-parser-feature-extraction/` | Passive packet capture/replay, parsing, flow construction, feature extraction, and dispatch. |
| `c2-beacon-module/` | Periodic command-and-control beacon detection. |
| `DDos_Detector/` | Multi-signal DDoS detection from traffic windows. |
| `dga-detector/` | Algorithmically generated domain detection from DNS records. |
| `dns-tunnel-detector/` | DNS tunnelling detection from encoded-label patterns, uniqueness, cadence, and query type. |
| `exfiltration-detection/` | Rule/threshold-based data-exfiltration detection from flow features. |
| `recon-detector/` | Horizontal and vertical scan detection. |
| `threat-intel-fusion/` | Local IoC lookups, early alerts, and confidence fusion. |
| `tls-malware-detection/` | TLS flow classifier and serialized model. |
| `vigilant-dashboard/` | Vigilant Streamlit operations dashboard and integrated PCAP replay runner. |

Each module also contains its own documentation or tests where applicable; see its README for module-specific details.

## Requirements

- Python 3.10 or newer.
- Install dependencies from the repository root into a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate              # Linux/macOS
# Windows Git Bash: source .venv/Scripts/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r vigilant-dashboard/requirements.txt
```

The dashboard requirements include dependencies used by the integrated replay path, including Streamlit, pandas, packet parsing, numerical features, and the TLS model runtime.

## Run the Dashboard

From the repository root:

```bash
python -m streamlit run vigilant-dashboard/app.py
```

By default, `VIGILANT_MODE` is `mock`; the dashboard generates synthetic alerts and telemetry for UI demonstrations. Set `VIGILANT_MODE=file` to have it read files written by the integrated pipeline. Existing `SENTINEL_*` environment variables remain supported as fallbacks.

## Run the Integrated PCAP Demo

The easiest way to exercise all detectors is to generate the bundled mixed-traffic capture. This writes only local demo output:

```bash
mkdir -p demo-output
python -c "import sys; sys.path.insert(0, 'packet-parser-feature-extraction/tools'); import traffic; traffic.write_pcap('demo-output/demo.pcap', traffic.scenario_mix())"
```

Use two terminals from the repository root. In Terminal 1, start the dashboard in file mode:

```bash
export VIGILANT_MODE=file
python -m streamlit run vigilant-dashboard/app.py --server.port 8502
```

In Terminal 2, run one replay:

```bash
python vigilant-dashboard/run_pipeline.py demo-output/demo.pcap
```

For a continuously changing demo, replay the capture repeatedly:

```bash
python vigilant-dashboard/run_pipeline.py demo-output/demo.pcap --loop
```

The dashboard refreshes from its configured files; the runner is the process that produces changes. Press `Ctrl+C` in the replay terminal to stop replaying, and leave the Streamlit terminal running. Open the local URL printed by Streamlit.

The runner writes by default to `vigilant-dashboard/data/alerts.jsonl` and `vigilant-dashboard/data/telemetry.json`. To use different paths, set `VIGILANT_ALERTS_FILE` and `VIGILANT_TELEMETRY_FILE` to the same values for both the dashboard and runner processes. Other settings include `VIGILANT_REFRESH` and `VIGILANT_IOC_DB`.

## Tests

Run the dashboard and integration tests from the repository root:

```bash
python -m pytest vigilant-dashboard/tests -q
```

Module-specific tests and commands are documented in each module. Some test suites expect to be run from their module directory so that its package is on the Python import path.

## Data and Security

- The parser is designed for passive metadata analysis; the integrated PCAP runner replays files and does not capture live interfaces.
- Module 1 has a separate Linux `AF_PACKET` receive-only capture path. Live capture requires an appropriate RX-only tap/SPAN setup and platform privileges; it is not enabled by the dashboard replay runner.
- The threat-intel module starts with a small offline sample feed. Configure a persistent IoC database and import an appropriate feed for longer-running use.
- Treat PCAP files, alerts, IP addresses, IoCs, and telemetry as potentially sensitive. Do not publish real runtime data in a public repository or unauthenticated dashboard.
- The bundled DGA language model and synthetic capture are demo/test material. Tune and evaluate detectors with representative labeled data before operational use.
- The parser's measured throughput depends on hardware and workload; the module documentation records known performance limits and parser gaps.

For a shareable mock-data demo, a Streamlit-hosted dashboard can be sufficient. Running the integrated dashboard and replay worker continuously requires a host where both processes can share persistent files; Vercel is not designed for this Streamlit-plus-worker arrangement.
