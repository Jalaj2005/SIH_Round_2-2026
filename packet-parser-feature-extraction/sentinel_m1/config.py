from dataclasses import dataclass


@dataclass
class Config:
    # --- flow builder ---
    idle_timeout: float = 15.0       # seconds without packets -> flow expires
    active_timeout: float = 120.0    # long-lived flows are cut into segments
    closed_grace: float = 2.0        # keep FIN/RST'd flows briefly so trailing ACKs join them
    max_flows: int = 500_000         # hard memory bound (spoofed-source floods!)
    # --- per-flow feature extraction ---
    splt_n: int = 20                 # first N payload packets for SPLT
    iat_seq_len: int = 128           # how many raw IATs to ship in the vector
    max_flow_times: int = 512        # timestamps kept per flow for spectral analysis
    ls_min_events: int = 12          # min packets/connections before Lomb-Scargle is computed
    # --- windowed (DDoS / scan / DNS-velocity) features ---
    window_s: float = 1.0
    min_window_pkts: int = 5         # suppress window records for near-idle keys
    max_window_keys: int = 400_000
    # --- beacon (repeated connection) tracker ---
    pair_history: int = 256
    max_pairs: int = 200_000
    # --- misc ---
    tick_every: int = 512            # packets between dispatcher time-based flushes
