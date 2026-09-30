# DGA Detector (Member 3 module)

Streaming, metadata-only detector for algorithmically generated domains. Consumes Module 1 `dns` records,
emits Section 6 alerts (`threat_class: "DGA Domain"`).

    from sentinel_dga import DGADetector
    det = DGADetector()                                   # heuristic mode, works offline
    det = DGADetector(model_path="models/dga_model.joblib")   # ML mode after training
    alert = det.process_dns(rec)     # rec: {"domain", "src_ip", "dst_ip", ...}  -> alert dict or None
    if alert: write_alert(alert)     # sentinel-dashboard core.writer

## How it decides
Per name (second-level label): trigram "English-likeness", dictionary word coverage, consonant runs, entropy, length,
digit/hex bonus. Per host: many distinct suspicious names within 60 s (what real DGA malware does) raises confidence and
severity; a single odd name stays low. Alerts are rate-limited per host (10 s) unless severity escalates.

## Limitations (say these before the judges do)
* The bundled language model is a bootstrap (Python docs + curated word list). Retrain on real data:
  `python -m sentinel_dga.train --benign tranco.txt --dga dgarchive.txt` and report the held-out numbers.
* Dictionary-word DGAs (e.g. Suppobox: "sunnycarpet.net") look like normal words and are missed by design.
* Numbers in tools/eval_synthetic.py use synthetic strings and were tuned on them; they are a smoke test, not accuracy.
* Only the second-level label is scored; the allowlist and suffix list are small.

    python tools/eval_synthetic.py      # synthetic smoke test
    python tools/build_lm.py            # rebuild the bootstrap language model
