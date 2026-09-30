"""Train the ML scorer on REAL data (recommended before the demo).
    python -m sentinel_dga.train --benign tranco_top1m.txt --dga dgarchive_domains.txt --out models/dga_model.joblib
Input files: one domain per line (a Tranco CSV 'rank,domain' also works). Output uses the same artifact convention as
the TLS malware module: {"model", "features", "threshold", "model_name"}."""
import argparse
import random
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from sentinel_dga.features import FEATURES, extract_features, split_domain


def load(path: str, limit: int) -> list[str]:
    out = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        d = line.strip().split(",")[-1].strip().lower()
        if "." in d:
            sld = split_domain(d)[0]
            if len(sld) >= 7:
                out.append(sld)
    random.Random(1).shuffle(out)
    return out[:limit]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--benign", required=True)
    ap.add_argument("--dga", required=True)
    ap.add_argument("--out", default="models/dga_model.joblib")
    ap.add_argument("--limit", type=int, default=200_000)
    a = ap.parse_args(argv)

    benign, dga = load(a.benign, a.limit), load(a.dga, a.limit)
    X = pd.DataFrame([[extract_features(s)[k] for k in FEATURES] for s in benign + dga], columns=FEATURES)
    y = np.array([0] * len(benign) + [1] * len(dga))
    Xtr, Xtmp, ytr, ytmp = train_test_split(X, y, test_size=0.3, stratify=y, random_state=7)
    Xval, Xte, yval, yte = train_test_split(Xtmp, ytmp, test_size=0.5, stratify=ytmp, random_state=7)

    model = HistGradientBoostingClassifier(max_depth=6, learning_rate=0.08, max_iter=250, class_weight="balanced",
                                           random_state=7).fit(Xtr, ytr)
    pv = model.predict_proba(Xval)[:, 1]
    thr = max(np.arange(0.10, 0.91, 0.01), key=lambda t: f1_score(yval, pv >= t, zero_division=0))
    pt = model.predict_proba(Xte)[:, 1]
    pred = pt >= thr
    print(f"threshold {thr:.2f} | TEST precision {precision_score(yte, pred):.4f} recall {recall_score(yte, pred):.4f} "
          f"F1 {f1_score(yte, pred):.4f} ROC-AUC {roc_auc_score(yte, pt):.4f}")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES, "threshold": float(thr), "model_name": "HistGradientBoosting"}, a.out)
    print("saved", a.out)


if __name__ == "__main__":
    main()
