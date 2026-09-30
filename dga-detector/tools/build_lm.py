"""Builds sentinel_dga/data/{words.txt,lm.json} from (a) Python's bundled doc text and (b) tools/curated_vocab.txt.
This is only a BOOTSTRAP so the detector works offline. For production, retrain with real data:
    python -m sentinel_dga.train --benign tranco_top1m.txt --dga dgarchive.txt"""
import collections
import json
import math
import re
from pathlib import Path

import pydoc_data.topics as topics

HERE = Path(__file__).parent
OUT = HERE.parent / "sentinel_dga" / "data"

counts = collections.Counter(re.findall(r"[a-z]{3,15}", " ".join(topics.topics.values()).lower()))
words = {w: c for w, c in counts.items() if c >= 2}
for w in (HERE / "curated_vocab.txt").read_text().split():
    if w.isalpha() and len(w) >= 2:
        words[w] = words.get(w, 0) + 25          # curated tokens count as well-attested

(OUT / "words.txt").write_text("\n".join(sorted(w for w in words if len(w) >= 3)), encoding="utf-8")

tri = collections.defaultdict(collections.Counter)
for w, c in words.items():
    weight = math.log1p(c)
    s = "^^" + w + "$"
    for i in range(2, len(s)):
        tri[s[i - 2:i]][s[i]] += weight
(OUT / "lm.json").write_text(json.dumps({k: {c: round(n, 3) for c, n in v.items()} for k, v in tri.items()}),
                             encoding="utf-8")
print(f"{len(words)} vocabulary entries, {len(tri)} trigram contexts")
