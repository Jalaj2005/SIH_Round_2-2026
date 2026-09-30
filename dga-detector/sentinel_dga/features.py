"""Lexical features of the second-level label. Metadata only: no payload, no external lookups."""
from __future__ import annotations
import json
import math
from collections import Counter
from functools import lru_cache
from pathlib import Path

DATA = Path(__file__).parent / "data"
_MULTI_SUFFIX = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "net.in", "org.in",
                 "gov.in", "ac.in", "nic.in", "co.jp", "com.br", "com.cn", "co.za", "com.mx", "co.nz", "com.sg", "com.tr"}
_VOWELS = set("aeiou")
_V = 38.0    # a-z, 0-9, '-', boundary
_K = 0.05    # add-k smoothing

FEATURES = ["length", "entropy", "vowel_ratio", "digit_ratio", "max_consonant_run", "max_digit_run", "hyphens",
            "unique_ratio", "trigram_logp", "word_coverage", "hex_like", "digit_letter_switches"]


@lru_cache(maxsize=1)
def _words() -> frozenset:
    return frozenset((DATA / "words.txt").read_text(encoding="utf-8").split())


@lru_cache(maxsize=1)
def _lm() -> dict:
    raw = json.loads((DATA / "lm.json").read_text(encoding="utf-8"))
    return {ctx: (dict(nxt), sum(nxt.values())) for ctx, nxt in raw.items()}


def reload_language_model() -> None:
    _words.cache_clear()
    _lm.cache_clear()


def split_domain(fqdn: str) -> tuple[str, str, str]:
    """-> (sld label, public suffix, subdomain). Naive suffix handling with a small multi-part list."""
    labels = fqdn.lower().strip().rstrip(".").split(".")
    if len(labels) < 2:
        return labels[0], "", ""
    n = 2 if ".".join(labels[-2:]) in _MULTI_SUFFIX and len(labels) > 2 else 1
    return labels[-n - 1], ".".join(labels[-n:]), ".".join(labels[:-n - 1])


def trigram_logp(s: str) -> float:
    """Mean natural-log probability per character under the English-like trigram model (higher = more word-like)."""
    lm, ctx, total = _lm(), "^^", 0.0
    for ch in s + "$":
        nxt, tot = lm.get(ctx, ({}, 0.0))
        total += math.log((nxt.get(ch, 0.0) + _K) / (tot + _K * _V))
        ctx = ctx[1] + ch
    return total / (len(s) + 1)


def word_coverage(s: str) -> float:
    """Share of characters explained by dictionary words (min length 3), via DP segmentation."""
    words, n = _words(), len(s)
    best = [0] * (n + 1)
    for i in range(1, n + 1):
        best[i] = best[i - 1]
        for length in range(3, min(i, 15) + 1):
            if s[i - length:i] in words:
                best[i] = max(best[i], best[i - length] + length)
    return best[n] / n if n else 0.0


def _max_run(s: str, pred) -> int:
    best = cur = 0
    for ch in s:
        cur = cur + 1 if pred(ch) else 0
        best = max(best, cur)
    return best


@lru_cache(maxsize=100_000)
def extract_features(sld: str) -> dict:
    n = max(len(sld), 1)
    counts = Counter(sld)
    letters = [c for c in sld if c.isalpha()]
    return {
        "length": float(len(sld)),
        "entropy": -sum(c / n * math.log2(c / n) for c in counts.values()),
        "vowel_ratio": sum(c in _VOWELS for c in sld) / n,
        "digit_ratio": sum(c.isdigit() for c in sld) / n,
        "max_consonant_run": float(_max_run(sld, lambda c: c.isalpha() and c not in _VOWELS)),
        "max_digit_run": float(_max_run(sld, str.isdigit)),
        "hyphens": float(sld.count("-")),
        "unique_ratio": len(counts) / n,
        "trigram_logp": trigram_logp(sld),
        "word_coverage": word_coverage("".join(letters)) * len(letters) / n if letters else 0.0,
        "hex_like": float(len(sld) >= 12 and all(c in "0123456789abcdef" for c in sld)),
        "digit_letter_switches": float(sum(a.isdigit() != b.isdigit() for a, b in zip(sld, sld[1:]))),
    }
