"""Periodicity detection (Lomb-Scargle) + small stat helpers."""
import math

import numpy as np
from scipy.signal import lombscargle


def shannon_counts(counts, total=None):
    total = total or sum(counts)
    if total <= 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def shannon_str(s):
    if not s:
        return 0.0
    cnt = {}
    for ch in s:
        cnt[ch] = cnt.get(ch, 0) + 1
    return shannon_counts(cnt.values(), len(s))


_EMPTY = {"ls_peak_power": 0.0, "ls_peak_period_s": 0.0, "ls_snr": 0.0, "ls_n_events": 0}


def periodicity(times, n_freq=256, max_bins=4096):
    """Lomb-Scargle on the binned event-count series of `times` (seconds, ascending).

    ls_peak_power in [0,1] (normalized periodogram); ls_snr = peak / median power.
    Beacons with jitter still produce a clear peak; Poisson traffic does not.
    """
    n = len(times)
    if n < 8:
        return dict(_EMPTY, ls_n_events=n)
    t = np.asarray(times, dtype=np.float64)
    t = t - t[0]
    span = t[-1]
    if span <= 0:
        return dict(_EMPTY, ls_n_events=n)
    med = float(np.median(np.diff(t)))
    dt = max(med / 4.0, span / max_bins, 1e-6)
    nb = int(span / dt) + 1
    y = np.bincount((t / dt).astype(np.int64), minlength=nb).astype(np.float64)
    y -= y.mean()
    if not y.any():
        return dict(_EMPTY, ls_n_events=n)
    tc = (np.arange(nb) + 0.5) * dt
    f = np.geomspace(2.0 / span, 1.0 / (2 * dt), n_freq)
    p = lombscargle(tc, y, 2 * np.pi * f, normalize=True)
    k = int(np.argmax(p))
    return {"ls_peak_power": float(p[k]), "ls_peak_period_s": float(1.0 / f[k]),
            "ls_snr": float(p[k] / (np.median(p) + 1e-12)), "ls_n_events": n}
