"""FFT-PCC: deteksi *kandidat* periodic noise (Eq. 4-6, Algoritma 1 langkah 1-7).

Periodisitas hanya SINYAL KANDIDAT untuk noise operasional berisiko rendah, bukan syarat cukup
untuk membuang alert (beaconing/low-and-slow juga periodik). Keputusan akhir ada di risk gate.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

import numpy as np


@dataclass
class PeriodicityResult:
    periodic: bool
    reason: str
    n: int = 0
    peak_ratio: float = 0.0
    k_star: int | None = None
    period_hours: int | None = None
    pcc: float | None = None
    segments: int = 0

    def to_dict(self):
        d = asdict(self)
        for k in ("peak_ratio", "pcc"):
            if d[k] is not None:
                d[k] = round(float(d[k]), 4)
        return d


def pairwise_mean_pearson(x: np.ndarray, period: int) -> tuple[float, int]:
    """Eq. 6: rata-rata Pearson seluruh pasangan subsekuens u<v (panjang = period)."""
    m = len(x) // period
    if m < 2:
        return 0.0, m
    segs = x[: m * period].reshape(m, period).astype(float)
    vals = []
    for u in range(m):
        for v in range(u + 1, m):
            a, b = segs[u], segs[v]
            if a.std() == 0 or b.std() == 0:  # korelasi tak terdefinisi -> 0 (konservatif)
                vals.append(0.0)
            else:
                vals.append(float(np.corrcoef(a, b)[0, 1]))
    return float(np.mean(vals)), m


def analyze(series, peak_ratio_min: float = 3.0, pcc_min: float = 0.85, min_period: int = 2,
            max_period: int = 72, min_history: int = 48, eps: float = 1e-9) -> PeriodicityResult:
    x = np.asarray(series, dtype=float)
    n = len(x)
    if n < min_history:
        return PeriodicityResult(False, "insufficient_history", n=n)
    if np.allclose(x, x[0]):
        return PeriodicityResult(False, "constant_series", n=n)

    spec = np.abs(np.fft.rfft(x))
    amps = spec[1:]                      # komponen frekuensi nol dibuang
    ks = np.arange(1, len(spec))
    periods = n / ks
    in_range = (periods >= min_period) & (periods <= max_period)
    if not in_range.any():
        return PeriodicityResult(False, "no_frequency_in_period_range", n=n)

    # puncak dominan dicari pada rentang periode operasional 2-72 jam
    idx = np.where(in_range)[0][np.argmax(amps[in_range])]
    k_star = int(ks[idx])
    others = np.delete(amps, idx)
    mean_other = float(others.mean()) if len(others) else 0.0
    rho = float(amps[idx] / (mean_other + eps))
    period = int(round(n / k_star))

    if rho < peak_ratio_min:
        return PeriodicityResult(False, "peak_not_dominant", n, rho, k_star, period)
    # Penyempurnaan: N streaming jarang kelipatan periode, sehingga round(N/k*) bisa meleset 1-4 jam.
    # Uji semua periode bulat yang dipetakan ke bin k* (N/(k*+0.5) .. N/(k*-0.5)), pilih PCC terbaik.
    lo = max(min_period, int(np.floor(n / (k_star + 0.5))))
    hi = min(max_period, int(np.ceil(n / max(k_star - 0.5, 0.5))))
    if lo > hi:
        return PeriodicityResult(False, "period_out_of_range", n, rho, k_star, period)
    best_p, best_r, best_m = period, -2.0, 0
    for cand in range(lo, hi + 1):
        r_c, m_c = pairwise_mean_pearson(x, cand)
        if m_c >= 2 and r_c > best_r:
            best_p, best_r, best_m = cand, r_c, m_c
    if best_m < 2:
        return PeriodicityResult(False, "too_few_cycles", n, rho, k_star, period, None, best_m)
    if best_r <= pcc_min:
        return PeriodicityResult(False, "pcc_below_threshold", n, rho, k_star, best_p, best_r, best_m)
    return PeriodicityResult(True, "periodic_candidate", n, rho, k_star, best_p, best_r, best_m)
