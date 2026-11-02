"""Bagian pelatihan BERT yang TIDAK butuh torch: split bebas-kebocoran, metrik, kalibrasi ambang. Diuji otomatis."""
from __future__ import annotations

import numpy as np


def split_indices(triplets: list[str], times: list[float], mode: str = "triplet", seed: int = 7, frac=(0.7, 0.1, 0.2)):
    """mode='triplet': semua alert satu triplet masuk SATU split (mencegah kebocoran pola periodik, Tabel 9 paper).
    mode='chronological': 70% waktu awal / 10% / 20% akhir (uji generalisasi temporal)."""
    n = len(triplets)
    if mode == "chronological":
        order = np.argsort(times, kind="stable")
        a, b = round(n * frac[0]), round(n * (frac[0] + frac[1]))
        return order[:a].tolist(), order[a:b].tolist(), order[b:].tolist()
    uniq = sorted(set(triplets))
    rng = np.random.default_rng(seed)
    rng.shuffle(uniq)
    a, b = round(len(uniq) * frac[0]), round(len(uniq) * (frac[0] + frac[1]))
    bucket = {t: 0 if i < a else 1 if i < b else 2 for i, t in enumerate(uniq)}
    out: list[list[int]] = [[], [], []]
    for i, t in enumerate(triplets):
        out[bucket[t]].append(i)
    return tuple(out)


def roc_auc(y: np.ndarray, s: np.ndarray) -> float:
    """AUC via statistik peringkat (Mann-Whitney) dengan penanganan ties."""
    y, s = np.asarray(y), np.asarray(s, dtype=float)
    pos, neg = (y == 1).sum(), (y == 0).sum()
    if pos == 0 or neg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s)); sorted_s = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def metrics(y, p, thr: float = 0.5) -> dict:
    """Kelas positif = FALSE-POSITIVE alert (konvensi paper). FPR = true alert yang salah diprediksi false-positive,
    yaitu risiko operasional utama (alert asli dibuang)."""
    y, p = np.asarray(y), np.asarray(p, dtype=float)
    pred = (p >= thr).astype(int)
    tp, fp = int(((pred == 1) & (y == 1)).sum()), int(((pred == 1) & (y == 0)).sum())
    fn, tn = int(((pred == 0) & (y == 1)).sum()), int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"accuracy": (tp + tn) / max(len(y), 1), "precision": prec, "recall": rec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "auc": roc_auc(y, p), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def calibrate_threshold(y, p, max_true_alert_loss: float = 0.005) -> float:
    """Ambang false-positive TERENDAH-risiko: pilih ambang p(FP) terkecil sehingga persentase TRUE alert yang salah dibuang <= batas
    (default 0.5%) pada set validasi. Konservatif: lebih baik menahan noise daripada membuang alert asli."""
    y, p = np.asarray(y), np.asarray(p, dtype=float)
    true_scores = p[y == 0]
    if len(true_scores) == 0:
        return 0.5
    best = 1.0
    for thr in np.unique(np.round(p, 4)):
        if (true_scores >= thr).mean() <= max_true_alert_loss:
            best = min(best, float(thr))
    return best
