"""Utilitas AHP: bobot dari matriks penilaian + consistency ratio (untuk verifikasi paper)."""
from __future__ import annotations

import numpy as np

RI = {1: 0, 2: 0, 3: 0.58, 4: 0.90, 5: 1.12, 6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45}


def weights_from_matrix(matrix) -> tuple[np.ndarray, float]:
    """Return (bobot eigenvector utama ternormalisasi, consistency ratio)."""
    m = np.asarray(matrix, dtype=float)
    n = m.shape[0]
    vals, vecs = np.linalg.eig(m)
    i = int(np.argmax(vals.real))
    w = np.abs(vecs[:, i].real)
    w = w / w.sum()
    ci = (vals[i].real - n) / (n - 1) if n > 2 else 0.0
    cr = ci / RI[n] if RI.get(n) else 0.0
    return w, float(cr)
