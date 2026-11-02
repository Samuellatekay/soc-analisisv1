import numpy as np
import pytest

from services.ml.evalkit import calibrate_threshold, metrics, roc_auc, split_indices


def test_triplet_split_has_no_leakage_and_covers_all():
    trip = [f"t{i % 40}" for i in range(1000)]
    tr, va, te = split_indices(trip, list(range(1000)), "triplet")
    s = lambda idx: {trip[i] for i in idx}  # noqa: E731
    assert not (s(tr) & s(va)) and not (s(tr) & s(te)) and not (s(va) & s(te))
    assert sorted(tr + va + te) == list(range(1000)) and te


def test_chronological_split_orders_by_time():
    t = [5, 1, 9, 3, 7, 2, 8, 4, 6, 0]
    tr, va, te = split_indices(["a"] * 10, t, "chronological")
    assert max(t[i] for i in tr) < min(t[i] for i in va) <= max(t[i] for i in va) < min(t[i] for i in te)


def test_auc_known_values_and_ties():
    assert roc_auc([0, 0, 1, 1], [0.1, 0.4, 0.35, 0.8]) == pytest.approx(0.75)      # contoh klasik scikit-learn
    assert roc_auc([0, 1], [0.5, 0.5]) == pytest.approx(0.5)
    assert roc_auc([1, 1], [0.1, 0.9]) != roc_auc([1, 1], [0.1, 0.9])               # NaN bila satu kelas


def test_metrics_confusion_matrix_matches_paper_fig12_style():
    # konfigurasi mirip Gambar 12 paper (positif = FP): TP=26910, FN=3090, FP=2243, TN=67757
    y = np.array([1] * 30000 + [0] * 70000)
    p = np.array([0.9] * 26910 + [0.1] * 3090 + [0.9] * 2243 + [0.1] * 67757)
    m = metrics(y, p)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (26910, 3090, 2243, 67757)
    assert m["accuracy"] == pytest.approx(0.94667, abs=1e-4) and m["precision"] == pytest.approx(0.9231, abs=1e-3)
    assert m["recall"] == pytest.approx(0.897, abs=1e-3) and m["f1"] == pytest.approx(0.9099, abs=1e-3) and m["fpr"] == pytest.approx(0.032, abs=1e-3)


def test_calibrate_threshold_protects_true_alerts():
    rng = np.random.default_rng(0)
    y = np.array([1] * 500 + [0] * 500)
    p = np.concatenate([rng.beta(8, 2, 500), rng.beta(2, 8, 500)])
    thr = calibrate_threshold(y, p, max_true_alert_loss=0.01)
    assert (p[y == 0] >= thr).mean() <= 0.01 and thr > 0.5
    assert calibrate_threshold(y, p, 0.0) >= thr           # semakin ketat batas, ambang semakin tinggi
