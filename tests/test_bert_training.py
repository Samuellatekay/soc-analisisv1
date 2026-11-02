"""Uji integrasi pelatihan BERT: skrip latih -> model -> dibaca engine. Memakai BERT mini ACAK buatan lokal (tanpa Hugging Face Hub).
Tujuan: memastikan ARAH label konsisten (bug inversi pernah terjadi) dan seluruh jalur berjalan; BUKAN mengukur kualitas model."""
import json
import random
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("torch"); pytest.importorskip("transformers")
ROOT = Path(__file__).resolve().parents[1]

FP = ["scheduled vulnerability scan monitoring probe approved", "health check heartbeat nagios keepalive", "backup job scheduled policy test whitelist"]
TP = ["ssh brute force failed login success root exploit", "malware c2 beacon reverse shell exfil", "sql injection webshell exploit privilege mimikatz"]


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    d = tmp_path_factory.mktemp("bert"); random.seed(5)
    rows, t0 = [], datetime(2026, 1, 1)
    for i in range(400):
        fp = random.random() < 0.6
        rows.append({"text": f"type={'scanning' if fp else 'brute_force'} sev={'low' if fp else 'high'} sig={random.choice(FP if fp else TP)} src=10.0.0.{i % 50} count={random.randint(1, 50)}",
                     "label": int(fp), "triplet": f"t{i % 40}", "time": (t0 + timedelta(hours=i)).timestamp()})
    (d / "train.jsonl").write_text("\n".join(map(json.dumps, rows)))
    words = sorted({w for r in rows for w in r["text"].replace("=", " = ").replace(".", " . ").lower().split()})
    vocab = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"] + words
    (d / "vocab.txt").write_text("\n".join(vocab))
    import torch
    from transformers import BertConfig, BertForSequenceClassification, BertTokenizerFast
    torch.manual_seed(0)    # inisialisasi BERT mini deterministik
    BertForSequenceClassification(BertConfig(vocab_size=len(vocab), hidden_size=64, num_hidden_layers=2, num_attention_heads=2, intermediate_size=128,
                                             max_position_embeddings=128, num_labels=2)).save_pretrained(d / "tiny")
    BertTokenizerFast(str(d / "vocab.txt"), do_lower_case=True).save_pretrained(d / "tiny")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "train_bert.py"), "--data", str(d / "train.jsonl"), "--base", str(d / "tiny"), "--out", str(d / "out"),
                        "--epochs", "6", "--lr", "3e-3", "--batch", "32", "--max-len", "64"], capture_output=True, text=True, cwd=ROOT, timeout=240)
    assert r.returncode == 0, r.stderr[-800:]
    return d / "out"


def test_training_outputs_model_eval_and_leak_free_split(trained):
    ev = json.loads((trained / "eval.json").read_text())
    assert ev["test_at_0.5"]["accuracy"] > 0.9, "model tidak belajar pada data sintetis yang mudah dipisahkan"
    assert ev["split"] == "triplet" and 0 < ev["threshold_fp"] <= 1 and "test_at_0.5" in ev
    assert (trained / "config.json").exists()


def test_engine_reads_label_direction_correctly(trained):
    from services.engine.agents.bert import load_reasoner
    r = load_reasoner(str(trained))
    assert type(r).__name__ == "TransformersReasoner"
    mk = lambda sig, t, sev, c: NS(source="generic", attack_type=t, severity=sev, signature=sig, src_ip="10.0.0.1", dst_ip="10.0.1.10", dst_port=22, protocol=None, count=c, message="")  # noqa: E731
    jinak = r.predict(mk("scheduled vulnerability scan monitoring probe approved", "scanning", "low", 5))
    serang = r.predict(mk("ssh brute force failed login success root exploit", "brute_force", "high", 30))
    assert serang.p_true > 0.5 > jinak.p_true, (jinak.p_true, serang.p_true)     # regresi: pernah terbalik
    assert serang.y == 1                                                            # serangan tidak pernah disaring
    assert jinak.y == (0 if (1 - jinak.p_true) >= r.fp_threshold else 1)            # keputusan mengikuti ambang kalibrasi (mungkin lebih ketat dari 0.5)
    assert r.fp_threshold == json.loads((trained / 'eval.json').read_text())['threshold_fp']


def test_calibrated_threshold_makes_filtering_stricter():
    from services.engine.agents.bert import BertOutput
    assert BertOutput(0.4, "m", 0.5).y == 0          # P(FP)=0.6 >= 0.5 -> false positive
    assert BertOutput(0.4, "m", 0.9).y == 1          # ambang ketat 0.9: P(FP)=0.6 belum cukup -> alert dipertahankan
    assert BertOutput(0.5, "m", 0.5).y == 0


def test_training_aborts_on_collapsed_model(tmp_path):
    """Pengaman: data tanpa sinyal + lr berlebihan -> prediksi konstan harus membatalkan pelatihan (tidak menyimpan model)."""
    import torch
    from transformers import BertConfig, BertForSequenceClassification, BertTokenizerFast
    rows = [{"text": "kata sama", "label": i % 2, "triplet": f"t{i % 30}", "time": float(i)} for i in range(200)]
    (tmp_path / "d.jsonl").write_text("\n".join(map(json.dumps, rows)))
    (tmp_path / "vocab.txt").write_text("\n".join(["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]", "kata", "sama"]))
    torch.manual_seed(0)
    BertForSequenceClassification(BertConfig(vocab_size=7, hidden_size=32, num_hidden_layers=1, num_attention_heads=2, intermediate_size=64, max_position_embeddings=32, num_labels=2)).save_pretrained(tmp_path / "t")
    BertTokenizerFast(str(tmp_path / "vocab.txt")).save_pretrained(tmp_path / "t")
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "train_bert.py"), "--data", str(tmp_path / "d.jsonl"), "--base", str(tmp_path / "t"), "--out", str(tmp_path / "o"),
                        "--epochs", "1", "--lr", "0", "--batch", "32", "--max-len", "16"], capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert r.returncode != 0 and "gagal belajar" in (r.stderr + r.stdout) and not (tmp_path / "o").exists()
