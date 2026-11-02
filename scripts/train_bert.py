"""Fine-tuning klasifikator BERT (0 = TRUE alert, 1 = FALSE POSITIVE; kelas positif = FP seperti di paper).

Input : JSONL/CSV dengan kolom  text,label,triplet,time   (text = serialize_alert(); label dari tiket insiden/analis)
        -> hasilkan dari DB: python scripts/export_training_data.py --labels labels.csv --out train.jsonl
Output: direktori model HuggingFace  -> set BERT_MODEL_PATH ke direktori itu.

  python scripts/train_bert.py --data train.jsonl --base bert-base-uncased --out models/bert-fp --split triplet

!! STATUS: logika split/metrik/kalibrasi diuji otomatis (tests/test_evalkit.py). LOOP PELATIHAN di bawah (torch/transformers)
   BELUM dijalankan oleh pembuatnya (lingkungan tanpa ruang disk untuk torch). Jalankan pada data kecil dulu dan periksa hasilnya.
!! Jangan memakai model ini sebelum: (1) split bebas-kebocoran lolos, (2) recall alert ASLI pada set uji >= target Anda, (3) review manual sampel.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path[:0] = [str(Path(__file__).resolve().parents[1])]
import numpy as np  # noqa: E402

from services.ml.evalkit import calibrate_threshold, metrics, split_indices  # noqa: E402


def load(path: str) -> list[dict]:
    p = Path(path)
    if p.suffix == ".csv":
        import csv
        return list(csv.DictReader(p.open()))
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True); ap.add_argument("--base", default="bert-base-uncased"); ap.add_argument("--out", required=True)
    ap.add_argument("--split", choices=["triplet", "chronological"], default="triplet")
    ap.add_argument("--epochs", type=int, default=3); ap.add_argument("--lr", type=float, default=2e-5); ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-len", type=int, default=256); ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    rows = load(a.data)
    y = np.array([int(r["label"]) for r in rows])
    tr, va, te = split_indices([r["triplet"] for r in rows], [float(r["time"]) for r in rows], a.split, a.seed)
    print(f"split={a.split} train={len(tr)} val={len(va)} test={len(te)} | FP rate train={y[tr].mean():.3f} test={y[te].mean():.3f}")
    if a.split == "triplet":   # jaminan anti-kebocoran
        t = lambda idx: {rows[i]["triplet"] for i in idx}  # noqa: E731
        assert not (t(tr) & t(va) or t(tr) & t(te) or t(va) & t(te)), "triplet bocor antar split"

    import torch
    from torch.utils.data import DataLoader
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup
    torch.manual_seed(a.seed)
    tok = AutoTokenizer.from_pretrained(a.base)
    model = AutoModelForSequenceClassification.from_pretrained(a.base, num_labels=2)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(dev)

    def enc(idx):
        e = tok([rows[i]["text"] for i in idx], truncation=True, max_length=a.max_len, padding=True, return_tensors="pt")
        return e, torch.tensor(y[idx])

    def batches(idx, shuffle):
        idx = np.array(idx)
        if shuffle:
            np.random.default_rng(a.seed).shuffle(idx)
        for i in range(0, len(idx), a.batch):
            yield enc(idx[i:i + a.batch])

    steps = a.epochs * ((len(tr) + a.batch - 1) // a.batch)
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
    sch = get_linear_schedule_with_warmup(opt, int(0.1 * steps), steps)
    # bobot kelas: FP biasanya mayoritas; bobot menjaga recall TRUE alert (kesalahan membuang alert asli lebih mahal)
    w = torch.tensor([1.5, 1.0], device=dev)
    lossf = torch.nn.CrossEntropyLoss(weight=w)

    def predict(idx):
        model.eval(); out = []
        with torch.no_grad():
            for e, _ in batches(idx, False):
                out.append(torch.softmax(model(**{k: v.to(dev) for k, v in e.items()}).logits, -1)[:, 1].cpu().numpy())
        return np.concatenate(out)

    best, last_std = (-1.0, None), 0.0
    for ep in range(a.epochs):
        model.train()
        for e, lab in batches(tr, True):
            loss = lossf(model(**{k: v.to(dev) for k, v in e.items()}).logits, lab.to(dev))
            loss.backward(); torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0); opt.step(); sch.step(); opt.zero_grad()
        pv = predict(va); m = metrics(y[va], pv)
        last_std = float(np.std(pv))
        print(f"epoch {ep + 1}: val {json.dumps({k: round(v, 4) for k, v in m.items() if k in ('f1', 'auc', 'precision', 'recall', 'fpr')})}")
        score = m["f1"] - 5 * m["fpr"]          # penalti berat untuk true alert yang dibuang
        if score > best[0]:
            best = (score, {k: v.detach().cpu().clone() for k, v in model.state_dict().items()})
    if last_std < 1e-3:   # model collapse: semua prediksi sama di akhir pelatihan -> jangan simpan model yang tampak "jalan" tetapi tidak belajar
        raise SystemExit(f"prediksi validasi konstan di akhir pelatihan (std={last_std:.1e}) — pelatihan gagal belajar. Turunkan --lr, periksa label/teks, atau tambah data.")
    model.load_state_dict(best[1])
    thr = calibrate_threshold(y[va], predict(va))
    pt = predict(te)
    res = {"threshold_fp": thr, "test_at_0.5": metrics(y[te], pt, 0.5), f"test_at_{thr:.3f}": metrics(y[te], pt, thr), "split": a.split, "base": a.base}
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out); tok.save_pretrained(out)
    (out / "eval.json").write_text(json.dumps(res, indent=1, default=float))
    print(json.dumps(res["test_at_0.5"], indent=1, default=float)); print(f"model + eval.json disimpan di {out}. Set BERT_MODEL_PATH={out}")


if __name__ == "__main__":
    main()
