"""BERT Reasoning Agent.

- Bila BERT_MODEL_PATH menunjuk ke model HuggingFace sequence-classification hasil `scripts/train_bert.py`
  (KONVENSI LABEL TUNGGAL, sama dengan paper: indeks 1 = FALSE POSITIVE, indeks 0 = TRUE alert; P(true) = 1 - P(FP))
  dan `transformers`+`torch` terpasang, model itu dipakai (encoder saja, BUKAN generative LLM).
- Jika tidak, dipakai `HeuristicReasoner`: pengganti leksikal ringan agar pipeline dapat berjalan. Ini BUKAN
  model hasil fine-tuning; ganti dengan model terlatih pada data alert berlabel Anda sebelum produksi.
"""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from dataclasses import dataclass


@dataclass
class BertOutput:
    p_true: float
    model: str
    fp_threshold: float = 0.5   # alert dianggap false-positive hanya bila P(FP) >= ambang (hasil kalibrasi; lebih ketat = lindungi alert asli)

    @property
    def y(self) -> int:
        return 0 if (1.0 - self.p_true) >= self.fp_threshold else 1

    @property
    def confidence(self) -> float:
        return max(self.p_true, 1 - self.p_true)


POS = re.compile(r"success|exploit|malware|c2|beacon|reverse shell|root|privilege|exfil|ransom|webshell|injection|mimikatz|lateral|dga", re.I)
NEG = re.compile(r"scheduled|health ?check|monitor|heartbeat|backup|vulnerability scan by|approved|whitelist|test|nagios|zabbix|keepalive", re.I)


def serialize_alert(ev) -> str:
    return (f"[{ev.source}] type={ev.attack_type} sev={ev.severity} sig={ev.signature} src={ev.src_ip} dst={ev.dst_ip}:"
            f"{ev.dst_port} proto={ev.protocol} count={ev.count} msg={ev.message}")


class HeuristicReasoner:
    name = "heuristic-fallback(not-fine-tuned-bert)"

    def predict(self, ev) -> BertOutput:
        text = serialize_alert(ev)
        z = -0.4
        z += 0.9 * len(POS.findall(text)) - 1.1 * len(NEG.findall(text))
        z += {"low": -0.3, "medium": 0.2, "high": 0.7, "critical": 1.2}.get(ev.severity, 0)
        z += 0.5 * min(1.0, math.log10(max(ev.count, 1)) / 2)
        z += {"malware_comm": 0.8, "web_attack": 0.4, "brute_force": 0.1, "scanning": -0.3, "policy_violation": -0.5}.get(ev.attack_type, 0)
        return BertOutput(1 / (1 + math.exp(-z)), self.name)


class TransformersReasoner:  # pragma: no cover - butuh model terlatih
    def __init__(self, path: str):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(path)
        self.model = AutoModelForSequenceClassification.from_pretrained(path).eval()
        if self.model.config.num_labels != 2:
            raise ValueError("model harus 2 label (0=true alert, 1=false positive)")
        self.name = f"bert:{path}"
        ev = Path(path) / "eval.json"   # ambang FP hasil kalibrasi pada set validasi (lihat scripts/train_bert.py)
        self.fp_threshold = float(json.loads(ev.read_text()).get("threshold_fp", 0.5)) if ev.exists() else 0.5

    def predict(self, ev) -> BertOutput:
        with self.torch.no_grad():
            enc = self.tok(serialize_alert(ev), truncation=True, max_length=256, return_tensors="pt")
            p_fp = self.torch.softmax(self.model(**enc).logits, dim=-1)[0, 1].item()   # indeks 1 = FALSE POSITIVE
        return BertOutput(1.0 - float(p_fp), self.name, self.fp_threshold)


def load_reasoner(model_path: str = ""):
    if model_path:
        try:
            return TransformersReasoner(model_path)
        except Exception:  # noqa: BLE001  fallback aman
            pass
    return HeuristicReasoner()
