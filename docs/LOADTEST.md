# Load test & hasil terukur

`scripts/loadtest.py` menjalankan N proses worker engine membaca Redis Streams (consumer group) dan menulis ke PostgreSQL, lalu memverifikasi:
tidak ada event hilang, tidak ada duplikat, penghitung triplet = jumlah `count` masukan, outbox = event, DLQ kosong, tidak ada pesan pending.
```bash
DATABASE_URL=postgresql+psycopg://soc:***@127.0.0.1/soc REDIS_URL=redis://127.0.0.1:6379/0 \
python scripts/loadtest.py --events 20000 --workers 1,2,4 --kill
```

## Hasil yang saya ukur (sandbox: **1 core CPU**, PostgreSQL 16 + Redis + semua worker berbagi core itu)
| Uji | Hasil |
|---|---|
| 4.000 event, 1 worker, commit per-event | 78 event/dtk, semua invarian lulus |
| 4.000 event, 1 worker, **commit per-batch** (savepoint per event) | **118 event/dtk** (+51%), semua invarian lulus |
| 6.000 event, 3 worker, `kill -9` satu worker pada 1.850 event | semua 6.000 event terproses, 6.000 unik, penghitung tepat, DLQ 0, pending 0 (pesan milik worker mati di-klaim ulang via `XAUTOCLAIM`) |
| Benchmark fast path tanpa jaringan (SQLite, 1 proses) | ≈ 140–250 event/dtk, p95 ≈ 6–10 ms/event |

## Yang TIDAK dibuktikan
* **Skalabilitas horizontal.** Dengan 1 core, menambah worker tidak menambah kapasitas; angka 2 worker/3 worker di sini hanya bukti kebenaran dan ketahanan, bukan kapasitas. Jalankan ulang pada hardware target (core terpisah untuk PostgreSQL, Redis, dan tiap worker).
* **Kapasitas produksi.** Tidak termasuk latensi jaringan enrichment (GLPI/OpenCTI), inferensi BERT nyata, Elasticsearch, atau beban baca UI.
* **Triplet panas.** Penghitung per (tenant, triplet, jam) adalah satu baris; satu sumber yang sangat berisik akan menserialisasi worker pada baris itu (upsert atomik aman tetapi mengantre). Bila ini terjadi, shard penghitung per worker lalu jumlahkan saat dibaca.
* Bug yang ditemukan oleh uji ini (semuanya sudah diperbaiki + test regresi di `tests/test_concurrency.py`): tabrakan primary key `triplet_counts` antar-worker, risiko lost-update pada penghitung, risiko hitung ganda saat redelivery (advisory lock per `event_id`), dan klaim ganda job analisis/outbox (`FOR UPDATE SKIP LOCKED`).
