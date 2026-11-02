# Mode Master (control plane)

Master mengelola **registri cluster, kebijakan bertanda tangan, dan kesehatan armada**. Master **bukan** jalur event dan **bukan** worker analisis: cluster tetap menerima, memproses, dan menilai alert walau Master mati.

```
 Admin ──► Master (apps/master) ──(PULL status tiap 30s)──► Cluster API  /api/v1/cluster/status
              ▲  kebijakan bertanda tangan Ed25519
              └──(cluster MENARIK /api/v1/policy/{id}; verifikasi; simpan di DB lokal)──  policy agent ──► PolicyState ──► engine (TTL 30s)
```

## Pasang
```bash
python -m services.master.keys gen /secure/dir            # master_policy.key (PRIVAT, hanya Master) + master_policy.pub (sebar ke cluster)
# Master:
export MASTER_API_TOKENS=<token>:admin,<token2>:viewer MASTER_SIGNING_KEY_FILE=/secure/dir/master_policy.key MASTER_DATABASE_URL=postgresql+psycopg://...
export TOK_C1=<token admin/baca-status cluster c1>        # nama env dirujuk saat registrasi (status_token_env)
uvicorn app.main:app --app-dir apps/master --port 8100
curl -XPOST :8100/api/v1/clusters -H "Authorization: Bearer <admin>" -H 'Content-Type: application/json' \
  -d '{"id":"c1","name":"Cluster 1","api_url":"https://c1.example","status_token_env":"TOK_C1"}'     # -> pull_token (SEKALI)
# Cluster c1 (di .env):
MASTER_URL=https://master.example CLUSTER_ID=c1 MASTER_CLUSTER_TOKEN=<pull_token> MASTER_POLICY_PUBKEY_FILE=/path/master_policy.pub
```
Terbitkan kebijakan: `POST /api/v1/policies {"policy":{...},"targets":["c1"],"note":"kanari"}` lalu ulangi dengan `["*"]` untuk rollout penuh. Rollback = `POST /policies/{v}/republish ["*"]` (isi lama, **versi baru**).

## Yang boleh/tidak boleh diatur kebijakan
Boleh (dengan batas keras, dicek di Master **dan** di cluster): `noise.pcc_threshold` 0.75–0.99, `noise.fft_peak_ratio` 2–10, `noise.fft_min_history_hours` 24–168, `fusion.retain` 0.5–0.9, `fusion.filter` 0.05–0.4 (harus < retain), `scoring.level_high_min` 70–95 / `level_medium_min` 40–80 (medium < high), `scoring.criteria_weights` (6 kriteria, tiap 0.02–0.6, jumlah 1), `scoring.tactic_policy_weight`, `enrichment.*`, `kb_stale_days`.
**Tidak ada** field untuk menonaktifkan risk gate atau menghapus perlindungan alert berisiko; field tak dikenal ditolak. Master yang dibobol tetap tidak bisa mematikan perlindungan itu lewat kebijakan.

## Jaminan keamanan yang diuji (`tests/test_master.py`)
Tanda tangan mengikat `cluster_id` + versi + isi (isi/versi diubah, cluster lain, kunci palsu → ditolak); versi harus lebih baru (anti-rollback/replay); kebijakan sah-bertanda-tangan tetapi melanggar batas → ditolak cluster; token tarik per-cluster (token cluster lain/admin → 401); token status tidak disimpan di DB Master (hanya nama env); Master mati → cluster lanjut dengan kebijakan terakhir; setiap keputusan alert mencatat `policy_version`.

## Batasan
Satu instance Master (tidak HA; kematiannya tidak mengganggu cluster tetapi menunda rollout & pemantauan — jalankan di balik orkestrator/replika DB). Rotasi kunci penandatangan belum didukung (butuh dukungan multi-kunci di cluster). Belum ada UI Master (API saja). Pemantauan = poll berkala, bukan push. Kesehatan "sehat" hanya mencerminkan indikator yang dilaporkan (`/cluster/status`), bukan jaminan kualitas keputusan.
