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

## UI konfigurasi, database eksternal, dan autoscaling

Master UI opsional tersedia melalui service Compose `master` dan `master-web`. Jalankan terpisah dari cluster yang dikelola:

```bash
mkdir -p secrets/master
chmod 700 secrets/master
.venv/bin/python -m services.master.keys gen secrets/master
.venv/bin/python -m services.master.keys gen-config secrets/master/master_config.key
sudo bash scripts/generate-master-tls.sh 192.168.33.140
```

Ganti alamat terakhir dengan IP/hostname yang akan dipakai node untuk menghubungi Master. Script membuat CA privat dan sertifikat HTTPS di `secrets/master/tls`; perintah menolak menimpa direktori TLS yang sudah ada. Simpan `ca.key`, `master_policy.key`, dan `master_config.key` di penyimpanan rahasia terenkripsi dengan backup terpisah. `master_policy.key` menandatangani payload; `master_config.key` mengenkripsi seluruh payload konfigurasi sebelum ditulis ke database Master. Kehilangan kunci konfigurasi membuat konfigurasi tersimpan tidak dapat dipulihkan. Jangan commit file kunci.

`ca.key` adalah private key CA dan tidak dipasang ke container mana pun. Compose hanya memasang dua private key Master ke API, serta sertifikat dan private key server ke Nginx HTTPS.

Container API berjalan sebagai UID non-root `10001`; berikan akses grup baca hanya pada dua key API (GID `1998` dipasang sebagai grup tambahan Compose):

```bash
sudo chgrp 1998 secrets/master/master_policy.key secrets/master/master_config.key
sudo chmod 640 secrets/master/master_policy.key secrets/master/master_config.key
```

Tambahkan Master UI credentials dan database Master ke `.env` (gunakan token acak yang berbeda dari token cluster):

```dotenv
MASTER_API_TOKENS=GANTI_TOKEN_ADMIN:admin,GANTI_TOKEN_VIEWER:viewer
MASTER_DATABASE_URL=postgresql+psycopg://user:password@db.example.com:5432/soc_master?sslmode=require
```

`MASTER_DATABASE_URL` menunjuk ke database metadata Master, terpisah dari database SOC tiap cluster. Jika tidak diberikan, Compose memakai SQLite volume `masterdata`. Jalankan:

```bash
docker compose -f infra/docker-compose.yml --env-file .env --profile master up --build -d master master-web
```

Buka `https://192.168.33.140:8443` (sesuaikan alamatnya) dan masuk dengan salah satu token Master. Port `8081` hanya mengarahkan browser ke HTTPS. Untuk menghilangkan peringatan sertifikat pada browser, pasang CA privat `secrets/master/tls/ca.crt` sebagai CA tepercaya dengan memverifikasi fingerprint SHA-256 yang dicetak saat pembuatan sertifikat. Jangan mengirim `ca.key` ke cluster/node; hanya sertifikat publik `ca.crt` yang dibagikan.

Daftarkan cluster; pull token hanya ditampilkan sekali. Simpan token di file rahasia berizin `0600`, lalu buat Secret bootstrap sebelum menerapkan overlay:

```bash
kubectl create namespace soc-cluster-01 --dry-run=client -o yaml | kubectl apply -f -
kubectl -n soc-cluster-01 create configmap soc-master-ca \
  --from-file=ca.crt=secrets/master/tls/ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n soc-cluster-01 create secret generic soc-runtime \
  --from-file=MASTER_CLUSTER_TOKEN=/secure/path/cluster-pull-token \
  --from-file=MASTER_POLICY_PUBKEY=secrets/master/master_policy.pub
kubectl apply -k deploy/kubernetes/overlays/cluster-template
```

Pastikan nilai `MASTER_URL` dan `CLUSTER_ID` di `config-patch.yaml` sesuai Master dan cluster yang didaftarkan. Overlay mengaktifkan satu replika `configuration-agent`; agent menggunakan service account terbatas untuk menerapkan ConfigMap/Secret dan melakukan rolling restart.

Di UI, pilih cluster lalu buka konfigurasi runtime untuk mengatur `DATABASE_URL` PostgreSQL, `ELASTICSEARCH_URL` dan API key, Redis, provider AI, konektor, serta autoscaling. Untuk mengganti database, ubah field rahasia `DATABASE_URL` ke URL PostgreSQL aktif, misalnya `postgresql+psycopg://USER:PASSWORD@HOST:5432/NAMA_DATABASE?sslmode=require`. Ganti semua nilai contoh; hostname harus dapat dijangkau dari Pod, dan karakter khusus dalam username/password harus di-URL-encode. Pastikan database/user sudah tersedia, akses jaringan dan TLS sesuai konfigurasi server. Simpan konfigurasi; perubahan diterbitkan sebagai versi baru, lalu agent menerapkan Secret dan melakukan rolling restart workload. Pantau status cluster hingga sinkron dan periksa log API jika belum siap.

Mengubah URL tidak menyalin data dari database lama ke database baru. Jika data lama harus dipertahankan, backup dan migrasikan data/schema PostgreSQL terlebih dahulu. Jangan ubah Secret `soc-runtime` langsung dengan `kubectl` untuk cluster yang dikelola Master karena agent dapat menimpa perubahan tersebut; panduan operator untuk cluster tanpa Master ada di [KUBERNETES.md](./KUBERNETES.md#mengganti-database-postgresql).

Elasticsearch/OpenSearch eksternal wajib HTTPS dan kredensial dipisahkan ke field secret/API key. Secret dapat dihapus melalui opsi “Hapus secret yang tersimpan”; nilai secret yang sudah disimpan tidak pernah dikembalikan oleh API.

Autoscaling memerlukan KEDA 2.16+ pada **setiap** cluster target dan Redis 7+ yang dapat menyediakan consumer-group lag Redis Streams. KEDA menskalakan `engine` berdasarkan lag stream `soc:events`/group `engine`; HPA menskalakan API dan Web berdasarkan CPU. Pastikan metrics-server tersedia untuk HPA dan workload memiliki CPU requests. KEDA/HPA hanya menambah/mengurangi Pod, bukan node; penambahan node tetap memerlukan Cluster Autoscaler dari penyedia cluster. Perubahan autoscaling ditolak atau tidak diterapkan jika prasyarat tersebut tidak tersedia. Mulai dari rentang replika kecil dan pantau kapasitas database/Redis eksternal sebelum menaikkan batas.

## Yang boleh/tidak boleh diatur kebijakan
Boleh (dengan batas keras, dicek di Master **dan** di cluster): `noise.pcc_threshold` 0.75–0.99, `noise.fft_peak_ratio` 2–10, `noise.fft_min_history_hours` 24–168, `fusion.retain` 0.5–0.9, `fusion.filter` 0.05–0.4 (harus < retain), `scoring.level_high_min` 70–95 / `level_medium_min` 40–80 (medium < high), `scoring.criteria_weights` (6 kriteria, tiap 0.02–0.6, jumlah 1), `scoring.tactic_policy_weight`, `enrichment.*`, `kb_stale_days`.
**Tidak ada** field untuk menonaktifkan risk gate atau menghapus perlindungan alert berisiko; field tak dikenal ditolak. Master yang dibobol tetap tidak bisa mematikan perlindungan itu lewat kebijakan.

## Jaminan keamanan yang diuji (`tests/test_master.py`)
Tanda tangan mengikat `cluster_id` + versi + isi (isi/versi diubah, cluster lain, kunci palsu → ditolak); versi harus lebih baru (anti-rollback/replay); kebijakan sah-bertanda-tangan tetapi melanggar batas → ditolak cluster; token tarik per-cluster (token cluster lain/admin → 401); token status tidak disimpan di DB Master (hanya nama env); Master mati → cluster lanjut dengan kebijakan terakhir; setiap keputusan alert mencatat `policy_version`.

## Batasan
Satu instance Master (tidak HA; kematiannya tidak mengganggu cluster tetapi menunda rollout & pemantauan — jalankan di balik orkestrator/replika DB). Rotasi kunci penandatangan belum didukung (butuh dukungan multi-kunci di cluster). UI Master mengelola cluster yang sudah disiapkan operator, tetapi tidak membuat cluster/node cloud. Pemantauan = poll berkala, bukan push. Kesehatan "sehat" hanya mencerminkan indikator yang dilaporkan (`/cluster/status`), bukan jaminan kualitas keputusan.
