# SOC Analisis

Implementasi dari spesifikasi **SOC Analisis Engine** dan paper *"Intelligent priority awareness method for alert data in SOC threat response"* (J. King Saud Univ. CIS, 2026) 38:776:
risk-gated FFT-PCC noise reduction → evidence orchestration (agen deterministik + BERT) → semantic integrity verification → skor risiko AHP → aplikasi analis (dashboard, alert, case).

## Instalasi cepat (Ubuntu/Linux, tanpa Docker)

```bash
make setup      # Python venv + dependency backend + frontend + build UI
make dev        # jalankan aplikasi di http://localhost:8000
```

Persyaratan: Python 3.12+, Node.js 18+, dan npm. Installer memakai akun pemilik repo (termasuk bila `make setup` dipanggil dari shell root), tidak mengubah `.env`, dan tidak memerlukan akses sudo. Setelah server berjalan, buka alamat tersebut dan login dengan token development `dev-analyst-token` (admin: `dev-admin-token`, viewer: `dev-viewer-token`). Tekan `Ctrl+C` untuk berhenti.

Jika mengakses dari komputer lain, gunakan `http://<IP-VM>:8000` dan pastikan port 8000 diizinkan oleh firewall VM/cloud. Untuk membuat data contoh, jalankan di terminal lain: `.venv/bin/python scripts/generate_demo_data.py --api http://localhost:8000`.

Untuk tes: `make test`; untuk tes UI: `cd apps/web && npm test`. Untuk menjalankan UI Vite dengan hot reload: `cd apps/web && npm run dev` (port 5173, proxy ke API port 8000).

`GET /api/v1/health` adalah liveness check. Gunakan `GET /api/v1/ready` untuk readiness: memeriksa koneksi database dan Redis bila ingest memakai mode queue, serta melaporkan status Elasticsearch/Neo4j bila dikonfigurasi.

### Smoke test integrasi staging

Dengan Elasticsearch dan Neo4j Compose sudah berjalan, uji query terhadap layanan nyata dari dalam network Compose (tidak perlu membuka port database ke host):

```bash
docker compose -f infra/docker-compose.yml --env-file .env up -d elasticsearch neo4j
docker compose -f infra/docker-compose.yml --env-file .env run --rm --no-deps \
  -v ./scripts:/app/scripts:ro api \
  python /app/scripts/staging_smoke.py --only elasticsearch,neo4j
```

Smoke test membuat index/dokumen sementara di Elasticsearch lalu menghapus index tersebut; di Neo4j ia membuat node sementara untuk menguji skema `Technique`/`Tactic`, query Cypher retriever, freshness, dan isolasi tenant, lalu membersihkannya. Hanya jalankan pada staging yang diizinkan. Tambahkan `ollama,opencti` setelah URL, model, dan token yang diperlukan sudah dikonfigurasi. Endpoint kosong akan dilaporkan sebagai `SKIP`, sedangkan konfigurasi ada tetapi gagal akan membuat tes gagal. Jangan menaruh token OpenCTI di command line atau Git; gunakan secret file.

### Memilih provider AI untuk analisis RAG

Worker RAG mendukung **Ollama**, **Google Gemini API**, **OpenAI API**, dan layanan lain yang menyediakan endpoint chat kompatibel OpenAI. Pilih satu provider melalui `.env`; provider ini hanya membuat ringkasan/rekomendasi RAG. Skor risiko dan keputusan alert tetap ditentukan engine SOC.

Atur variabel berikut di `.env`:

| Provider | `LLM_PROVIDER` | Pengaturan yang diperlukan |
|---|---|---|
| Ollama lokal | `ollama` | `OLLAMA_URL`, `OLLAMA_MODEL` |
| Google Gemini | `gemini` | `LLM_MODEL`, `LLM_API_KEY` |
| OpenAI API | `openai` | `LLM_MODEL`, `LLM_API_KEY` |
| Endpoint kompatibel OpenAI | `openai_compatible` | `LLM_MODEL`, `LLM_BASE_URL`; API key jika provider mewajibkannya |
| Tanpa layanan AI | `none` | Tidak ada; aplikasi membuat analisis template |

`LLM_PROVIDER=auto` adalah nilai bawaan untuk menjaga kompatibilitas: bila `OLLAMA_URL` dan `OLLAMA_MODEL` terisi, aplikasi memakai Ollama; jika tidak, aplikasi memakai analisis template tanpa menghubungi provider cloud.

#### Contoh lengkap: mengaktifkan Gemini

1. Dari folder utama aplikasi, buka file konfigurasi:

   ```bash
   nano .env
   ```

   Jika file `.env` belum ada, buat dari template terlebih dahulu dengan `cp .env.example .env`.
2. Tambahkan atau ubah baris berikut di `.env`:

   ```dotenv
   LLM_PROVIDER=gemini
   LLM_MODEL=gemini-2.5-flash
   LLM_API_KEY=GANTI_DENGAN_API_KEY_DARI_GOOGLE_AI_STUDIO
   ```

   Ganti seluruh nilai `GANTI_DENGAN_API_KEY_DARI_GOOGLE_AI_STUDIO` dengan API key milik Anda. Teks tersebut hanya placeholder, bukan key yang berfungsi. Simpan file (`Ctrl+O`, `Enter`), lalu keluar (`Ctrl+X`). Jangan menaruh key di `.env.example`, Git, atau chat.
3. Jalankan atau restart aplikasi agar konfigurasi dibaca:

   ```bash
   make dev
   ```

   Jika aplikasinya sudah berjalan, hentikan dulu dengan `Ctrl+C`, lalu jalankan lagi `make dev`.

Untuk Docker Compose, setelah mengubah `.env`, bangun ulang dan jalankan worker RAG:

```bash
docker compose -f infra/docker-compose.yml --env-file .env up --build -d rag_worker
```

Contoh OpenAI API (gunakan API key OpenAI, bukan password/langganan ChatGPT):

```dotenv
LLM_PROVIDER=openai
LLM_MODEL=gpt-4.1-mini
LLM_API_KEY=GANTI_DENGAN_API_KEY_OPENAI
```

Contoh endpoint kompatibel OpenAI:

```dotenv
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://provider.example/v1
LLM_MODEL=nama-model-dari-provider
LLM_API_KEY=GANTI_DENGAN_API_KEY_PROVIDER
```

Setelah mengubah `.env`, restart aplikasi Single dengan `make dev`, atau buat ulang container Compose dengan `docker compose -f infra/docker-compose.yml --env-file .env up --build -d`. Untuk key yang tidak boleh ditulis langsung di `.env`, gunakan `LLM_API_KEY_FILE` dan pastikan file tersebut tersedia di proses worker. Di Compose, mount file itu ke service `rag_worker` dan isi `LLM_API_KEY_FILE` dengan path di dalam container. File `.env` tidak boleh dimasukkan ke Git.

**Privasi dan biaya:** Gemini, OpenAI, dan provider cloud kompatibel akan menerima data alert serta bukti RAG yang dikirim untuk dianalisis, dan penggunaan API dapat dikenai biaya. Pastikan pengiriman data diizinkan organisasi Anda, periksa kebijakan retensi/data provider, dan jangan kirim data sensitif bila belum disetujui. Gunakan Ollama jika analisis harus tetap di lingkungan sendiri.

Untuk menjalankan stack penuh dengan Docker Compose, ikuti [panduan instalasi](#panduan-instalasi-pilih-salah-satu-dari-3-mode) berikut.

## Panduan instalasi: pilih salah satu dari 3 mode

Perintah di bawah ditujukan untuk Ubuntu/Linux dan dijalankan dari folder utama repository.

| Mode | Cocok untuk | Yang perlu disiapkan |
|---|---|---|
| **1. Single** | Belajar, demo, dan development di satu komputer | Python 3.12+, Node.js 18+, npm |
| **2. Orkestrasi** | Menjalankan aplikasi, database, antrean, dan worker di satu host | Docker Engine dan Docker Compose v2 |
| **3. Master** | Memantau beberapa cluster SOC dan mengelola kebijakan | Cluster SOC yang sudah berjalan; Master dipasang terpisah |

### 1. Single — paling mudah, tanpa Docker

Mode ini menjalankan API, worker, dan UI bersama-sama. Data disimpan di SQLite lokal. Cocok untuk mencoba aplikasi, bukan untuk high availability atau produksi.

1. Pastikan Python 3.12+, Node.js 18+, dan npm tersedia.
2. Siapkan aplikasi:

   ```bash
   make setup
   ```

3. Jalankan aplikasi:

   ```bash
   make dev
   ```

4. Buka `http://localhost:8000`. Login demo: `dev-analyst-token` (admin: `dev-admin-token`).
5. Untuk berhenti, tekan `Ctrl+C`.

Untuk membuat data contoh, buka terminal lain di folder repository:

```bash
.venv/bin/python scripts/generate_demo_data.py --api http://localhost:8000
```

Token di atas hanya untuk demo lokal. Jangan gunakan token development atau buka aplikasi langsung ke internet.

### 2. Orkestrasi — Docker Compose di satu host

Mode ini menjalankan API, UI, database, antrean, dan worker sebagai layanan terpisah. Ini tetap satu host, bukan konfigurasi high availability. Master UI opsional dijalankan terpisah dengan profil Compose `master`; panduannya ada di [`docs/MASTER.md`](docs/MASTER.md).

1. Pasang Docker Engine dan plugin Docker Compose v2. Pastikan akun Anda bisa menjalankan `docker compose`.
2. Buat file konfigurasi dari folder repository:

   ```bash
   cp -n .env.example .env
   test -e infra/config/connectors.json || cp infra/config/connectors.example.json infra/config/connectors.json
   ```

3. Edit `.env`: ganti password, token API, dan ingest key contoh. Untuk menghindari konektor berjalan dua kali, set `EMBEDDED_CONNECTORS=false`; service `connectors` Compose akan menjalankannya. Jangan commit `.env` atau secret ke Git.
4. Bangun dan jalankan seluruh layanan:

   ```bash
   docker compose -f infra/docker-compose.yml --env-file .env up --build -d
   ```

5. Pastikan layanan berjalan:

   ```bash
   docker compose -f infra/docker-compose.yml --env-file .env ps
   ```

   Buka UI di `http://localhost:8080`. Untuk melihat log, jalankan `docker compose -f infra/docker-compose.yml --env-file .env logs -f`.
6. Untuk menghentikan layanan tanpa menghapus data:

   ```bash
   docker compose -f infra/docker-compose.yml --env-file .env down
   ```

Perintah `down` mempertahankan data volume. **Jangan gunakan `down -v`** kecuali memang ingin menghapus data. Ollama tidak otomatis dijalankan oleh Compose; RAG tetap dapat menggunakan analisis template bila Ollama belum dikonfigurasi. Backup aktif pada contoh `.env`; sebelum menjalankan stack, siapkan kunci lalu mount file tersebut ke service `backup` pada path `BACKUP_ENCRYPTION_KEY_FILE`. Path secret tidak otomatis dipasang oleh Compose.

### Deployment Kubernetes untuk banyak cluster

Panduan langkah demi langkah untuk prasyarat, build image, Master, secret, overlay per cluster, KEDA, deploy, dan pemeriksaan readiness ada di [`docs/KUBERNETES.md`](docs/KUBERNETES.md). Manifest di [`deploy/kubernetes/`](deploy/kubernetes/) memakai PostgreSQL, Redis, Elasticsearch, dan Neo4j eksternal; template tidak membuat database atau node cloud.

Untuk konfigurasi production, ganti contoh model/provider AI hanya setelah kebijakan data mengizinkan alert dikirim ke provider itu. Backup template menyimpan hasil pada PVC satu cluster; replikasi off-site, uji restore berkala, pemulihan Elasticsearch, monitoring/alerting, pengaturan egress, dan uji beban sesuai target **tetap wajib disiapkan oleh operator**. Jangan menyatakan deployment enterprise siap sebelum seluruh uji tersebut lulus pada lingkungan target. Lihat [`docs/LOADTEST.md`](docs/LOADTEST.md) untuk batas angka benchmark yang sudah ada.

### 3. Master — pengelola cluster (opsional)

Master bukan pengganti aplikasi SOC dan tidak memproses alert. Untuk mode Single/Compose, Master bisa ditambahkan setelah aplikasi berjalan. **Untuk overlay Kubernetes `cluster-template`, siapkan Master dan daftarkan cluster sebelum deploy**, karena overlay tersebut mengaktifkan agent yang membutuhkan token dan public key Master saat Pod dibuat. Ikuti [`docs/KUBERNETES.md`](docs/KUBERNETES.md) untuk instalasi Kubernetes; contoh Linux di bawah menghubungkan Master development ke cluster Single lokal.

#### Contoh lokal di Ubuntu/Linux

1. Pastikan `make setup` sudah selesai dan cluster Single dapat dibuka di `http://localhost:8000`.
2. Buat kunci Master:

   ```bash
   mkdir -p secrets/master
   .venv/bin/python -m services.master.keys gen secrets/master
   ```

   Jaga `master_policy.key` sebagai rahasia. Salin hanya `master_policy.pub` ke cluster yang akan dikelola. Jangan commit folder `secrets/`.
3. Buka terminal baru. Buat token admin acak:

   ```bash
   python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
   ```

   Salin token yang ditampilkan sementara. Di terminal Master, tempel token saat diminta (input tidak ditampilkan), lalu jalankan:

   ```bash
   read -rsp 'Token admin Master: ' MASTER_ADMIN_TOKEN; echo
   export MASTER_API_TOKENS="${MASTER_ADMIN_TOKEN}:admin"
   export MASTER_SIGNING_KEY_FILE="$PWD/secrets/master/master_policy.key"
   export TOK_C1='dev-admin-token'
   .venv/bin/python -m uvicorn app.main:app --app-dir apps/master --host 127.0.0.1 --port 8100
   ```

   Biarkan terminal ini berjalan. Master development memakai SQLite lokal.
4. Di terminal lain, masukkan token admin yang sama, lalu daftarkan cluster. `pull_token` hanya ditampilkan sekali; simpan token itu dengan aman:

   ```bash
   read -rsp 'Token admin Master: ' MASTER_ADMIN_TOKEN; echo
   curl -sS -X POST http://127.0.0.1:8100/api/v1/clusters \
     -H "Authorization: Bearer $MASTER_ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"id":"c1","name":"Cluster lokal","api_url":"http://127.0.0.1:8000","status_token_env":"TOK_C1","verify_tls":false}'
   ```

   `verify_tls:false` hanya untuk contoh lokal dengan HTTP. Gunakan HTTPS dan verifikasi TLS untuk cluster sungguhan.
5. Hentikan cluster Single dengan `Ctrl+C`. Di terminal tempat Anda menjalankan cluster, masukkan `pull_token` yang diterima lalu jalankan kembali dalam mode terkelola:

   ```bash
   read -rsp 'Pull token cluster: ' MASTER_CLUSTER_TOKEN; echo
   export MASTER_CLUSTER_TOKEN
   MASTER_URL=http://127.0.0.1:8100 \
   CLUSTER_ID=c1 \
   MASTER_POLICY_PUBKEY_FILE="$PWD/secrets/master/master_policy.pub" \
   make dev
   ```

Status cluster dapat diperiksa dengan token admin:

```bash
curl -H "Authorization: Bearer $MASTER_ADMIN_TOKEN" http://127.0.0.1:8100/api/v1/clusters
```

Untuk kebijakan, rollout, dan batas keamanan, lihat [`docs/MASTER.md`](docs/MASTER.md). Master development di atas hanya untuk lokal; deployment nyata memerlukan HTTPS, secret manager, dan database yang dipelihara. Jika Master tidak tersedia, cluster tetap bekerja dengan kebijakan terakhir yang diterima.

#### Contoh di Windows (PowerShell)

Master dijalankan terpisah dari cluster SOC. Untuk penggunaan nyata, gunakan HTTPS, token unik, secret manager, dan database Master yang dipelihara; jangan mengekspos token atau private key di Git.

1. Siapkan environment dan buat pasangan kunci Ed25519 sekali saja:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   New-Item -ItemType Directory -Force .\secrets\master | Out-Null
   python -m services.master.keys gen .\secrets\master
   ```

   Simpan `master_policy.key` secara privat di Master; distribusikan hanya `master_policy.pub` ke cluster.
2. Jalankan cluster lokal terlebih dahulu di terminal PowerShell pertama:

   ```powershell
   python run_dev.py
   ```

   API development tersedia pada `http://127.0.0.1:8000`.
3. Di terminal PowerShell kedua, atur token Master dan jalankan control plane:

   ```powershell
   $masterToken = python -c "import secrets; print(secrets.token_urlsafe(32))"
   $env:MASTER_API_TOKENS = "${masterToken}:admin"
   $env:MASTER_SIGNING_KEY_FILE = (Resolve-Path .\secrets\master\master_policy.key).Path
   $env:TOK_C1 = "dev-admin-token"
   python -m uvicorn app.main:app --app-dir apps/master --host 127.0.0.1 --port 8100
   ```

   Untuk demo lokal, database Master default disimpan terpisah di `data\master.db`. Simpan nilai `$masterToken`; token ini diperlukan untuk mengelola Master.
4. Di terminal ketiga, daftarkan cluster ke Master. `pull_token` hanya ditampilkan sekali:

   ```powershell
   $headers = @{ Authorization = "Bearer $masterToken" }
   $body = @{
     id = "c1"
     name = "Cluster lokal"
     api_url = "http://127.0.0.1:8000"
     status_token_env = "TOK_C1"
     verify_tls = $false
   } | ConvertTo-Json
   $cluster = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8100/api/v1/clusters" `
     -Headers $headers -ContentType "application/json" -Body $body
   $cluster.pull_token
   ```

   `verify_tls = $false` hanya untuk contoh lokal HTTP. Gunakan HTTPS dan verifikasi TLS aktif untuk cluster sungguhan.
5. Hentikan cluster di terminal pertama (`Ctrl+C`), lalu jalankan kembali dengan konfigurasi Master:

   ```powershell
   $env:MASTER_URL = "http://127.0.0.1:8100"
   $env:CLUSTER_ID = "c1"
   $env:MASTER_CLUSTER_TOKEN = "<pull_token-dari-langkah-sebelumnya>"
   $env:MASTER_POLICY_PUBKEY_FILE = (Resolve-Path .\secrets\master\master_policy.pub).Path
   python run_dev.py
   ```

   Cluster akan menarik dan memverifikasi kebijakan Master. Status armada dapat dilihat di `GET /api/v1/clusters`; referensi endpoint, rollout, dan batas kebijakan ada di [`docs/MASTER.md`](docs/MASTER.md). Master development di atas memakai HTTP dan SQLite: **jangan gunakan konfigurasi tersebut untuk produksi**. Master tidak meneruskan event dan bukan HA; cluster tetap berjalan dengan kebijakan terakhir jika Master tidak tersedia.

## Yang dikerjakan engine (alur)

1. **Ingest** `POST /api/v1/ingest/{source}` (header `X-Ingest-Key`) → validasi ukuran/schema → `event_id = uuid5(tenant|source|source_event_id)` (idempoten) → UTC. Mode `queue`: Redis Streams + consumer group, ack setelah commit, retry terbatas, DLQ + replay.
2. **Normalisasi** per produk (`generic`, `wazuh`, `ecs`); payload disanitasi (password/token di-mask).
3. **Enrichment** aset (GLPI/ekspor inventaris), IOC (OpenCTI/file), vuln-scan; cache TTL + timeout; status `ok/partial/stale/missing`, tidak pernah menahan jalur utama.
4. **Semantic integrity (Algoritma 2)**: canonical identity, schema/disjoint-class, domain/range relasi, provenance+confidence, freshness, deteksi konflik. Fakta stale/kontradiktif **dikarantina**, tidak boleh mengaktifkan risk gate.
5. **Risk gate** (IOC terkonfirmasi, vuln dengan exploit publik, aset `core`, progres kill-chain) lalu **FFT-PCC** (peak ratio ≥3, periode 2–72 jam, PCC > 0.85). Periodik **dan** G=0 → difilter. Periodik tetapi G=1 → tetap dianalisis/dipertahankan.
6. **Evidence orchestration**: Master Agent deterministik → Knowledge Retrieval (aturan lokal) + Association Query (plugin Tabel 1) + BERT Reasoning → fusion konservatif `S_TA = Σ ω·c·y + η·G` (≥0.60 retain, ≤0.30 filter, selain itu review manual; filter hanya bila ≥2 cabang yakin FP **dan** konteks aset/enrichment lengkap).
7. **Skor AHP** deterministik (`R = min(100, 100·ΣW_i·C_i·E_ext·E_int)`), semua komponen/provenance/versi formula/snapshot graph disimpan per alert. Level: High ≥80, Medium 60–<80, Low <60.
8. **Fast path**: event + skor + outbox dalam satu transaksi → indexer (outbox → Elasticsearch, atau SQL bila ES tidak ada).
9. **Asinkron**: RAG worker (KB: ATT&CK/playbook via Neo4j/Cypher atau tabel `kb_items`) → Ollama/LLM → validasi rujukan (klaim yang mengutip sumber di luar bukti dibuang) → simpan + outbox. LLM **tidak** mengubah skor / menghapus alert / menulis ke KB.
10. **kb_sync**: jadwal harian 01:00 Asia/Jakarta, distributed lease + catch-up, diff checksum, rollback. Kandidat teknik baru → antrean review analis.

Retriever membatasi bukti berdasarkan tenant (`tenant_ids` pada data KB; tanpa daftar berarti materi bersama `["*"]`) dan mengabaikan item yang melewati `KB_STALE_DAYS`. Jika Neo4j dikonfigurasi tetapi retrieval gagal, job RAG dicatat dan dicoba ulang; worker tidak diam-diam beralih ke salinan KB lokal.

## Mencoba SSO tanpa IdP sungguhan
```bash
python scripts/mock_idp.py &                        # IdP tiruan dev di :9200 (tanpa password/MFA — BUKAN untuk produksi)
OIDC_ISSUER=http://127.0.0.1:9200 OIDC_AUDIENCE=soc-api OIDC_CLIENT_ID=soc-ui \
OIDC_ROLE_MAP='{"soc-admin":"admin","soc-analyst":"analyst","soc-viewer":"viewer"}' python run_dev.py
# buka http://localhost:8000 -> "Masuk dengan SSO" (token statis otomatis ditolak saat OIDC aktif)
```
Untuk IdP sungguhan: buat client **publik** (tanpa secret) dengan flow Authorization Code + PKCE, redirect URI `https://<host-anda>/`, izinkan CORS dari origin UI pada endpoint token, dan petakan klaim peran/tenant (`OIDC_ROLE_CLAIM`, `OIDC_ROLE_MAP`, `OIDC_TENANT_CLAIM`; lihat `.env.example`). Entra ID memakai `scope=api://<app>/.default`/klaim `roles`; Keycloak `realm_access.roles`.

## Konektor SIEM / EDR
Splunk ES, Microsoft Sentinel, IBM QRadar, CrowdStrike Falcon, SentinelOne, Microsoft Defender XDR, Palo Alto Cortex XDR, Elasticsearch/Wazuh indexer, plus syslog CEF/LEEF dan webhook generik.
```bash
cp infra/config/connectors.example.json infra/config/connectors.json     # set enabled=true, isi parameter non-rahasia
export CS_CLIENT_SECRET=...                                               # secret hanya lewat env / NAMA_FILE
python -m services.engine.adapters.runner --test crowdstrike-prod         # uji auth+format tanpa menyimpan data
python run_dev.py                                                         # konektor enabled berjalan otomatis; lihat menu "Konektor"
python scripts/mock_vendor_server.py                                      # coba alur tanpa akun vendor
```
Cursor hanya maju setelah event diterima pipeline; overlap + `event_id` idempoten mencegah duplikat; satu konektor rusak tidak menjatuhkan yang lain. **Baca `docs/CONNECTORS.md` (izin minimum, batasan, status verifikasi per produk) sebelum mengaktifkan.**

## Struktur
Sesuai rancangan spesifikasi. Penyimpangan kecil yang disengaja: `services/common/` (config/db/model dipakai bersama API & worker), `services/engine/{noise,agents,graph}/` (logika paper), dan tanpa folder `repositories/` (query ada di `apps/api/app/services/queries.py`).

## ⚠ Temuan verifikasi paper (baca sebelum dipakai operasional)

* **Bobot AHP terpublikasi ≠ hasil hitung matriksnya.** Matriks Tabel 5 menghasilkan bobot ≈ **0.134 / 0.360 / 0.159 / 0.251 / 0.057 / 0.039** (CR ≈ 0.043), sedangkan paper menulis **0.16 / 0.31 / 0.18 / 0.22 / 0.07 / 0.06** (CR 0.041). Default memakai bobot terpublikasi (sesuai spesifikasi). Untuk membandingkan: `GET /api/v1/config/scoring/verify`; untuk memakai hasil hitung ubah `weights_source` menjadi `matrix` di `infra/config/scoring_v1.json`. Putuskan lewat validasi pada data berlabel milik Anda.
* **Parameter yang tidak diberikan paper** dan saya isi sebagai *asumsi awal yang harus dikalibrasi*: bobot cabang fusion (ω=0.30 ×3, η=0.10), hazard per taktik ATT&CK, bobot kebijakan fase (tahap akhir kill-chain lebih tinggi), half-life freshness IOC (30 hari), batas freshness per sumber, aturan ambang knowledge rule, pemetaan lingkungan→kriteria (Baseline v1: E_ext=E_int=1.0, kriteria lingkungan 0/1).
* Paper memilih puncak FFT dominan di seluruh spektrum dan `p=round(N/k*)`. Di streaming nyata N bukan kelipatan periode (mis. 163 jam → p=23, bukan 24) sehingga PCC anjlok; implementasi ini mencari puncak pada rentang 2–72 jam dan menguji periode bulat di sekitar bin puncak (tetap wajib lolos PCC>0.85 dan risk gate).
* Angka kinerja paper (AUC 0.973, −45.2% MTTR, dst.) **tidak direproduksi** di sini: dataset aslinya tidak dirilis penuh, dan model BERT hasil fine-tuning tidak tersedia.

## Status verifikasi (jujur)

| Bagian | Status |
|---|---|
| FFT-PCC, risk gate, integrity, AHP, pipeline, fusion, API+RBAC+tenant, case workflow, RAG worker (template), outbox/indexer (SQL), KB importer+rollback+lease, backup SQLite+verify+retensi, Redis Streams (retry/DLQ/replay, via fakeredis) | **Diuji otomatis** (145 tes Python — lulus di SQLite **dan** PostgreSQL 16 + Redis nyata — + 9 tes vitest di `apps/web`) + demo end-to-end |
| Impor MITRE ATT&CK resmi (STIX) | Diuji sungguhan (706 teknik) |
| UI React | Type-check + build lolos; tampilan belum diuji visual lintas peramban |
| **PostgreSQL 16 + Redis (nyata)** | **Diuji**: seluruh suite (145 tes), migrasi SQL, `pg_dump`/`pg_restore`, Redis Streams multi-proses, uji `kill -9` worker, DUMP/RESTORE Redis. Menemukan & memperbaiki bug konkurensi yang tidak muncul di SQLite (lihat `docs/LOADTEST.md`) |
| Elasticsearch 8.14.3 + Neo4j 5 (Docker Compose staging) | **Diuji langsung** lewat Compose network: ES create mapping, upsert, refresh, search lalu cleanup; Cypher `Technique`/`Tactic`/`Playbook`, freshness, dan filter tenant lewat retriever lulus. Docker Compose `up` serta `run --no-deps` berhasil. Gunakan `scripts/staging_smoke.py` untuk mengulang tes pada staging Anda |
| Ollama, Gemini, OpenAI, OpenAI-compatible, OpenCTI GraphQL | **Belum diuji live**: endpoint/API key belum dikonfigurasi untuk staging. Klien Gemini, OpenAI-compatible, dan Ollama diuji dengan respons tiruan; OpenCTI provider gagal eksplisit untuk error GraphQL/response schema yang tidak sesuai. Atur provider AI di `.env`, lalu validasi di akun staging sebelum penggunaan operasional. |
| GLPI REST | Provider ada (`services/engine/enrichment/glpi.py`): initSession/search/killSession sesuai dokumentasi GLPI, pemetaan field berbasis konfigurasi (`infra/config/glpi.example.json`), nilai tak terpetakan diabaikan. Diuji dengan respons tiruan; **belum** dengan instance GLPI nyata. ID field kritikalitas/sensitivitas bersifat khas instalasi (lihat `--list-options`) |
| Konektor Splunk ES, Sentinel, QRadar, CrowdStrike, SentinelOne, Defender, Cortex XDR, Elasticsearch/Wazuh, syslog CEF/LEEF | **Ada** (polling + checkpoint + retry/rate-limit + status di UI). Diuji dengan respons tiruan bentuk-dokumentasi dan CrowdStrike lewat HTTP nyata ke server tiruan. **Belum diuji terhadap tenant vendor sungguhan**; 5 dari 8 endpoint dicocokkan dengan dokumentasi, Splunk/QRadar/Elasticsearch ditulis dari pengetahuan dokumentasi. Rincian & batasan: `docs/CONNECTORS.md` |
| BERT | Default `HeuristicReasoner` (leksikal, **bukan** BERT). Tersedia `scripts/export_training_data.py` + `scripts/train_bert.py` (split bebas-kebocoran per-triplet/kronologis, metrik, kalibrasi ambang yang melindungi alert asli — **diuji**). **Loop pelatihan dijalankan sungguhan** (torch 2.15/transformers 5.22) pada BERT mini acak: plumbing, penyimpanan, kalibrasi, dan pembacaan oleh engine diuji (menemukan & memperbaiki bug **label terbalik** + pengaman collapse). **Kualitas pada BERT-base dan data alert asli belum pernah diukur** (tanpa akses Hub/data). Label harus dari tiket/analis, bukan dari `disposition` sistem sendiri |
| Backup | SQLite/pg_dump (**pg_dump+restore diuji di PostgreSQL nyata**) + Redis DUMP/RESTORE (diuji, termasuk consumer group/PEL) + export logis KG Neo4j (logika diuji dengan store memori; `Neo4jStore` belum dengan server nyata) + **enkripsi AES-256-GCM** (tamper/truncation terdeteksi; plaintext dihapus) + manifest checksum + retensi + `--restore` (diuji). Snapshot Elasticsearch ditulis (diuji dengan respons tiruan, **belum** dengan cluster). Dump fisik Neo4j (`neo4j-admin`) tidak diotomasi. Uji pemulihan penuh ke instans produksi belum dilakukan |
| Auth | Token statis (dev) + RBAC + tenant. **OIDC bearer JWT** (JWKS, RS256/ES256 saja, tolak `none`/HS256-confusion, iss/aud/exp wajib, peran & tenant dari klaim, tanpa default role) — diuji dengan IdP tiruan. MFA dilakukan di IdP. **Login SSO di UI** = Authorization Code + PKCE (S256, `state` anti-CSRF, code/state dibuang dari URL, token hanya di sessionStorage) — diuji dengan IdP tiruan (`scripts/mock_idp.py`) dan vektor RFC 7636. **Belum:** uji terhadap IdP sungguhan (Keycloak/Entra/Okta; perhatikan CORS endpoint token & pendaftaran redirect URI `https://<host>/`), refresh token / silent renew (sesi berakhir saat token kedaluwarsa → login ulang), validasi `id_token`/nonce (UI hanya memakai access token) |
| Kinerja | Fast path ≈ 140–250 event/dtk (SQLite, 1 proses); dengan PostgreSQL+Redis+worker pada **1 core** sandbox: 118 event/dtk (commit per-batch). Ketahanan `kill -9` terbukti; **kapasitas/skala horizontal belum terukur** (sandbox 1 core). Rincian & batasan: `docs/LOADTEST.md` |
| Master (control plane) | **Ada** (`apps/master`, `docs/MASTER.md`): registri cluster, kebijakan bertanda tangan Ed25519, UI konfigurasi per-cluster dengan enkripsi secret at-rest, agent Kubernetes untuk ConfigMap/Secret + rolling restart, serta KEDA (lag Redis Streams) dan HPA (CPU) untuk autoscaling Pod. Tanda tangan, enkripsi, API, dan agent diuji dengan tes; **belum diuji pada cluster Kubernetes/KEDA sungguhan atau dibenchmark pada beban enterprise**. Master tidak membuat node/cluster cloud. Belum: HA Master, rotasi kunci, provisioning node |

## Keamanan (ringkas)
Secret lewat env/`*_FILE` (Docker secrets); `.env.example` tanpa nilai rahasia. Token dev **wajib diganti**. Tenant difilter di backend pada setiap query (404 lintas tenant). Sort/filter di-whitelist. Isi log & dokumen KB diperlakukan sebagai data tidak tepercaya di prompt LLM; model tanpa akses tool.
