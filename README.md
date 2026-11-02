# SOC Analisis

Implementasi dari spesifikasi **SOC Analisis Engine** dan paper *"Intelligent priority awareness method for alert data in SOC threat response"* (J. King Saud Univ. CIS, 2026) 38:776:
risk-gated FFT-PCC noise reduction → evidence orchestration (agen deterministik + BERT) → semantic integrity verification → skor risiko AHP → aplikasi analis (dashboard, alert, case).

## Jalankan (tanpa Docker, 2 menit)

```bash
pip install -r requirements-dev.txt
python run_dev.py                       # http://localhost:8000  (SQLite + worker tertanam + UI hasil build)
# terminal lain:
python scripts/generate_demo_data.py --api http://localhost:8000   # data sintetis ±750 alert
```
Buka http://localhost:8000 → masukkan token `dev-analyst-token` (admin: `dev-admin-token`, viewer: `dev-viewer-token`).
Tes: `python -m pytest -q` (144 tes Python — lulus di SQLite **dan** PostgreSQL 16 + Redis nyata — + 9 tes vitest di `apps/web`). UI dev dengan hot-reload: `cd apps/web && npm install && npm run dev` (port 5173, proxy ke :8000).

Stack penuh (PostgreSQL, Redis Streams, Elasticsearch, Neo4j, worker terpisah): `cp .env.example .env && docker compose -f infra/docker-compose.yml --env-file .env up --build` — lihat "Status verifikasi".

## Instalasi menurut mode operasi

Perintah PowerShell di bawah ditujukan untuk Windows. Mode **Single** menjalankan API dan worker dalam satu proses untuk development/POC. Mode **Orkestrasi** memisahkan API, broker, database, dan worker. **Master bukan mode pemrosesan alert**: ia adalah control plane opsional untuk memantau cluster dan mengirim kebijakan; alert tetap diproses oleh cluster.

### Single (lokal, tanpa Docker)

1. Pasang Python 3.12 atau lebih baru, lalu dari root repo:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements-dev.txt
   ```

2. Jalankan aplikasi:

   ```powershell
   python run_dev.py
   ```

3. Buka `http://localhost:8000`, lalu login dengan token development `dev-analyst-token` (admin: `dev-admin-token`). Server bind ke `0.0.0.0`, sehingga dari perangkat lain di jaringan yang sama gunakan `http://<IP-LAN-komputer>:8000`. Database SQLite dan worker tertanam digunakan secara otomatis. Untuk berhenti, tekan `Ctrl+C`.

Mode ini untuk development/POC, bukan deployment HA atau produksi. Pastikan firewall hanya membuka port yang diperlukan; jangan gunakan token development atau memaparkan server ini langsung ke internet. Ganti token dan gunakan HTTPS, autentikasi, serta secret yang sesuai sebelum akses jaringan yang lebih luas.

Untuk UI hot-reload Vite, jalankan `npm run dev -- --host 0.0.0.0` dari `apps/web`; akses dari perangkat lain melalui `http://<IP-LAN-komputer>:5173`. Proxy API mengarah ke port 8000.

### Orkestrasi (Docker Compose, satu host)

1. Pasang Docker Desktop dengan Docker Compose v2 dan pastikan Docker berjalan.
2. Dari root repo, siapkan konfigurasi:

   ```powershell
   Copy-Item .env.example .env
   Copy-Item infra\config\connectors.example.json infra\config\connectors.json
   ```

3. Edit `.env`: ganti password development, token API, dan ingest key; isi konfigurasi secret yang diperlukan. Jangan gunakan nilai contoh untuk deployment yang dapat diakses pihak lain.
4. Bangun dan jalankan stack:

   ```powershell
   docker compose -f infra\docker-compose.yml --env-file .env up --build
   ```

   UI tersedia di `http://localhost:8080`. Log bisa dilihat dengan `docker compose -f infra\docker-compose.yml --env-file .env logs -f`.
5. Untuk menghentikan stack tanpa menghapus data volume:

   ```powershell
   docker compose -f infra\docker-compose.yml --env-file .env down
   ```

Compose menjalankan PostgreSQL, Redis Streams, Elasticsearch, Neo4j, API, engine, RAG worker, indexer, connector, KB sync, backup, dan web. Untuk menambah worker pada host yang sama, gunakan misalnya `docker compose -f infra\docker-compose.yml --env-file .env up --build --scale engine=2 --scale rag_worker=2`. Ini tetap **single-node development**, bukan HA; jangan gunakan `down -v` kecuali memang ingin menghapus data. Ollama tidak disertakan; tanpa konfigurasi Ollama, RAG menghasilkan analisis template.

### Master (control plane opsional)

Master dijalankan terpisah dari cluster SOC. Contoh berikut menjalankan Master dan satu cluster development secara lokal. Untuk penggunaan nyata, gunakan HTTPS, token unik, secret manager, dan database Master yang dipelihara; jangan mengekspos token atau private key di Git.

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
| FFT-PCC, risk gate, integrity, AHP, pipeline, fusion, API+RBAC+tenant, case workflow, RAG worker (template), outbox/indexer (SQL), KB importer+rollback+lease, backup SQLite+verify+retensi, Redis Streams (retry/DLQ/replay, via fakeredis) | **Diuji otomatis** (144 tes Python — lulus di SQLite **dan** PostgreSQL 16 + Redis nyata — + 9 tes vitest di `apps/web`) + demo end-to-end |
| Impor MITRE ATT&CK resmi (STIX) | Diuji sungguhan (706 teknik) |
| UI React | Type-check + build lolos; tampilan belum diuji visual lintas peramban |
| **PostgreSQL 16 + Redis (nyata)** | **Diuji**: seluruh suite (144 tes), migrasi SQL, `pg_dump`/`pg_restore`, Redis Streams multi-proses, uji `kill -9` worker, DUMP/RESTORE Redis. Menemukan & memperbaiki bug konkurensi yang tidak muncul di SQLite (lihat `docs/LOADTEST.md`) |
| Elasticsearch, Neo4j, Ollama, OpenCTI GraphQL, docker-compose | **Ditulis tetapi belum dijalankan** terhadap layanan sungguhan — uji di staging. Query ES & Cypher mengasumsikan skema tertentu; sesuaikan |
| GLPI REST | Provider ada (`services/engine/enrichment/glpi.py`): initSession/search/killSession sesuai dokumentasi GLPI, pemetaan field berbasis konfigurasi (`infra/config/glpi.example.json`), nilai tak terpetakan diabaikan. Diuji dengan respons tiruan; **belum** dengan instance GLPI nyata. ID field kritikalitas/sensitivitas bersifat khas instalasi (lihat `--list-options`) |
| Konektor Splunk ES, Sentinel, QRadar, CrowdStrike, SentinelOne, Defender, Cortex XDR, Elasticsearch/Wazuh, syslog CEF/LEEF | **Ada** (polling + checkpoint + retry/rate-limit + status di UI). Diuji dengan respons tiruan bentuk-dokumentasi dan CrowdStrike lewat HTTP nyata ke server tiruan. **Belum diuji terhadap tenant vendor sungguhan**; 5 dari 8 endpoint dicocokkan dengan dokumentasi, Splunk/QRadar/Elasticsearch ditulis dari pengetahuan dokumentasi. Rincian & batasan: `docs/CONNECTORS.md` |
| BERT | Default `HeuristicReasoner` (leksikal, **bukan** BERT). Tersedia `scripts/export_training_data.py` + `scripts/train_bert.py` (split bebas-kebocoran per-triplet/kronologis, metrik, kalibrasi ambang yang melindungi alert asli — **diuji**). **Loop pelatihan dijalankan sungguhan** (torch 2.15/transformers 5.22) pada BERT mini acak: plumbing, penyimpanan, kalibrasi, dan pembacaan oleh engine diuji (menemukan & memperbaiki bug **label terbalik** + pengaman collapse). **Kualitas pada BERT-base dan data alert asli belum pernah diukur** (tanpa akses Hub/data). Label harus dari tiket/analis, bukan dari `disposition` sistem sendiri |
| Backup | SQLite/pg_dump (**pg_dump+restore diuji di PostgreSQL nyata**) + Redis DUMP/RESTORE (diuji, termasuk consumer group/PEL) + export logis KG Neo4j (logika diuji dengan store memori; `Neo4jStore` belum dengan server nyata) + **enkripsi AES-256-GCM** (tamper/truncation terdeteksi; plaintext dihapus) + manifest checksum + retensi + `--restore` (diuji). Snapshot Elasticsearch ditulis (diuji dengan respons tiruan, **belum** dengan cluster). Dump fisik Neo4j (`neo4j-admin`) tidak diotomasi. Uji pemulihan penuh ke instans produksi belum dilakukan |
| Auth | Token statis (dev) + RBAC + tenant. **OIDC bearer JWT** (JWKS, RS256/ES256 saja, tolak `none`/HS256-confusion, iss/aud/exp wajib, peran & tenant dari klaim, tanpa default role) — diuji dengan IdP tiruan. MFA dilakukan di IdP. **Login SSO di UI** = Authorization Code + PKCE (S256, `state` anti-CSRF, code/state dibuang dari URL, token hanya di sessionStorage) — diuji dengan IdP tiruan (`scripts/mock_idp.py`) dan vektor RFC 7636. **Belum:** uji terhadap IdP sungguhan (Keycloak/Entra/Okta; perhatikan CORS endpoint token & pendaftaran redirect URI `https://<host>/`), refresh token / silent renew (sesi berakhir saat token kedaluwarsa → login ulang), validasi `id_token`/nonce (UI hanya memakai access token) |
| Kinerja | Fast path ≈ 140–250 event/dtk (SQLite, 1 proses); dengan PostgreSQL+Redis+worker pada **1 core** sandbox: 118 event/dtk (commit per-batch). Ketahanan `kill -9` terbukti; **kapasitas/skala horizontal belum terukur** (sandbox 1 core). Rincian & batasan: `docs/LOADTEST.md` |
| Master (control plane) | **Ada** (`apps/master`, `docs/MASTER.md`): registri cluster, kebijakan bertanda tangan Ed25519 dengan batas keamanan keras + rollout kanari, poller kesehatan, ringkasan armada, audit. Cluster *menarik* kebijakan dan tetap jalan bila Master mati (diuji, termasuk sebagai proses nyata). Belum: UI Master, HA Master, rotasi kunci |

## Keamanan (ringkas)
Secret lewat env/`*_FILE` (Docker secrets); `.env.example` tanpa nilai rahasia. Token dev **wajib diganti**. Tenant difilter di backend pada setiap query (404 lintas tenant). Sort/filter di-whitelist. Isi log & dokumen KB diperlakukan sebagai data tidak tepercaya di prompt LLM; model tanpa akses tool.
