# Konektor SIEM / EDR

Satu kelas per produk (`services/engine/adapters/vendors.py`) + satu fungsi pemetaan (`mappings.py`). Semua konektor: poll terjadwal, paginasi, retry+backoff (429/5xx/jaringan, menghormati `Retry-After`), refresh token pada 401, checkpoint (tabel `connector_state`) yang **hanya maju setelah event diterima pipeline/antrean**, overlap baca-ulang (default 120 dtk) dengan dedupe `event_id` idempoten, dan status kesehatan di UI (menu *Konektor*) / `GET /api/v1/connectors`.

## Cara pakai
```bash
cp infra/config/connectors.example.json infra/config/connectors.json      # edit, set enabled=true
export CS_CLIENT_SECRET=...                                                # secret hanya lewat env / NAMA_FILE
python -m services.engine.adapters.runner --test crowdstrike-prod          # uji auth+format (ambil <=1 event, tidak menyimpan)
python -m services.engine.adapters.runner --once                           # satu siklus
python run_dev.py                                                          # konektor enabled otomatis berjalan (EMBEDDED_CONNECTORS=true)
python scripts/mock_vendor_server.py                                       # server tiruan berbentuk API CrowdStrike untuk mencoba tanpa akun vendor
```

## Matriks produk
| Produk (`type`) | Endpoint | Auth | Izin minimum | Cursor | Status verifikasi |
|---|---|---|---|---|---|
| Splunk ES (`splunk_es`) | `POST :8089/services/search/jobs/export` atas index `notable` | Splunk token (Bearer) | role dengan search pada index notable | `_indextime` | Ditulis dari pengetahuan dokumentasi; **tidak** dicek ulang. Sesuaikan field notable & `index` |
| Microsoft Sentinel (`sentinel`) | ARM `…/Microsoft.SecurityInsights/incidents` (2023-02-01) + `POST …/incidents/{id}/entities` | Entra ID client-credentials, scope `management.azure.com/.default` | *Microsoft Sentinel Reader* pada workspace | `lastModifiedTimeUtc` | Endpoint/filter/nextLink **dicocokkan dengan dokumentasi** |
| IBM QRadar (`qradar`) | `GET /api/siem/offenses` (+`Range`, `filter=last_updated_time > ms`) | header `SEC` (authorized service token) | role dengan akses offenses | `last_updated_time` (ms) | Ditulis dari pengetahuan dokumentasi; **tidak** dicek ulang. IP offense terbatas pada `offense_source` |
| CrowdStrike Falcon (`crowdstrike`) | `GET /alerts/queries/alerts/v2` (FQL) → `POST /alerts/entities/alerts/v2` `{composite_ids}` | OAuth2 client-credentials | scope **Alerts: Read** | `updated_timestamp` | **Dicocokkan dengan dokumentasi** (Detects API lama sudah dihentikan) |
| SentinelOne (`sentinelone`) | `GET /web/api/v2.1/threats` (`createdAt__gte`, `cursor`) | `Authorization: ApiToken` | *Threats.view* | `createdAt` (opsi `updatedAt`) | **Dicocokkan dengan dokumentasi/contoh**; filter `updatedAt__gte` perlu dicek di tenant Anda |
| Microsoft Defender XDR (`defender`) | `GET graph.microsoft.com/v1.0/security/alerts_v2` (`$filter=lastUpdateDateTime`, `@odata.nextLink`) | Entra ID client-credentials, scope Graph `.default` | `SecurityAlert.Read.All` (application) | `lastUpdateDateTime` | **Dicocokkan dengan dokumentasi** |
| Palo Alto Cortex XDR (`cortex_xdr`) | `POST /public_api/v1/alerts/get_alerts_multi_events` | `x-xdr-auth-id` + key (standard) / SHA-256 nonce (advanced) | API key role Viewer | `creation_time`/`detection_timestamp` (ms) | **Dicocokkan dengan dokumentasi**; endpoint ini **legacy** (v2 tersedia) → ubah `alerts_path`, dan cek ulang pemetaan field v2 |
| Wazuh indexer / Elastic Security (`elasticsearch`) | `POST /{index}/_search` | Basic atau `ApiKey` | read pada index alert | `timestamp` / `@timestamp` | Ditulis dari pengetahuan dokumentasi; **tidak** dicek ulang. Wazuh `mapper:"wazuh"`, Elastic `mapper:"ecs"` |
| Syslog CEF/LEEF (`python -m services.engine.adapters.syslog_listener`) | UDP/TCP | – | – | – | Parser diuji; tanpa TLS (pakai relay TLS) |
| Webhook generik | `POST /api/v1/ingest/{source}` | `X-Ingest-Key` | – | – | Diuji |

"Dicocokkan dengan dokumentasi" = path, parameter, dan bentuk respons dicek terhadap dokumentasi/sampel publik vendor saat pembuatan. Semua konektor diuji otomatis dengan respons tiruan (`tests/test_adapters.py`) dan CrowdStrike juga lewat HTTP nyata ke server tiruan. **Tidak satu pun diuji terhadap tenant vendor sungguhan** — jalankan `--test` dan tinjau 20–50 event pertama di UI sebelum mengandalkannya.

## Pemetaan (ke skema internal)
Entitas yang diambil: `src_ip`, `dst_ip`, `host`, `user`, `domain`, `hash`, teknik ATT&CK (regex `Txxxx(.xxx)`), taktik (nama kanonis dari `TA0006 - Credential Access`/`CredentialAccess`/…). Produk EDR (CrowdStrike, SentinelOne, Cortex, Defender) bersifat *host-centric*: alamat host dipetakan ke `dst_ip`/`host` agar lookup aset (GLPI/inventaris) dan skor kritikalitas bekerja; IP eksternal (mis. IP penyerang pada Defender/Cortex/Sentinel) menjadi `src_ip`. Versi pemetaan (`map-v2`) disimpan per konektor.

## Batasan yang perlu diketahui
* **Pembaruan insiden tidak diproses ulang.** Sentinel/QRadar/Cortex dapat mengubah insiden yang sama; `event_id` dibentuk dari ID vendor sehingga perubahan status/severity setelah ingest pertama tidak menimbulkan event baru.
* **Delivery at-least-once.** Dedupe mengandalkan `source_event_id`; ID yang tidak stabil di sisi vendor akan menghasilkan duplikat.
* Splunk: bila ≥ `batch_size` event memiliki `_indextime` yang sama, konektor berhenti dengan error (agar tidak ada event terlewat) → naikkan `batch_size`.
* Defender: `alerts_v2` dibaca habis sebelum cursor maju; bila `max_pages` tercapai, konektor error alih-alih melewati data.
* Rate limit & kuota dikelola per-request (retry), bukan penjadwal global lintas konektor.
* Tidak ada push/webhook native vendor (mis. Event Hub Sentinel, Splunk HEC keluar); polling saja.

## Menambah produk baru
1. `mappings.py`: `map_<produk>(raw) -> dict` + daftarkan di `MAPPERS`.
2. `vendors.py`: kelas turunan `Connector` (`make_client`, `fetch`) + daftarkan di `REGISTRY`.
3. Tambah test di `tests/test_adapters.py` dengan payload representatif (termasuk paginasi, 429, dan satu event yang diterima `normalize`).
