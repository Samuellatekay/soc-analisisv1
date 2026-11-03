# Instalasi SOC Analisis di Kubernetes

Panduan ini memasang satu cluster SOC pada satu namespace Kubernetes. Ulangi dengan `CLUSTER_ID` dan namespace berbeda untuk setiap cluster. Database dan layanan data berjalan di luar namespace (misalnya layanan terkelola); manifest tidak membuat PostgreSQL, Redis, Elasticsearch, atau Neo4j.

> **Penting:** overlay `cluster-template` menambahkan `policy-agent` dan `configuration-agent`, jadi harus dapat menghubungi Master dan memerlukan token cluster serta public key Master saat Pod dibuat. Siapkan Master dan daftarkan cluster sebelum menerapkan overlay. Panduan Master ada di [`MASTER.md`](MASTER.md).

## 1. Prasyarat

Siapkan:

- Kubernetes 1.27+, `kubectl`, Kustomize (`kubectl kustomize` sudah cukup), Helm, registry image yang dapat diakses semua node, ingress controller, DNS, sertifikat TLS, dan StorageClass yang menyediakan PVC `ReadWriteOnce` 100 GiB.
- PostgreSQL yang dapat dijangkau dari namespace SOC, Redis 7+, Elasticsearch/OpenSearch dengan HTTPS, dan Neo4j. Gunakan kredensial unik, TLS, firewall/network policy, serta connection pool yang sesuai jumlah replika.
- Master yang dapat dijangkau dari cluster melalui HTTPS. Simpan `MASTER_CLUSTER_TOKEN` dan `MASTER_POLICY_PUBKEY` untuk cluster tersebut.
- Secret Manager/Kubernetes Secret at-rest encryption. Jangan simpan `.env`, private key, token, Secret yang dirender, atau file credential di Git.

Periksa context yang akan dipakai:

```bash
kubectl config current-context
kubectl cluster-info
kubectl get storageclass
```

Pastikan context di atas benar sebelum membuat namespace atau menerapkan manifest.

## 2. Siapkan Master dan token cluster

Jika Master UI belum berjalan, lihat bagian setup Master di [`MASTER.md`](MASTER.md). Daftarkan cluster lebih dahulu dari UI, lalu simpan pull token yang hanya ditampilkan sekali. Salin token dan `master_policy.pub` ke lokasi aman yang hanya dapat dibaca operator.

Pilih nilai contoh untuk deployment ini:

| Nilai | Contoh |
|---|---|
| Namespace | `soc-cluster-01` |
| Cluster ID di Master | `soc-cluster-01` |
| Host UI | `soc-cluster-01.example.com` |
| Master URL yang dapat dijangkau Pod | `https://master.example.com` |
| Image tag | `v1.0.0` |

Ganti contoh-contoh tersebut dengan nilai lingkungan Anda. `CLUSTER_ID` harus sama persis dengan ID cluster yang didaftarkan di Master.

Jika Master juga perlu menampilkan health/status cluster, saat registrasi berikan `status_token_env` dan pastikan Master memiliki environment variable dengan nama tersebut, berisi token admin API cluster. Jangan memasukkan nilai token ke `status_token_env`.

## 3. Build dan push image

Untuk VM dua node ini, `192.168.33.140` adalah **VM master/control-plane Kubernetes** (`mira`), bukan worker. Registry internal contoh ini dijalankan pada VM tersebut di port `5000` dan menyimpan image di `/srv/registry`; worker `192.168.33.141` menarik image dari alamat itu. Ini hanya pilihan untuk lab. Untuk production, lebih baik host registry terpisah/terkelola agar registry tetap tersedia saat control-plane maintenance atau gagal.

> **Lab saja:** contoh ini tidak mengaktifkan TLS atau autentikasi registry. Jangan expose port 5000 ke internet atau jaringan yang tidak dipercaya. Untuk production, gunakan registry dengan HTTPS, autentikasi, dan storage yang dibackup.

Registry container di port `5000` berbeda dari aplikasi **SOC Master** di port `8100`: Kubernetes control-plane mengatur node/Pod, SOC Master mengatur konfigurasi SOC, sedangkan registry hanya menyimpan image container.

### 3.1 Jalankan registry pada control-plane

Docker daemon tidak diperlukan. Pasang Podman di control-plane (node `mira`):

```bash
sudo apt update
sudo apt install -y podman
sudo mkdir -p /srv/registry
sudo chown 1000:1000 /srv/registry
```

Gunakan Quadlet agar registry otomatis hidup kembali setelah VM reboot:

```bash
sudo mkdir -p /etc/containers/systemd
sudo tee /etc/containers/systemd/soc-registry.container >/dev/null <<'EOF'
[Unit]
Description=Private SOC container registry

[Container]
Image=docker.io/library/registry:2
ContainerName=soc-registry
PublishPort=5000:5000
Volume=/srv/registry:/var/lib/registry

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl start soc-registry.service
curl --fail http://127.0.0.1:5000/v2/
```

Perintah `curl` harus mengembalikan `{}`. Dari worker `node`, pastikan `curl --fail http://192.168.33.140:5000/v2/` juga mengembalikan `{}`. Batasi firewall port 5000 hanya untuk alamat node/mesin build yang perlu mengaksesnya. Contoh jika UFW aktif:

```bash
sudo ufw allow from 192.168.33.140 to any port 5000 proto tcp
sudo ufw allow from 192.168.33.141 to any port 5000 proto tcp
```

### 3.2 Konfigurasikan containerd di kedua node

Jalankan langkah berikut di `mira` dan `node`. Pastikan containerd menggunakan `/etc/containerd/certs.d` sebagai registry config path; periksa konfigurasi aktif terlebih dahulu:

```bash
sudo containerd config dump | grep -n -A8 -B2 'config_path'
```

Jika config path belum disetel, tambahkan `config_path = "/etc/containerd/certs.d"` pada bagian registry plugin yang sesuai dengan format config containerd 2.x Anda di `/etc/containerd/config.toml`; jangan menimpa konfigurasi cluster yang sudah ada. Kemudian buat host config:

Untuk containerd 2.x, bagian konfigurasi yang diperlukan adalah:

```toml
[plugins."io.containerd.cri.v1.images".registry]
  config_path = "/etc/containerd/certs.d"
```

Jika bagian plugin sudah ada, tambahkan hanya baris `config_path` ke bagian itu. Jangan membuat tabel duplikat.

```bash
sudo mkdir -p /etc/containerd/certs.d/192.168.33.140:5000
sudo tee /etc/containerd/certs.d/192.168.33.140:5000/hosts.toml >/dev/null <<'EOF'
server = "http://192.168.33.140:5000"

[host."http://192.168.33.140:5000"]
  capabilities = ["pull", "resolve"]
EOF
```

Jika Anda mengubah `/etc/containerd/config.toml`, restart containerd pada satu node pada satu waktu dan pastikan node kembali `Ready` sebelum melanjutkan:

```bash
sudo systemctl restart containerd
sudo systemctl is-active containerd
kubectl get nodes
```

### 3.3 Build dan push dari root repository

Di mesin yang memiliki source code dan Buildah, gunakan registry IP yang bisa dijangkau kedua node:

```bash
sudo apt update
sudo apt install -y buildah
cd /home/mira/soc-analisisv1
export REGISTRY=192.168.33.140:5000
export RELEASE=v1.0.0

buildah bud -f infra/docker/python.Dockerfile \
  -t "$REGISTRY/soc-analisis-api:$RELEASE" .
buildah bud -f infra/docker/web.Dockerfile \
  -t "$REGISTRY/soc-analisis-web:$RELEASE" .
buildah push --tls-verify=false "$REGISTRY/soc-analisis-api:$RELEASE"
buildah push --tls-verify=false "$REGISTRY/soc-analisis-web:$RELEASE"
```

Tidak diperlukan login untuk registry lab tanpa autentikasi ini. Jika build memakai root Buildah, jalankan seluruh perintah build dan push dengan user/lingkungan yang sama agar image lokalnya terlihat.

### Jika build/push gagal

- `short-name ... did not resolve`: gunakan perubahan Dockerfile yang memakai `docker.io/...` untuk seluruh image dasar dan build ulang.
- `connection refused` atau timeout ke `192.168.33.140:5000`: periksa service registry, firewall, routing antar node, dan hasil `curl http://192.168.33.140:5000/v2/`.
- `server gave HTTP response to HTTPS client`: config `hosts.toml` atau containerd `config_path` belum terbaca; pastikan direktori host registry tepat dan config path aktif pada kedua node.
- `403 Forbidden`: contoh registry internal ini tidak memakai autentikasi. Error 403 berarti Anda masih mengarah ke GHCR/registry lain, atau registry yang dipilih memiliki autentikasi sendiri.
- `image ... not known`: build image terkait belum berhasil secara lokal; selesaikan build sebelum push.

## 4. Buat overlay khusus cluster

Salin template, lalu edit overlay baru agar perubahan tidak tercampur dengan template:

```bash
cp -a deploy/kubernetes/overlays/cluster-template deploy/kubernetes/overlays/soc-cluster-01
```

Di `deploy/kubernetes/overlays/soc-cluster-01/kustomization.yaml`:

1. Pastikan `namespace` adalah `soc-cluster-01`.
2. Set `newName` ke `192.168.33.140:5000/soc-analisis-api` dan `192.168.33.140:5000/soc-analisis-web`, lalu set `newTag` ke `$RELEASE`.

Edit `namespace-patch.yaml` sehingga nama Namespace `soc-cluster-01`. Edit `config-patch.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: soc-config
data:
  ELASTICSEARCH_URL: https://es.example.com:9200
  NEO4J_URI: neo4j+s://neo4j.example.com:7687
  LLM_PROVIDER: none
  MASTER_URL: https://master.example.com
  CLUSTER_ID: soc-cluster-01
```

Sesuaikan `ingress-patch.yaml` dengan DNS dan nama Secret TLS. NetworkPolicy pada base mengasumsikan ingress controller berada pada namespace `ingress-nginx`; sesuaikan label selector jika berbeda.

## 5. Siapkan namespace dan Secret

Buat namespace dengan Pod Security Restricted. Jika namespace sudah ada, perintah label aman dijalankan kembali:

```bash
kubectl create namespace soc-cluster-01 --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace soc-cluster-01 \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite
```

### TLS untuk lab

`/secure/path/tls.crt` dan `/secure/path/tls.key` adalah placeholder, bukan file bawaan. Untuk lab, buat sertifikat self-signed. `HOST` harus sama dengan host di `ingress-patch.yaml`:

```bash
HOST=soc-cluster-01.example.com
sudo install -d -m 700 /root/soc-certs
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout "/root/soc-certs/$HOST.key" \
  -out "/root/soc-certs/$HOST.crt" \
  -subj "/CN=$HOST" \
  -addext "subjectAltName=DNS:$HOST"

kubectl -n soc-cluster-01 create secret tls soc-analisis-tls \
  --cert="/root/soc-certs/$HOST.crt" \
  --key="/root/soc-certs/$HOST.key"
```

Sertifikat self-signed membuat browser menampilkan peringatan dan hanya cocok untuk uji coba. Untuk production, gunakan sertifikat dari CA tepercaya atau cert-manager, dan arahkan DNS host Ingress ke alamat Ingress controller. Jaga file private key; jangan commit ke Git atau kirim melalui chat.

Jika Secret TLS sudah ada dan ingin memperbaruinya, perintah berikut membuat manifest langsung melalui pipe (tidak menyimpan Secret ke file):

```bash
kubectl -n soc-cluster-01 create secret tls soc-analisis-tls \
  --cert="/root/soc-certs/$HOST.crt" \
  --key="/root/soc-certs/$HOST.key" \
  --dry-run=client -o yaml | kubectl apply -f -
```

### Apa itu `soc-runtime`?

`soc-runtime` adalah **Secret Kubernetes**: tempat Kubernetes menyimpan password/token lalu menyediakannya ke Pod SOC. File `soc-runtime.env` di bawah hanya file sementara di VM untuk memasukkan nilai ke Secret; file ini bukan file konfigurasi aplikasi dan jangan diletakkan di repository.

Buat folder dan file tersebut pada VM control-plane. `/root/soc-cluster-01/` adalah contoh lokasi aman, bukan path wajib:

```bash
sudo install -d -m 700 /root/soc-cluster-01
sudo nano /root/soc-cluster-01/soc-runtime.env
```

Isi file dengan nilai koneksi **milik Anda yang benar-benar aktif**. Contoh berikut menunjukkan format saja; alamat `*.example.com` dan teks `GANTI_...` harus diganti:

```dotenv
DATABASE_URL=postgresql+psycopg://soc:URL_ENCODED_PASSWORD@postgres.example.com:5432/soc?sslmode=require
REDIS_URL=rediss://redis.example.com:6379/0
INGEST_API_KEY=GANTI_DENGAN_TOKEN_INGEST:default
API_TOKENS=GANTI_TOKEN_ADMIN:admin:default,GANTI_TOKEN_ANALYST:analyst:default
NEO4J_PASSWORD=GANTI_PASSWORD_NEO4J
```

Arti tiap baris:

- `DATABASE_URL`: alamat PostgreSQL eksternal yang bisa dijangkau Pod. Ganti username, password, host, port, dan nama database. Contoh host bukan server PostgreSQL sungguhan.
- `REDIS_URL`: alamat Redis untuk antrean. `rediss://` berarti koneksi TLS; gunakan format/skema yang disediakan layanan Redis Anda.
- `INGEST_API_KEY`: kunci pengiriman alert dengan format `nilai-rahasia:tenant`; contoh tenant di sini `default`.
- `API_TOKENS`: token untuk login UI/API, format `token:role:tenant`, dipisah koma. Role contoh `admin` dan `analyst`; buat token acak sendiri. Jika login OIDC belum dikonfigurasi, baris ini diperlukan untuk masuk.
- `NEO4J_PASSWORD`: password untuk Neo4j pada host `NEO4J_URI` di ConfigMap.

Simpan dan keluar dari editor, kemudian kunci izin file:

```bash
sudo chmod 600 /root/soc-cluster-01/soc-runtime.env
```

Jangan menambahkan tanda kutip di sekitar nilai pada file env. Jika password URL mengandung karakter khusus seperti `@`, encode sebagai URL (misalnya `@` menjadi `%40`). `sslmode=require` mewajibkan TLS PostgreSQL. Tambahkan baris `ELASTICSEARCH_API_KEY=...`, `LLM_API_KEY=...`, `OPENCTI_TOKEN=...`, atau secret konektor hanya jika layanan tersebut digunakan; URL Elasticsearch sudah diatur di `config-patch.yaml`.

Manifest contoh mengaktifkan backup. `BACKUP_ENCRYPTION_KEY` dipakai untuk mengenkripsi hasil backup dan dipasang dari Secret yang sama. Buat key satu kali dari root repository:

```bash
cd /home/mira/soc-analisisv1
sudo .venv/bin/python -m services.backup.crypto genkey /root/soc-cluster-01/backup.key
```

Simpan file `backup.key` dengan aman dan buat salinan cadangan di lokasi terpisah. Tanpa key yang sama, backup terenkripsi lama tidak bisa dipulihkan.

File `master_policy.pub` yang Anda temukan berada di `/home/mira/soc-analisisv1/secrets/master/master_policy.pub`; file itu boleh digunakan langsung atau disalin ke folder rahasia cluster. `cluster-pull-token` **tidak dibuat sebagai file otomatis**. Token awal hanya ditampilkan saat registrasi cluster di SOC Master. Jika token awal hilang dan cluster sudah terdaftar, admin Master bisa menerbitkan token baru; tindakan ini langsung membatalkan token lama.

Buat folder dan salin public key ke lokasi yang digunakan pada perintah Secret:

```bash
sudo install -d -m 700 /root/soc-cluster-01
sudo cp /home/mira/soc-analisisv1/secrets/master/master_policy.pub \
  /root/soc-cluster-01/master_policy.pub
sudo chmod 644 /root/soc-cluster-01/master_policy.pub
```

Pastikan Master API sudah berjalan di port `8100` dan endpoint rotasi tersedia. Jalankan pemeriksaan ini di terminal kedua; terminal pertama harus tetap menjalankan Master:

```bash
curl -fsS http://127.0.0.1:8100/openapi.json \
  | jq -r '.paths | keys[] | select(. == "/api/v1/clusters/{cluster_id}/rotate-token")'
```

Jika path tidak muncul, Master yang sedang berjalan belum memuat endpoint. Perbarui/restart Master dengan versi repo yang berisi `POST /api/v1/clusters/{cluster_id}/rotate-token`, lalu ulangi pemeriksaan. Jika `curl` menyatakan connection refused, Master tidak berjalan di port `8100`; mulai Master menggunakan cara dan konfigurasi/database yang sama seperti sebelumnya. Jangan memulai instance kedua pada port yang sudah dipakai.

#### Token admin Master dan pull token cluster

Ada **dua token berbeda** untuk dua layanan berbeda:

| Token | Dipakai untuk | Bentuk penyimpanan |
|---|---|---|
| Master API bearer token (role `admin`) | Login ke Master UI/API dan memanggil endpoint admin Master, termasuk menerbitkan pull token | Master membaca entri `TOKEN:admin` dari `MASTER_API_TOKENS` atau `MASTER_API_TOKENS_FILE`; header request hanya berisi `TOKEN` |
| Pull token cluster | Agent cluster meminta kebijakan dari Master | Disimpan di Secret Kubernetes sebagai `MASTER_CLUSTER_TOKEN` |

Tidak ada token terpisah bernama “token admin” dan “token API Master”: token admin adalah **Master API bearer token yang diberi role `admin`**. Saat diminta `Authorization: Bearer ...`, masukkan hanya bagian `TOKEN`, jangan sertakan `:admin`. Token API untuk SOC cluster (misalnya `API_TOKENS`) adalah credential layanan lain dan tidak otomatis berhak ke Master. Pull token cluster juga berbeda dan tidak dapat dipakai untuk endpoint admin.

Master tidak dapat menampilkan kembali token yang hilang. Jika Master API token yang ber-role admin masih tersimpan, gunakan nilai sebelum `:admin`; jika hilang/lupa, buat token baru di konfigurasi Master dan restart Master menggunakan konfigurasi itu.

##### Menampilkan token yang tersimpan

Jika memang perlu melihat token, jalankan perintah berikut langsung di terminal lokal VM yang tepercaya. Perintah akan menampilkan rahasia di layar; jangan kirim output, screenshot, atau salin nilainya ke chat.

Token admin yang sebelumnya disimpan sebagai nilai mentah:

```bash
sudo cat /root/soc-cluster-01/master-admin-token
```

Jika menggunakan file konfigurasi `master-api-tokens`, tampilkan entri konfigurasi:

```bash
sudo cat /root/soc-cluster-01/master-api-tokens
```

Format entri adalah `TOKEN:admin` (atau beberapa entri dipisahkan koma). Untuk autentikasi API, gunakan bagian token sebelum `:admin`; suffix tersebut hanya penanda role. File ini mungkin berisi beberapa token, jadi pilih entri admin yang memang digunakan proses Master.

Pull token cluster yang tersimpan ada di file terpisah:

```bash
sudo cat /root/soc-cluster-01/cluster-pull-token
```

Nilainya dipakai sebagai `MASTER_CLUSTER_TOKEN` oleh cluster, bukan sebagai token admin. Bila file tidak ditemukan, token mungkin belum pernah disimpan di lokasi tersebut. Token pull yang hilang tidak dapat dibaca kembali dari Master; terbitkan token baru melalui langkah rotasi di bawah.

##### A. Buat dan aktifkan token admin

Langkah berikut khusus untuk Master yang dijalankan langsung dengan Uvicorn di VM. Jalankan sebagai `root`, karena contoh ini menyimpan file konfigurasi di `/root`. File berisi `TOKEN:admin`—suffix `:admin` adalah role, **bukan bagian dari token yang dikirim pada header API**.

```bash
sudo install -d -m 700 /root/soc-cluster-01
sudo sh -c 'umask 077; python3 -c "import secrets; print(secrets.token_urlsafe(32) + \":admin\")" > /root/soc-cluster-01/master-api-tokens'
sudo chmod 600 /root/soc-cluster-01/master-api-tokens
```

Hentikan Master lama dengan `Ctrl+C` pada terminal yang menjalankannya. Dari root repository, mulai ulang Master dengan file token tersebut:

```bash
cd /home/mira/soc-analisisv1
export MASTER_API_TOKENS_FILE=/root/soc-cluster-01/master-api-tokens
export MASTER_SIGNING_KEY_FILE=/home/mira/soc-analisisv1/secrets/master/master_policy.key
.venv/bin/python -m uvicorn app.main:app --app-dir apps/master --host 127.0.0.1 --port 8100
```

Biarkan proses ini berjalan. Gunakan terminal kedua untuk langkah berikut. **Pertahankan database dan pengaturan konfigurasi yang sama dengan Master sebelumnya**; jangan restart dengan database baru/kosong. Jika Master berjalan lewat Compose/systemd, atur token melalui secret/config milik service tersebut, bukan perintah Uvicorn di atas. Pastikan file token bisa dibaca oleh service, tetapi tidak oleh pengguna lain.

##### B. Uji Master API bearer token (role `admin`)

Yang diminta untuk autentikasi adalah **Master API bearer token** yang memiliki role `admin`. Jika file berisi `NILAI_TOKEN:admin`, nilai yang dikirim sebagai `Bearer` hanya `NILAI_TOKEN`; jangan sertakan `:admin`. Ini bukan API token SOC dan bukan pull token cluster. Jalankan di terminal kedua. Skrip membaca file konfigurasi, mengambil hanya bagian sebelum `:admin`, lalu memanggil endpoint Master `/api/v1/me`. Token tidak dicetak:

```bash
sudo python3 - <<'PY'
import json
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

entries = Path("/root/soc-cluster-01/master-api-tokens").read_text().strip().split(",")
admins = [entry.rsplit(":", 1)[0] for entry in entries if entry.rsplit(":", 1)[-1] == "admin"]
if not admins or not admins[0]:
    sys.exit("File tidak berisi entri token:admin.")

request = Request(
    "http://127.0.0.1:8100/api/v1/me",
    headers={"Authorization": f"Bearer {admins[0]}"},
)
try:
    with urlopen(request, timeout=5) as response:
        identity = json.load(response)
except HTTPError as error:
    sys.exit(f"Master menolak token (HTTP {error.code}); pastikan Master memakai file konfigurasi ini.")
except URLError as error:
    sys.exit(f"Master tidak dapat dijangkau: {error.reason}")

print(f"Master API bearer token valid; role={identity.get('role')}.")
PY
```

Jika mendapat `401`, pastikan token yang dipakai adalah nilai sebelum `:admin` dan Master aktif dimulai dengan `MASTER_API_TOKENS_FILE` yang benar. Jika token API SOC saja yang berhasil pada layanan SOC, itu tidak membuktikan token tersebut berhak ke Master. Jika koneksi ditolak, Master tidak berjalan di port `8100`. Pemeriksaan ini tidak mengubah token atau data cluster.

##### C. Terbitkan pull token baru untuk cluster

Pastikan endpoint rotasi muncul di OpenAPI dan `c1` adalah ID cluster yang sudah terdaftar. Skrip berikut membaca token admin dari file yang sama, mengirim **hanya token mentah** ke API, lalu menyimpan pull token baru dengan permission `600`. Ganti `c1` jika ID cluster Anda berbeda:

```bash
sudo python3 - <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

root = Path("/root/soc-cluster-01")
entries = (root / "master-api-tokens").read_text().strip().split(",")
admins = [entry.rsplit(":", 1)[0] for entry in entries if entry.rsplit(":", 1)[-1] == "admin"]
if not admins or not admins[0]:
    sys.exit("File tidak berisi entri token:admin; rotasi dibatalkan.")

request = Request(
    "http://127.0.0.1:8100/api/v1/clusters/c1/rotate-token",
    data=b"",
    headers={"Authorization": f"Bearer {admins[0]}"},
    method="POST",
)
try:
    with urlopen(request, timeout=10) as response:
        result = json.load(response)
except HTTPError as error:
    sys.exit(f"Rotasi gagal (HTTP {error.code}); pastikan token admin valid dan cluster c1 terdaftar.")
except URLError as error:
    sys.exit(f"Master tidak dapat dijangkau: {error.reason}")

token = result.get("pull_token")
if not isinstance(token, str) or not token:
    sys.exit("Respons Master tidak berisi pull_token; file tidak diubah.")

output = root / "cluster-pull-token"
fd, temp_name = tempfile.mkstemp(prefix=".cluster-pull-token.", dir=root)
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w") as temp_file:
        temp_file.write(token)
        temp_file.flush()
        os.fsync(temp_file.fileno())
    os.replace(temp_name, output)
except Exception:
    try:
        os.unlink(temp_name)
    except FileNotFoundError:
        pass
    raise

print("Pull token baru tersimpan di /root/soc-cluster-01/cluster-pull-token.")
PY
```

Rotasi langsung membatalkan pull token sebelumnya. Perbarui Secret `soc-runtime` dengan token baru sebelum workload berikutnya memakai Master. Jika mendapat `401`, konfigurasi token admin pada Master aktif tidak cocok; jika `404`, pastikan ID cluster benar. Jangan gunakan atau menyalin token lama.

Jika percobaan terdahulu membuat file token, periksa keberadaannya tanpa menampilkan isinya; file kosong atau token lama yang sudah dirotasi jangan digunakan:

```bash
test -s /root/soc-cluster-01/cluster-pull-token \
  && echo "token file berisi data" \
  || echo "token file kosong/tidak ada; jangan gunakan"
```

### Membuat Secret `soc-runtime`

`kubectl create secret generic` **tidak mendukung** `--from-env-file` dan `--from-file` dalam perintah yang sama. Buat file env sementara berizin root-only yang menggabungkan isi file env dan ketiga key, lalu buat Secret dari file gabungan.

Pastikan tiga key berikut **tidak** ada di `soc-runtime.env`: `MASTER_CLUSTER_TOKEN`, `MASTER_POLICY_PUBKEY`, `BACKUP_ENCRYPTION_KEY`. Jalankan dari shell root setelah semua file sumber tersedia:

```bash
set -euo pipefail
umask 077
for source_file in \
  /root/soc-cluster-01/soc-runtime.env \
  /root/soc-cluster-01/cluster-pull-token \
  /root/soc-cluster-01/master_policy.pub \
  /root/soc-cluster-01/backup.key; do
  if [ ! -s "$source_file" ]; then
    echo "File kosong/tidak ada: $source_file" >&2
    exit 1
  fi
done
COMBINED_ENV=$(mktemp /root/soc-cluster-01/soc-runtime-combined.XXXXXX)
trap 'rm -f "$COMBINED_ENV"' EXIT
cat /root/soc-cluster-01/soc-runtime.env > "$COMBINED_ENV"
printf '\nMASTER_CLUSTER_TOKEN=%s\nMASTER_POLICY_PUBKEY=%s\nBACKUP_ENCRYPTION_KEY=%s\n' \
  "$(tr -d '\r\n' < /root/soc-cluster-01/cluster-pull-token)" \
  "$(tr -d '\r\n' < /root/soc-cluster-01/master_policy.pub)" \
  "$(tr -d '\r\n' < /root/soc-cluster-01/backup.key)" \
  >> "$COMBINED_ENV"

kubectl -n soc-cluster-01 create secret generic soc-runtime \
  --from-env-file="$COMBINED_ENV"
```

File gabungan dihapus otomatis saat shell selesai dan hanya dapat dibaca root selama proses berlangsung. `--from-env-file` membuat satu entry Secret untuk tiap baris `KEY=VALUE`; workload API, worker, policy-agent, dan configuration-agent membaca Secret `soc-runtime`.

Periksa bahwa Secret ada tanpa menampilkan isinya:

```bash
kubectl -n soc-cluster-01 get secret soc-runtime
kubectl -n soc-cluster-01 describe secret soc-runtime
```

Jangan memakai `kubectl get secret -o yaml` atau mencetak isi file env ke log/chat karena itu menampilkan kredensial. Perintah `create` di atas hanya untuk pertama kali; jika Secret sudah ada, gunakan secret manager organisasi atau prosedur rotasi Secret yang terkelola—jangan hapus Secret begitu saja, karena Pod membutuhkannya untuk berjalan.

## 6. (Opsional) Pasang KEDA untuk autoscaling

Autoscaling Engine melalui Redis Streams memerlukan KEDA 2.16+ pada cluster. HPA API/Web juga memerlukan metrics-server. Pastikan extension API KEDA tersedia **sebelum mengaktifkan autoscaling di Master**.


6.1. Instal Helm Terlebih Dahulu

Pilih salah satu cara instalasi di bawah ini (disarankan menggunakan manajer paket resmi):
Opsi A: Menggunakan Apt (Disarankan untuk Debian/Ubuntu)
```bash
curl https://baltocdn.com | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
sudo apt-get install apt-transport-https --yes
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com all main" | sudo tee /etc/apt/sources.list.p/helm-stable-debian.list
sudo apt-get update
sudo apt-get install helm -yes
```

6.2. Jalankan Ulang Perintah KEDA Anda

Setelah Helm berhasil terinstal, Anda bisa menjalankan kembali rangkaian perintah Anda sebelumnya:
```bash
# Tambahkan repo KEDA dan update
helm repo add kedacore https://kedacore.github.io/charts
helm repo update

# Instal KEDA v2.16.0
helm upgrade --install keda kedacore/keda \
  --namespace keda --create-namespace --version 2.16.0

# Verifikasi CRD dan API Services (Sekarang seharusnya sudah muncul)
kubectl get crd scaledobjects.keda.sh triggerauthentications.keda.sh
kubectl get apiservices | grep keda

```

Contoh pemasangan KEDA 2.16.0 melalui Helm:

```bash
helm repo add kedacore https://kedacore.github.io/charts
helm repo update
helm upgrade --install keda kedacore/keda \
  --namespace keda --create-namespace --version 2.16.0
kubectl get crd scaledobjects.keda.sh triggerauthentications.keda.sh
kubectl get apiservices | grep keda
```

Untuk production, pilih versi KEDA yang disetujui dan dipelihara organisasi Anda. Jika KEDA belum terpasang, biarkan autoscaling nonaktif di Master. Autoscaling menambah/mengurangi Pod, bukan node; node autoscaling memerlukan Cluster Autoscaler dari penyedia cluster.

## 7. Validasi dan deploy

Sebelum deploy, periksa file overlay dan render manifest. Jangan meneruskan jika output masih berisi contoh registry, host, namespace, atau credential yang tidak sesuai:

```bash
kubectl kustomize deploy/kubernetes/overlays/soc-cluster-01
kubectl diff -k deploy/kubernetes/overlays/soc-cluster-01
```

Terapkan overlay dan tunggu semua workload siap:

```bash
kubectl apply -k deploy/kubernetes/overlays/soc-cluster-01

kubectl -n soc-cluster-01 rollout status deployment/api --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/engine --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/rag-worker --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/indexer --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/connectors --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/kb-sync --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/web --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/policy-agent --timeout=10m
kubectl -n soc-cluster-01 rollout status deployment/configuration-agent --timeout=10m

kubectl -n soc-cluster-01 get pods,svc,ingress,pvc
```

Periksa log Pod yang tidak siap:

```bash
kubectl -n soc-cluster-01 get pods
kubectl -n soc-cluster-01 logs deployment/api --tail=100
kubectl -n soc-cluster-01 logs deployment/policy-agent --tail=100
kubectl -n soc-cluster-01 logs deployment/configuration-agent --tail=100
kubectl -n soc-cluster-01 describe pod POD_NAME
```

Uji readiness API dari dalam cluster dengan port-forward:

```bash
kubectl -n soc-cluster-01 port-forward service/api 8000:8000
```

Di terminal lain:

```bash
curl --fail http://127.0.0.1:8000/api/v1/ready
```

Kemudian buka `https://soc-cluster-01.example.com`, masuk dengan token API yang dibuat, dan uji ingest dari klien yang diizinkan. Di Master UI, pastikan status cluster dan versi konfigurasi berubah menjadi sinkron. Jika mengaktifkan autoscaling, periksa resource KEDA dan HPA:

```bash
kubectl -n soc-cluster-01 get scaledobjects,triggerauthentications,hpa
kubectl -n soc-cluster-01 describe scaledobject engine-autoscaler
```

## 8. Mengelola konfigurasi dan upgrade

- Untuk mengubah runtime, provider AI, konektor, PostgreSQL/Elasticsearch eksternal, atau batas autoscaling setelah onboarding, gunakan Master UI. Perubahan diterbitkan sebagai versi baru; agent menerapkan ConfigMap/Secret lalu melakukan rolling restart.
- Perubahan nilai Secret melalui Master tidak mengembalikan nilai lama di UI. Nilai kosong mempertahankan secret; gunakan kontrol hapus di UI untuk menghapusnya.
- Untuk mengganti tag image, edit `kustomization.yaml`, render/diff ulang, lalu `kubectl apply -k`. Periksa status rollout setiap workload.
- Pantau kapasitas dan koneksi PostgreSQL/Redis/Elasticsearch/Neo4j saat menambah replica. HPA/KEDA tidak menambah kapasitas database atau node Kubernetes.
- Backup PVC lokal bukan backup off-site. Atur replikasi backup, retensi, alerting, uji restore, TLS/egress, dan uji beban untuk lingkungan Anda.

Untuk kegagalan deployment, periksa Events dan log sebelum mengulang rollout. Jangan mencetak Secret ke terminal/log atau mengirimkannya ke tiket/chat. Template ini bukan jaminan HA atau enterprise readiness; uji failover, pemulihan, kapasitas, dan kontrol keamanan di cluster target sebelum produksi.
