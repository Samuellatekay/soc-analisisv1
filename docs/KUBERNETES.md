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

Cluster ini memakai `containerd`; Docker daemon tidak dibutuhkan oleh Kubernetes, tetapi `docker build` tetap memerlukan Docker Engine. Di VM Ubuntu tanpa Docker, gunakan Buildah. Instal jika belum tersedia:

```bash
sudo apt update
sudo apt install -y buildah
```

Bangun dari root repository. Ganti owner GHCR dengan nama akun/organisasi yang benar-benar memiliki akses menulis package; `mira` di contoh sebelumnya bukan otomatis nama owner GitHub Anda. Nama package harus kecil semua:

```bash
cd /home/mira/soc-analisisv1
export REGISTRY=ghcr.io/samuellatekay
export RELEASE=v1.0.0

buildah bud -f infra/docker/python.Dockerfile \
  -t "$REGISTRY/soc-analisis-api:$RELEASE" .
buildah bud -f infra/docker/web.Dockerfile \
  -t "$REGISTRY/soc-analisis-web:$RELEASE" .
```

Dockerfile menggunakan nama image dasar fully qualified (`docker.io/...`) sehingga Buildah tidak perlu menebak registry untuk nama pendek.

Login GHCR memakai Personal Access Token (classic) dengan izin `write:packages` dan akses ke organisasi/repository tersebut. Jangan tempel token ke command line atau simpan di file repository. Masukkan secara interaktif:

```bash
read -rsp 'GHCR token: ' GHCR_TOKEN; echo
printf '%s' "$GHCR_TOKEN" | buildah login ghcr.io \
  --username Samuellatekay --password-stdin
unset GHCR_TOKEN
```

Pastikan akun/organisasi mengizinkan token itu mem-publish Packages. Jika package terkait repository private, pastikan package memiliki akses ke repository atau token memiliki akses yang diperlukan. Lalu push:

```bash
buildah push "$REGISTRY/soc-analisis-api:$RELEASE"
buildah push "$REGISTRY/soc-analisis-web:$RELEASE"
```

Kalau VM tidak boleh menyimpan credential registry, build image di CI/mesin build tepercaya, push ke registry, lalu gunakan nama image dan tag immutable yang sama pada overlay.

Jika registry private, buat `imagePullSecret` di namespace dan tambahkan `imagePullSecrets` ke Pod template overlay. Jangan menaruh credential registry pada image atau ConfigMap.

### Jika build/push gagal

- `short-name "nginxinc/nginx-unprivileged:..." did not resolve`: Buildah tidak menebak registry untuk nama image pendek. Dockerfile repo sudah memakai `docker.io/nginxinc/...` dan `docker.io/library/...`; tarik perubahan itu atau gunakan Dockerfile yang sudah diperbarui, lalu jalankan ulang **kedua** build.
- `403 Forbidden` saat push ke GHCR: pastikan path image memakai owner GitHub yang benar (nama akun/organisasi yang punya package, bukan nama VM), huruf kecil, dan token yang dipakai `buildah login` memiliki izin `write:packages` serta akses ke package/repository. Untuk akun pribadi `Samuellatekay`, contohnya `ghcr.io/samuellatekay/...`; jika package dimiliki organisasi, ganti dengan owner organisasi itu.
- `image ... web ... not known`: build image web sebelumnya gagal pada `FROM nginxinc/...`, sehingga image lokal untuk di-push memang belum ada. Perbaiki build dahulu; jangan hanya mengulang `push`.

## 4. Buat overlay khusus cluster

Salin template, lalu edit overlay baru agar perubahan tidak tercampur dengan template:

```bash
cp -a deploy/kubernetes/overlays/cluster-template deploy/kubernetes/overlays/soc-cluster-01
```

Di `deploy/kubernetes/overlays/soc-cluster-01/kustomization.yaml`:

1. Pastikan `namespace` adalah `soc-cluster-01`.
2. Ganti `newName` image dengan registry Anda dan `newTag` dengan `$RELEASE`.

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

Buat TLS Secret sesuai host pada ingress:

```bash
kubectl -n soc-cluster-01 create secret tls soc-analisis-tls \
  --cert=/secure/path/tls.crt \
  --key=/secure/path/tls.key
```

Buat file environment Secret di luar repository dengan permission terbatas, misalnya `/secure/path/soc-runtime.env`. Isi key yang diperlukan oleh workload:

```dotenv
DATABASE_URL=postgresql+psycopg://soc:URL_ENCODED_PASSWORD@postgres.example.com:5432/soc?sslmode=require
REDIS_URL=rediss://redis.example.com:6379/0
INGEST_API_KEY=GANTI_DENGAN_TOKEN_INGEST:default
API_TOKENS=GANTI_TOKEN_ADMIN:admin:default,GANTI_TOKEN_ANALYST:analyst:default
NEO4J_PASSWORD=GANTI_PASSWORD_NEO4J
```

Pastikan file hanya dapat dibaca operator, misalnya `chmod 600 /secure/path/soc-runtime.env`.

Tambahkan `ELASTICSEARCH_API_KEY`, `LLM_API_KEY`, `OPENCTI_TOKEN`, atau secret konektor hanya jika dipakai. Password di URL harus percent-encode karakter khusus. Pastikan URL dan kredensial dapat diakses dari Pod; `sslmode=require` pada PostgreSQL mewajibkan TLS.

Manifest mengaktifkan backup dan me-mount key `BACKUP_ENCRYPTION_KEY` dari Secret `soc-runtime`. Buat key sekali, backup secara aman, lalu jangan menggantinya tanpa memastikan backup lama masih dapat didekripsi:

```bash
.venv/bin/python -m services.backup.crypto genkey /secure/path/backup.key
```

Buat Secret runtime dengan Master token dan public key. File token sebaiknya permission `0600`. Untuk instalasi baru:

```bash
kubectl -n soc-cluster-01 create secret generic soc-runtime \
  --from-env-file=/secure/path/soc-runtime.env \
  --from-file=MASTER_CLUSTER_TOKEN=/secure/path/cluster-pull-token \
  --from-file=MASTER_POLICY_PUBKEY=/secure/path/master_policy.pub \
  --from-file=BACKUP_ENCRYPTION_KEY=/secure/path/backup.key
```

Jika Secret sudah ada, jangan menjalankan perintah `create` di atas tanpa strategi update. Gunakan secret manager yang digunakan organisasi, atau buat manifest secara ephemeral dan pipe ke `kubectl apply` tanpa menyimpan manifest di disk.

## 6. (Opsional) Pasang KEDA untuk autoscaling

Autoscaling Engine melalui Redis Streams memerlukan KEDA 2.16+ pada cluster. HPA API/Web juga memerlukan metrics-server. Pastikan extension API KEDA tersedia **sebelum mengaktifkan autoscaling di Master**.

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
