#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
ENV_FILE="$ROOT/.env"
CREDENTIAL_DIR="$ROOT/secrets/install"

if [[ "$EUID" -eq 0 && "$MODE" != orchestration && "$MODE" != orchestration-agent && "$(stat -c '%U' "$ROOT")" != root ]]; then
  exec "$ROOT/scripts/as-repo-owner.sh" bash "$ROOT/scripts/install-mode.sh" "$@"
fi

fail() {
  echo "Error: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 tidak ditemukan."
}

random_hex() {
  openssl rand -hex 32
}

has_env_key() {
  grep -qE "^[[:space:]]*$1=" "$ENV_FILE"
}

env_value_is_set() {
  local value
  value="$(sed -n "s/^[[:space:]]*$1=//p" "$ENV_FILE" | tail -n 1)"
  [[ -n "$value" ]]
}

create_single_env() {
  local admin analyst viewer ingest
  admin="$(random_hex)"
  analyst="$(random_hex)"
  viewer="$(random_hex)"
  ingest="$(random_hex)"
  cat >"$ENV_FILE" <<EOF
HOST=127.0.0.1
DATABASE_URL=sqlite:///data/soc.db
INGEST_MODE=inline
EMBEDDED_WORKERS=true
EMBEDDED_CONNECTORS=true
API_TOKENS=${admin}:admin:default,${analyst}:analyst:default,${viewer}:viewer:default
INGEST_API_KEY=${ingest}:default
LLM_PROVIDER=none
EOF
  printf 'Admin: %s\nAnalyst: %s\nViewer: %s\nIngest API key: %s\n' \
    "$admin" "$analyst" "$viewer" "$ingest" >"$CREDENTIAL_DIR/single.txt"
  chmod 0600 "$ENV_FILE" "$CREDENTIAL_DIR/single.txt"
}

ensure_master_credentials() {
  local token
  if has_env_key MASTER_API_TOKENS; then
    env_value_is_set MASTER_API_TOKENS || fail "MASTER_API_TOKENS di .env kosong; isi token admin sebelum melanjutkan."
    if grep -Eq 'dev-admin-token|GANTI_TOKEN_ADMIN' "$ENV_FILE"; then
      fail "MASTER_API_TOKENS masih memakai placeholder; isi token admin yang kuat."
    fi
    return
  fi
  token="$(random_hex)"
  printf '\nMASTER_API_TOKENS=%s:admin\n' "$token" >>"$ENV_FILE"
  printf 'Master admin token: %s\n' "$token" >"$CREDENTIAL_DIR/master.txt"
  chmod 0600 "$ENV_FILE" "$CREDENTIAL_DIR/master.txt"
}

ensure_master_keys() {
  local policy="$ROOT/secrets/master/master_policy.key"
  local config="$ROOT/secrets/master/master_config.key"
  mkdir -p "$ROOT/secrets/master"
  chmod 0700 "$ROOT/secrets/master"

  if [[ ! -e "$policy" && ! -e "$ROOT/secrets/master/master_policy.pub" ]]; then
    "$ROOT/.venv/bin/python" -m services.master.keys gen "$ROOT/secrets/master"
  elif [[ ! -s "$policy" || ! -s "$ROOT/secrets/master/master_policy.pub" ]]; then
    fail "Pasangan kunci kebijakan Master tidak lengkap; pulihkan backup, jangan buat pasangan baru."
  fi

  if [[ ! -e "$config" ]]; then
    "$ROOT/.venv/bin/python" -m services.master.keys gen-config "$config"
  elif [[ ! -s "$config" ]]; then
    fail "Kunci konfigurasi Master kosong; pulihkan backup, jangan menggantinya."
  fi
  chmod 0600 "$policy" "$config"
}

install_single() {
  require_command openssl
  mkdir -p "$CREDENTIAL_DIR"
  if [[ ! -e "$ENV_FILE" ]]; then
    create_single_env
  else
    echo ".env sudah ada dan tidak akan ditimpa."
    if grep -Eq 'dev-(admin|analyst|viewer)-token|dev-ingest-key' "$ENV_FILE"; then
      fail ".env masih memakai token development. Ganti API_TOKENS dan INGEST_API_KEY sebelum instalasi."
    fi
  fi
  bash "$ROOT/scripts/install.sh"
  echo "Menjalankan SOC Single di http://127.0.0.1:8000 (Ctrl+C untuk berhenti)."
  cd "$ROOT"
  exec "$ROOT/.venv/bin/python" "$ROOT/run_dev.py"
}

check_k3s_host() {
  [[ "$EUID" -eq 0 ]] || fail "Bootstrap K3s memerlukan root. Jalankan: sudo bash scripts/install-mode.sh $MODE ${2:-}"
  require_command curl
  require_command systemctl
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" == ubuntu || "${ID_LIKE:-}" == *debian* ]] ||
      fail "Mode K3s ini mendukung Ubuntu/Debian; terdeteksi ${PRETTY_NAME:-OS tidak diketahui}."
  else
    fail "Tidak dapat membaca /etc/os-release untuk memvalidasi sistem operasi."
  fi
}

existing_kubernetes_conflict() {
  if systemctl is-active --quiet kubelet 2>/dev/null ||
    [[ -e /etc/kubernetes/admin.conf ]] ||
    [[ -e /etc/rancher/k3s/k3s.yaml ]] ||
    [[ -e /etc/rancher/k3s/k3s-agent.yaml ]]; then
    return 0
  fi
  return 1
}

download_and_run_k3s_installer() {
  local installer status
  installer="$(mktemp "${TMPDIR:-/tmp}/soc-k3s-install.XXXXXX")" ||
    fail "Tidak dapat membuat file sementara untuk installer K3s."
  if ! curl --fail --location --silent --show-error https://get.k3s.io --output "$installer"; then
    rm -f -- "$installer"
    fail "Tidak dapat mengunduh installer resmi K3s melalui HTTPS."
  fi
  chmod 0700 "$installer"
  if sh "$installer"; then
    rm -f -- "$installer"
  else
    status=$?
    rm -f -- "$installer"
    return "$status"
  fi
}

install_orchestration_server() {
  local address
  check_k3s_host
  address="${2:-$(hostname -I | awk '{print $1}')}"
  [[ -n "$address" ]] || fail "Alamat node tidak terbaca. Gunakan: sudo bash scripts/install-mode.sh orchestration <IP-node>"

  if systemctl is-active --quiet k3s 2>/dev/null; then
    echo "K3s server sudah aktif; tidak mengubah konfigurasi yang ada."
  else
    if existing_kubernetes_conflict; then
      fail "Ditemukan cluster Kubernetes lama atau konfigurasi K3s. Installer tidak menghapus/reset cluster. Backup dan bersihkan cluster secara terencana terlebih dahulu."
    fi
    echo "Memasang K3s server pada $address..."
    INSTALL_K3S_EXEC="server --write-kubeconfig-mode 600 --tls-san $address" \
      download_and_run_k3s_installer
  fi

  systemctl is-active --quiet k3s || fail "Service K3s server tidak aktif; periksa: journalctl -u k3s -n 100 --no-pager"
  k3s kubectl wait --for=condition=Ready node --all --timeout=180s ||
    fail "Node K3s belum Ready; periksa: k3s kubectl get nodes -o wide"
  echo "K3s server siap di https://$address:6443."
  echo "Token join worker tersimpan di /var/lib/rancher/k3s/server/node-token (jangan kirim lewat chat)."
  echo "Gabungkan worker dengan perintah di README.md menggunakan token tersebut."
  echo "Catatan: langkah ini hanya menyiapkan Kubernetes; aplikasi SOC dan layanan datanya belum dipasang."
}

install_orchestration_agent() {
  local server_url
  check_k3s_host
  server_url="${2:-}"
  [[ "$server_url" =~ ^https://[^[:space:]]+:6443$ ]] ||
    fail "Berikan URL control-plane, misalnya https://192.168.33.140:6443."

  if systemctl is-active --quiet k3s-agent 2>/dev/null; then
    echo "K3s agent sudah aktif; tidak mengubah konfigurasi yang ada."
    return
  fi
  [[ -n "${K3S_TOKEN:-}" ]] || fail "Atur K3S_TOKEN dari node server sebelum menjalankan perintah ini; jangan menaruh token di riwayat shell."
  if existing_kubernetes_conflict; then
    fail "Ditemukan cluster Kubernetes lama atau konfigurasi K3s. Installer tidak menghapus/reset cluster."
  fi
  echo "Menggabungkan node ini ke $server_url..."
  K3S_URL="$server_url" INSTALL_K3S_EXEC=agent download_and_run_k3s_installer
  systemctl is-active --quiet k3s-agent ||
    fail "Service K3s agent tidak aktif; periksa: journalctl -u k3s-agent -n 100 --no-pager"
  echo "K3s agent aktif. Periksa statusnya dari control-plane dengan: k3s kubectl get nodes -o wide"
}

install_master() {
  require_command docker
  require_command openssl
  require_command sudo
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 plugin tidak tersedia."
  mkdir -p "$CREDENTIAL_DIR"
  if [[ ! -e "$ENV_FILE" ]]; then
    cat >"$ENV_FILE" <<'EOF'
MASTER_DATABASE_URL=sqlite:////app/data/master.db
EOF
    chmod 0600 "$ENV_FILE"
  fi
  ensure_master_credentials

  if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    require_command python3
    python3 -m venv "$ROOT/.venv"
  fi
  if ! "$ROOT/.venv/bin/python" -c 'import cryptography' >/dev/null 2>&1; then
    "$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
  fi
  ensure_master_keys

  local host
  host="${2:-}"
  if [[ -z "$host" ]]; then
    host="$(hostname -I | awk '{print $1}')"
  fi
  [[ -n "$host" ]] || fail "Berikan alamat Master: bash scripts/install-mode.sh master <IP-atau-hostname>"
  if [[ ! -e "$ROOT/secrets/master/tls" ]]; then
    sudo bash "$ROOT/scripts/generate-master-tls.sh" "$host"
  fi
  for file in ca.crt master.crt master.key; do
    [[ -s "$ROOT/secrets/master/tls/$file" ]] || fail "File TLS $file tidak ada/kosong; pulihkan backup atau perbaiki direktori TLS."
  done
  sudo chgrp 1998 "$ROOT/secrets/master/master_policy.key" "$ROOT/secrets/master/master_config.key"
  sudo chmod 0640 "$ROOT/secrets/master/master_policy.key" "$ROOT/secrets/master/master_config.key"

  cd "$ROOT"
  docker compose -f infra/docker-compose.yml --env-file .env --profile master up --build -d master master-web
  echo "SOC Master UI: https://$host:8443"
  if [[ -f "$CREDENTIAL_DIR/master.txt" ]]; then
    echo "Token admin awal disimpan dengan izin 0600 di $CREDENTIAL_DIR/master.txt"
  fi
  echo "Perintah ini hanya memasang Master control plane, bukan Kubernetes pada node."
}

case "$MODE" in
  single) install_single ;;
  orchestration) install_orchestration_server "$@" ;;
  orchestration-agent) install_orchestration_agent "$@" ;;
  master) install_master ;;
  *) fail "Pilih mode: single | orchestration | orchestration-agent | master. Contoh: sudo bash scripts/install-mode.sh orchestration <IP-node>" ;;
esac
