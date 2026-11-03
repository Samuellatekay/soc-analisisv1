#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-}"
ENV_FILE="$ROOT/.env"
CREDENTIAL_DIR="$ROOT/secrets/install"

if [[ "$EUID" -eq 0 && "$(stat -c '%U' "$ROOT")" != root ]]; then
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

create_orchestration_env() {
  local admin analyst viewer ingest postgres neo4j
  admin="$(random_hex)"
  analyst="$(random_hex)"
  viewer="$(random_hex)"
  ingest="$(random_hex)"
  postgres="$(random_hex)"
  neo4j="$(random_hex)"
  cat >"$ENV_FILE" <<EOF
API_TOKENS=${admin}:admin:default,${analyst}:analyst:default,${viewer}:viewer:default
INGEST_API_KEY=${ingest}:default
POSTGRES_PASSWORD=${postgres}
NEO4J_PASSWORD=${neo4j}
LLM_PROVIDER=none
EOF
  printf 'Admin: %s\nAnalyst: %s\nViewer: %s\nIngest API key: %s\nPostgreSQL password: %s\nNeo4j password: %s\n' \
    "$admin" "$analyst" "$viewer" "$ingest" "$postgres" "$neo4j" >"$CREDENTIAL_DIR/orchestration.txt"
  chmod 0600 "$ENV_FILE" "$CREDENTIAL_DIR/orchestration.txt"
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

install_orchestration() {
  require_command docker
  require_command openssl
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 plugin tidak tersedia."
  mkdir -p "$CREDENTIAL_DIR"
  if [[ ! -e "$ENV_FILE" ]]; then
    create_orchestration_env
  else
    echo ".env sudah ada dan tidak akan ditimpa."
    for key in API_TOKENS INGEST_API_KEY POSTGRES_PASSWORD NEO4J_PASSWORD; do
      has_env_key "$key" && env_value_is_set "$key" || fail ".env harus memiliki nilai yang tidak kosong untuk $key."
    done
    if grep -Eq 'dev-(admin|analyst|viewer)-token|dev-ingest-key|change-me-dev' "$ENV_FILE"; then
      fail ".env masih memakai kredensial development. Ganti dengan nilai acak sebelum instalasi."
    fi
  fi
  chmod 0600 "$ENV_FILE"
  cd "$ROOT"
  docker compose -f infra/docker-compose.yml --env-file .env up --build -d
  echo "Stack Compose dimulai. UI: http://localhost:8080"
  if [[ -f "$CREDENTIAL_DIR/orchestration.txt" ]]; then
    echo "Kredensial awal disimpan dengan izin 0600 di $CREDENTIAL_DIR/orchestration.txt"
  fi
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
  orchestration) install_orchestration ;;
  master) install_master ;;
  *) fail "Pilih mode: single | orchestration | master. Contoh: bash scripts/install-mode.sh orchestration" ;;
esac
