#!/usr/bin/env bash
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
  echo "Jalankan sebagai root: sudo $0 <alamat-master>" >&2
  exit 1
fi

host="${1:-}"
if [[ ! "$host" =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Berikan hostname atau IPv4 Master, misalnya 192.168.33.140." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tls_dir="$root/secrets/master/tls"
group_id=1999

if [[ -e "$tls_dir" ]]; then
  echo "Direktori $tls_dir sudah ada; tidak menimpa CA atau sertifikat." >&2
  exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl tidak ditemukan." >&2
  exit 1
fi

install -d -o root -g "$group_id" -m 0750 "$tls_dir"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [[ "$host" =~ ^[0-9.]+$ ]]; then
  san="IP:$host"
else
  san="DNS:$host"
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$tls_dir/ca.key" -out "$tls_dir/ca.crt" -days 3650 \
  -subj "/CN=SOC Master Private CA"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$tls_dir/master.key" -out "$tmp/master.csr" \
  -subj "/CN=$host"
printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyAgreement\n' "$san" > "$tmp/master.ext"
openssl x509 -req -in "$tmp/master.csr" -CA "$tls_dir/ca.crt" -CAkey "$tls_dir/ca.key" \
  -CAcreateserial -out "$tls_dir/master.crt" -days 825 -sha256 -extfile "$tmp/master.ext"

chown root:"$group_id" "$tls_dir/master.key" "$tls_dir/master.crt"
chmod 0640 "$tls_dir/master.key"
chmod 0644 "$tls_dir/master.crt" "$tls_dir/ca.crt"
chmod 0600 "$tls_dir/ca.key"

printf '\nTLS certificate created for %s.\n' "$host"
printf 'CA fingerprint (verify when distributing ca.crt):\n'
openssl x509 -in "$tls_dir/ca.crt" -noout -fingerprint -sha256
printf 'Master CA certificate: %s/ca.crt\n' "$tls_dir"
