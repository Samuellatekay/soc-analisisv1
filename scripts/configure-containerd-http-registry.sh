#!/usr/bin/env bash
set -euo pipefail

registry="${1:-192.168.33.140:5000}"
config_root="/etc/containerd/certs.d"
hosts_dir="${config_root}/${registry}"
hosts_file="${hosts_dir}/hosts.toml"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Jalankan sebagai root, misalnya: sudo $0 [registry-host:port]" >&2
  exit 1
fi

if ! command -v containerd >/dev/null 2>&1; then
  echo "containerd tidak ditemukan pada node ini." >&2
  exit 1
fi

if [[ ! "${registry}" =~ ^[A-Za-z0-9.-]+:[0-9]+$ ]]; then
  echo "Alamat registry harus berbentuk host:port, misalnya 192.168.33.140:5000." >&2
  exit 1
fi

config_dump="$(containerd config dump)"
if ! grep -Fq "config_path = '${config_root}'" <<<"${config_dump}" \
  && ! grep -Fq "config_path = \"${config_root}\"" <<<"${config_dump}"; then
  cat >&2 <<EOF
Containerd belum mengaktifkan registry config path ${config_root}.
Atur config_path = '${config_root}' pada tabel registry plugin yang sudah ada
di /etc/containerd/config.toml, jangan menambahkan config_path duplikat,
lalu jalankan ulang skrip ini.
EOF
  exit 1
fi

install -d -m 755 "${hosts_dir}"
temp_file="$(mktemp "${hosts_dir}/hosts.toml.XXXXXX")"
trap 'rm -f "${temp_file}"' EXIT
cat >"${temp_file}" <<EOF
server = "http://${registry}"

[host."http://${registry}"]
  capabilities = ["pull", "resolve"]
EOF
chmod 644 "${temp_file}"
mv "${temp_file}" "${hosts_file}"
trap - EXIT

echo "Registry HTTP dikonfigurasi untuk node ini: ${registry}"
echo "File: ${hosts_file}"
echo "Periksa akses registry dari node ini dengan: curl -i http://${registry}/v2/"
echo "Jika config.toml diubah, restart containerd pada node ini dan tunggu node Ready."
