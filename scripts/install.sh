#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
VENV="$ROOT/.venv"
WEB="$ROOT/apps/web"

if [[ "$EUID" -eq 0 && "$(stat -c '%U' "$ROOT")" != root ]]; then
    exec "$ROOT/scripts/as-repo-owner.sh" bash "$ROOT/scripts/install.sh"
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python 3.12+ tidak ditemukan. Pasang Python lalu jalankan ulang." >&2
    exit 1
fi

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || {
    echo "Diperlukan Python 3.12 atau lebih baru." >&2
    exit 1
}

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
    echo "Node.js 18+ dan npm tidak ditemukan. Pasang Node.js lalu jalankan ulang." >&2
    exit 1
fi

node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 18 ? 0 : 1)' || {
    echo "Diperlukan Node.js 18 atau lebih baru." >&2
    exit 1
}

echo "Menyiapkan environment Python..."
if [[ ! -x "$VENV/bin/python" ]]; then
    "$PYTHON" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install -r "$ROOT/requirements-dev.txt"

echo "Memasang dependency frontend dari lockfile..."
cd "$WEB"
npm ci
npm run build

echo
echo "Instalasi selesai."
echo "Jalankan aplikasi dengan: make dev"
echo "Kemudian buka: http://localhost:8000"
