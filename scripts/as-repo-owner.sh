#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if (($# == 0)); then
    echo "Usage: $0 command [args...]" >&2
    exit 2
fi

OWNER="$(stat -c '%U' "$ROOT")"
OWNER_HOME="$(getent passwd "$OWNER" | cut -d: -f6)"
if [[ -z "$OWNER_HOME" ]]; then
    echo "Tidak dapat menemukan home directory pemilik repo: $OWNER" >&2
    exit 1
fi

if [[ "$EUID" -eq 0 && "$OWNER" != root ]]; then
    if ! command -v runuser >/dev/null 2>&1; then
        echo "runuser tidak tersedia; jalankan perintah sebagai $OWNER, bukan root." >&2
        exit 1
    fi
    exec runuser -u "$OWNER" -- env PATH="$OWNER_HOME/.local/bin:$PATH" "$@"
fi

export PATH="$OWNER_HOME/.local/bin:$PATH"
exec "$@"
