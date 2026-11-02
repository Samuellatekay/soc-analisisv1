"""Enkripsi artefak backup: AES-256-GCM per-chunk (streaming). Chunk diikat ke indeks + penanda chunk terakhir lewat AAD,
sehingga reorder, penghapusan chunk, dan pemotongan file terdeteksi. Kunci: 32 byte acak (base64) dari FILE — jangan simpan di repositori backup.
  python -m services.backup.crypto genkey /run/secrets/backup_key"""
from __future__ import annotations

import base64
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SOCBK1\n"
CHUNK = 1 << 20


class CryptoError(Exception):
    pass


def load_key(path: str) -> bytes:
    raw = Path(path).read_text().strip()
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as e:  # noqa: BLE001
        raise CryptoError("kunci harus base64 dari 32 byte") from e
    if len(key) != 32:
        raise CryptoError("kunci harus tepat 32 byte (AES-256)")
    return key


def genkey(path: str) -> None:
    p = Path(path)
    if p.exists():
        raise CryptoError("file kunci sudah ada; tidak ditimpa")
    p.write_text(base64.b64encode(os.urandom(32)).decode() + "\n")
    p.chmod(0o600)


def _nonce(base: bytes, i: int) -> bytes:
    return base[:4] + struct.pack(">Q", i)  # 4 byte acak per-file + counter 64-bit => nonce unik per chunk


def encrypt_file(src: Path, dst: Path, key: bytes) -> None:
    aes, base = AESGCM(key), os.urandom(4)
    with src.open("rb") as f, dst.open("wb") as out:
        out.write(MAGIC + base)
        i, cur = 0, f.read(CHUNK)
        while True:
            nxt = f.read(CHUNK)
            last = not nxt
            ct = aes.encrypt(_nonce(base, i), cur, struct.pack(">QB", i, last))
            out.write(struct.pack(">I", len(ct)) + ct)
            if last:
                break
            i, cur = i + 1, nxt


def decrypt_file(src: Path, dst: Path, key: bytes) -> None:
    """Pada kegagalan APA PUN, hasil parsial dihapus (tidak ada plaintext tak-terverifikasi yang tertinggal)."""
    try:
        _decrypt(src, dst, key)
    except BaseException:
        dst.unlink(missing_ok=True)
        raise


def _decrypt(src: Path, dst: Path, key: bytes) -> None:
    aes = AESGCM(key)
    with src.open("rb") as f, dst.open("wb") as out:
        if f.read(len(MAGIC)) != MAGIC:
            raise CryptoError("format berkas tidak dikenal")
        base = f.read(4)
        i, hdr, seen_last = 0, f.read(4), False
        while hdr:
            if seen_last:
                raise CryptoError("data tambahan setelah chunk terakhir")
            if len(hdr) != 4:
                raise CryptoError("berkas terpotong")
            (n,) = struct.unpack(">I", hdr)
            ct = f.read(n)
            if len(ct) != n:
                raise CryptoError("berkas terpotong")
            nxt = f.read(4)
            last = not nxt
            try:
                out.write(aes.decrypt(_nonce(base, i), ct, struct.pack(">QB", i, last)))
            except InvalidTag as e:
                raise CryptoError("autentikasi gagal: kunci salah atau berkas dimodifikasi/terpotong") from e
            seen_last, hdr, i = last, nxt, i + 1
        if not seen_last:
            raise CryptoError("berkas terpotong (tanpa chunk terakhir)")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "genkey":
        genkey(sys.argv[2]); print("kunci dibuat (chmod 600). SIMPAN SALINAN TERPISAH — tanpa kunci backup tidak dapat dipulihkan.")
    else:
        raise SystemExit(__doc__)
