"""python -m services.master.keys gen <dir> | gen-config <file>"""
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from .policy import gen_keypair

def main():
    if len(sys.argv) == 3 and sys.argv[1] == "gen":
        directory = Path(sys.argv[2])
        directory.mkdir(parents=True, exist_ok=True)
        private_path, public_path = directory / "master_policy.key", directory / "master_policy.pub"
        if private_path.exists() or public_path.exists():
            raise SystemExit("kunci sudah ada; tidak ditimpa")
        private, public = gen_keypair()
        private_path.write_text(private + "\n")
        private_path.chmod(0o600)
        public_path.write_text(public + "\n")
        public_path.chmod(0o644)
        print(f"dibuat di {directory}. Simpan kunci privat hanya di Master; distribusikan .pub ke cluster.")
        return
    if len(sys.argv) == 3 and sys.argv[1] == "gen-config":
        path = Path(sys.argv[2])
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise SystemExit("kunci konfigurasi sudah ada; tidak ditimpa") from exc
        with os.fdopen(fd, "wb") as stream:
            stream.write(Fernet.generate_key() + b"\n")
        print(f"kunci enkripsi konfigurasi dibuat di {path}. Cadangkan secara aman; tanpa kunci ini konfigurasi tersimpan tidak dapat dipulihkan.")
        return
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
