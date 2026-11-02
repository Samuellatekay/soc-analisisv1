"""python -m services.master.keys gen <dir>  -> master_policy.key (PRIVAT, chmod 600; hanya di Master) + master_policy.pub (distribusikan ke SEMUA cluster)."""
import sys
from pathlib import Path

from .policy import gen_keypair

if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "gen":
    d = Path(sys.argv[2]); d.mkdir(parents=True, exist_ok=True)
    if (d / "master_policy.key").exists():
        raise SystemExit("kunci sudah ada; tidak ditimpa")
    priv, pub = gen_keypair()
    (d / "master_policy.key").write_text(priv + "\n"); (d / "master_policy.key").chmod(0o600); (d / "master_policy.pub").write_text(pub + "\n")
    print(f"dibuat di {d}. Simpan salinan kunci privat secara terpisah; sebar .pub ke cluster (MASTER_POLICY_PUBKEY_FILE).")
else:
    raise SystemExit(__doc__)
