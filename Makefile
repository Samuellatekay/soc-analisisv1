.PHONY: setup install dev demo test web
setup install:  ## siapkan backend dan frontend
	bash scripts/as-repo-owner.sh bash scripts/install.sh
dev:            ## API + worker tertanam + UI (http://localhost:8000)
	bash scripts/as-repo-owner.sh .venv/bin/python run_dev.py
demo:           ## isi data sintetis (server harus berjalan)
	bash scripts/as-repo-owner.sh .venv/bin/python scripts/generate_demo_data.py --api http://localhost:8000
test:
	bash scripts/as-repo-owner.sh .venv/bin/python -m pytest -q
web:            ## build ulang frontend
	bash scripts/as-repo-owner.sh bash -c 'cd apps/web && npm ci && npm run build'
