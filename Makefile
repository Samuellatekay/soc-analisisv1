.PHONY: setup install dev demo test web
setup install:  ## siapkan backend dan frontend
	bash scripts/install.sh
dev:            ## API + worker tertanam + UI (http://localhost:8000)
	.venv/bin/python run_dev.py
demo:           ## isi data sintetis (server harus berjalan)
	.venv/bin/python scripts/generate_demo_data.py --api http://localhost:8000
test:
	.venv/bin/python -m pytest -q
web:            ## build ulang frontend
	cd apps/web && npm ci && npm run build
