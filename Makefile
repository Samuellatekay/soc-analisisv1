.PHONY: install dev demo test web
install:        ## dependensi Python
	pip install -r requirements-dev.txt
dev:            ## API + worker tertanam + UI (http://localhost:8000)
	python run_dev.py
demo:           ## isi data sintetis (server harus berjalan)
	python scripts/generate_demo_data.py --api http://localhost:8000
test:
	python -m pytest -q
web:            ## build ulang frontend
	cd apps/web && npm install && npm run build
