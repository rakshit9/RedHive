.PHONY: dev api worker ui demo-target migrate test install help

help:
	@echo "RedHive — common commands:"
	@echo "  make install       Install Python + UI deps"
	@echo "  make dev           Boot the whole stack (API + worker + UI + demo target)"
	@echo "  make migrate       Apply DB migrations"
	@echo "  make test          Run the test suite"
	@echo "  make api           Run just the API"
	@echo "  make worker        Run just a scan worker"
	@echo "  make demo-target   Run just the vulnerable demo target"

install:
	pip install -r requirements.txt
	cd ui && npm install

dev:
	./scripts/dev.sh

migrate:
	alembic upgrade head

test:
	pytest

api:
	uvicorn redhive.api.app:app --reload --port 8000

worker:
	python -m redhive.worker

demo-target:
	uvicorn demo_target.app:app --port 8780
