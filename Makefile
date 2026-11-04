VENV ?= .venv
PY := $(VENV)/bin/python

.PHONY: install backend-install frontend-install sandbox-image fixtures test backend-test frontend-test lint dev-api dev-ui build run

install: backend-install frontend-install

backend-install:
	python3 -m venv $(VENV)
	$(PY) -m pip install -r backend/requirements-dev.txt

frontend-install:
	cd frontend && npm ci

sandbox-image:
	docker build -f docker/sandbox.Dockerfile -t dfa-sandbox:latest .

fixtures:
	$(PY) scripts/generate_fixtures.py

test: backend-test frontend-test

backend-test:
	cd backend && ../$(PY) -m pytest

frontend-test:
	cd frontend && npx vitest run && npx tsc -b --noEmit

lint:
	cd backend && ../$(VENV)/bin/ruff check dfa tests

dev-api:
	cd backend && ../$(VENV)/bin/uvicorn dfa.main:app_factory --factory --reload --host 127.0.0.1 --port 8000

dev-ui:
	cd frontend && npm run dev

build:
	cd frontend && npm run build

# Production-like single process: API + in-process worker + built UI on :8000
run: build
	cd backend && ../$(VENV)/bin/uvicorn dfa.main:app_factory --factory --host 127.0.0.1 --port 8000
