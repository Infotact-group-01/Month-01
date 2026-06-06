# ─────────────────────────────────────────────────────────────────────────────
# TIP — Threat Intelligence Platform
# Convenience Makefile for common development tasks.
#
# Windows users: use the .ps1 launcher scripts directly, or run via Git Bash.
# CI (GitHub Actions):  these targets run on ubuntu-latest automatically.
# ─────────────────────────────────────────────────────────────────────────────

.PHONY: help run test demo enforcer api docker-up docker-down clean

help:
	@echo ""
	@echo "  TIP — Threat Intelligence Platform"
	@echo "  ─────────────────────────────────────────────────────────"
	@echo "  make run          Run the full ingestion pipeline"
	@echo "  make test         Run the automated test suite (100+ tests)"
	@echo "  make demo         Load the demo dataset into Elasticsearch"
	@echo "  make enforcer     Start the Policy Enforcer daemon (dry-run)"
	@echo "  make api          Start the Rollback API on port 5050 (dry-run)"
	@echo "  make docker-up    Start Elasticsearch + Kibana + MongoDB"
	@echo "  make docker-down  Stop all Docker services (data is preserved)"
	@echo "  make clean        Remove __pycache__ and .pyc files"
	@echo ""
	@echo "  Windows users: use run.ps1, run_api.ps1, run_enforcer.ps1"
	@echo ""

## ── Pipeline ─────────────────────────────────────────────────────────────────

run:
	python -m src.ingest

demo:
	python load_demo_data.py

## ── Testing ──────────────────────────────────────────────────────────────────

test:
	pytest tests/ -v --tb=short

test-quiet:
	pytest tests/ -q

## ── Services ─────────────────────────────────────────────────────────────────

enforcer:
	python -m src.enforcer --dry-run --once

api:
	python -m src.rollback_api --dry-run

## ── Docker ───────────────────────────────────────────────────────────────────

docker-up:
	docker-compose up -d

docker-down:
	docker-compose stop

docker-reset:
	docker-compose down -v

## ── Housekeeping ─────────────────────────────────────────────────────────────

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
