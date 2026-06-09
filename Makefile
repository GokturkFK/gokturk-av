PYTHON  := python3
VENV    := .venv
PY      := $(VENV)/bin/python
PIP     := $(VENV)/bin/pip

.PHONY: help setup run test lint fix clean docker up down

.DEFAULT_GOAL := help

help:
	@printf "%-10s %s\n" "setup"  "Sanal ortam kur, bağımlılıkları yükle"
	@printf "%-10s %s\n" "run"    "Streamlit UI başlat  →  http://localhost:8501"
	@printf "%-10s %s\n" "test"   "pytest çalıştır"
	@printf "%-10s %s\n" "lint"   "ruff lint kontrolü"
	@printf "%-10s %s\n" "fix"    "ruff otomatik düzeltme"
	@printf "%-10s %s\n" "clean"  "Önbellek dosyalarını temizle"
	@printf "%-10s %s\n" "docker" "Docker image oluştur"
	@printf "%-10s %s\n" "up"     "docker compose ile başlat"
	@printf "%-10s %s\n" "down"   "docker compose ile durdur"

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt -r requirements-dev.txt
	$(VENV)/bin/pre-commit install

run:
	$(VENV)/bin/streamlit run ui/app.py

test:
	$(VENV)/bin/pytest --tb=short

lint:
	$(VENV)/bin/ruff check .

fix:
	$(VENV)/bin/ruff check --fix .

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} \; 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache

docker:
	docker build -t goktürk-av:latest .

up:
	docker compose up -d

down:
	docker compose stop
