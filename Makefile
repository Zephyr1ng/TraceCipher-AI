.PHONY: setup install run clean-runs

PYTHON ?= python3
VENV ?= .venv
PIP := $(VENV)/bin/pip
UVICORN := $(VENV)/bin/uvicorn

setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

install:
	$(PIP) install -r requirements.txt

run:
	$(UVICORN) app.main:app --reload

clean-runs:
	rm -rf data/runs/*
