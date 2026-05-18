# Makefile — Linux/macOS conveniences.
# Windows: use .\build.ps1 (or invoke python directly).
#
# All real logic lives in build.py / pytest / ruff config — these are
# just memorable command names. Adding a new target? Keep it a thin
# wrapper, not a place where behaviour lives.

PYTHON ?= python3

.PHONY: help install test lint format check build build-v1 build-v2 clean

help:
	@echo "Targets:"
	@echo "  install     pip install -e '.[dev]'   (pytest, ruff, pyinstaller)"
	@echo "  test        pytest"
	@echo "  lint        ruff check ."
	@echo "  format      ruff format ."
	@echo "  check       ruff check . && ruff format . --check  (pre-commit gate)"
	@echo "  build       build both v1.1 and v2.0 binaries to dist/"
	@echo "  build-v1    build only v1.1 -> dist/shai_hulud_guard_legacy"
	@echo "  build-v2    build only v2.0 -> dist/shai_hulud_guard"
	@echo "  clean       remove build/ dist/ *.spec"

install:
	$(PYTHON) -m pip install -e '.[dev]'

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .

format:
	$(PYTHON) -m ruff format .

check:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format . --check

build:
	$(PYTHON) build.py

build-v1:
	$(PYTHON) build.py --v1

build-v2:
	$(PYTHON) build.py --v2

clean:
	$(PYTHON) build.py --clean
