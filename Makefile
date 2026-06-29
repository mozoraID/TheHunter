# PentestGPT Makefile
# Usage: make [target]

.PHONY: help install test test-cov test-verbose lint format typecheck clean build
.PHONY: ci ci-quick

# Default target
help:
	@echo "PentestGPT Commands"
	@echo "==================="
	@echo ""
	@echo "Setup:"
	@echo "  make install     Install dependencies (uv sync)"
	@echo ""
	@echo "Development:"
	@echo "  make test         Run all tests"
	@echo "  make lint         Run linter (ruff)"
	@echo "  make format       Format code (ruff)"
	@echo "  make typecheck    Run type checker (mypy)"
	@echo "  make check        Run all checks (lint + typecheck)"
	@echo "  make ci           Run full CI simulation (lint, format, typecheck, test, build)"
	@echo "  make ci-quick     Run quick CI (skip build step)"
	@echo "  make clean        Clean build artifacts"

# ============================================================================
# Setup
# ============================================================================

install:
	uv sync

# ============================================================================
# Testing
# ============================================================================

test:
	uv run pytest tests/ -v

test-all:
	uv run pytest tests/ -v

test-cov:
	uv run pytest tests/ -v --cov=pentestgpt --cov-report=term-missing --cov-report=html

test-verbose:
	uv run pytest tests/ -vvs

# Test by category
test-unit:
	uv run pytest tests/unit/ -v

test-integration:
	uv run pytest tests/integration/ -v

test-fast:
	uv run pytest tests/ -v -m "not slow"

# Run specific test files
test-session:
	uv run pytest tests/unit/test_session.py -v

test-events:
	uv run pytest tests/unit/test_events.py -v

test-controller:
	uv run pytest tests/integration/test_controller.py -v

test-backend:
	uv run pytest tests/unit/test_backend_interface.py -v

test-config:
	uv run pytest tests/unit/test_config.py -v

# ============================================================================
# Code Quality
# ============================================================================

lint:
	uv run ruff check pentestgpt/ pentestgpt_legacy/ tests/

lint-fix:
	uv run ruff check --fix pentestgpt/ pentestgpt_legacy/ tests/

format:
	uv run ruff format pentestgpt/ pentestgpt_legacy/ tests/

format-check:
	uv run ruff format --check pentestgpt/ pentestgpt_legacy/ tests/

typecheck:
	uv run mypy pentestgpt/

check: lint typecheck
	@echo "All checks passed!"

# ============================================================================
# CI Simulation (End-to-End)
# ============================================================================

# Full CI simulation - mirrors GitHub Actions workflow exactly
ci:
	@echo "=========================================="
	@echo "Running full CI simulation..."
	@echo "=========================================="
	@echo ""
	@echo "[1/5] Lint check (ruff check)..."
	uv run ruff check pentestgpt/ pentestgpt_legacy/ tests/
	@echo ""
	@echo "[2/5] Format check (ruff format --check)..."
	uv run ruff format --check pentestgpt/ pentestgpt_legacy/ tests/
	@echo ""
	@echo "[3/5] Type check (mypy)..."
	uv run mypy pentestgpt/
	@echo ""
	@echo "[4/5] Running tests..."
	uv run pytest tests/ -v
	@echo ""
	@echo "[5/5] Building package..."
	uv build
	@echo ""
	@echo "=========================================="
	@echo "CI simulation completed successfully!"
	@echo "=========================================="

# Quick CI - skip build step (faster iteration)
ci-quick:
	@echo "=========================================="
	@echo "Running quick CI simulation..."
	@echo "=========================================="
	@echo ""
	@echo "[1/4] Lint check (ruff check)..."
	uv run ruff check pentestgpt/ pentestgpt_legacy/ tests/
	@echo ""
	@echo "[2/4] Format check (ruff format --check)..."
	uv run ruff format --check pentestgpt/ pentestgpt_legacy/ tests/
	@echo ""
	@echo "[3/4] Type check (mypy)..."
	uv run mypy pentestgpt/
	@echo ""
	@echo "[4/4] Running tests..."
	uv run pytest tests/ -v
	@echo ""
	@echo "=========================================="
	@echo "Quick CI simulation completed successfully!"
	@echo "=========================================="

# ============================================================================
# Build
# ============================================================================

build:
	uv build

clean:
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# ============================================================================
# Local Development
# ============================================================================

# Run locally
run:
	uv run pentestgpt --target example.com

# Run in debug mode
run-debug:
	uv run pentestgpt --target example.com --debug

# Watch for changes and run tests
watch:
	uv run ptw tests/ -- -v
