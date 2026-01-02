# HTTP-Smuggler Makefile

.PHONY: help install install-dev test lint format clean build

help:
	@echo "HTTP-Smuggler Development Commands"
	@echo ""
	@echo "  install      Install package"
	@echo "  install-dev  Install with dev dependencies"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage"
	@echo "  lint         Run linters (black, isort, mypy)"
	@echo "  format       Format code"
	@echo "  clean        Remove build artifacts"
	@echo "  build        Build distribution packages"

install:
	pip install -e .

install-dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

test-cov:
	pytest tests/ --cov=http_smuggler --cov-report=term-missing --cov-report=html

lint:
	black --check http_smuggler/ tests/
	isort --check-only http_smuggler/ tests/
	mypy http_smuggler/

format:
	black http_smuggler/ tests/
	isort http_smuggler/ tests/

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true

build: clean
	python -m build

