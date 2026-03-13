# AGENTS.md

## Cursor Cloud specific instructions

### Overview

HTTP-Smuggler is a single-process Python CLI tool for detecting HTTP request smuggling vulnerabilities. No external services (databases, Docker, etc.) are required.

### Virtual environment

All commands must be run inside the virtualenv at `/workspace/venv`. Activate with `source /workspace/venv/bin/activate` before running any Python/CLI commands.

### Key commands

| Task | Command |
|------|---------|
| Run CLI | `http-smuggler --help` |
| Protocol detect | `http-smuggler detect <URL>` |
| Run tests | `pytest tests/ -v` |
| Lint (check) | `make lint` |
| Format code | `make format` |
| Build | `make build` |

See `Makefile` and `README.md` for full command reference.

### Known issues (pre-existing)

- `black --check` and `isort --check-only` report formatting violations across the entire codebase. These are pre-existing and not caused by agent changes.
- `mypy http_smuggler/` reports type errors (missing annotations, import issues). Pre-existing.
- 2 tests fail in `tests/test_detection.py` due to stale default-value assertions (`baseline_requests` expects 3 but code defaults to 10; `confidence_threshold` expects 0.7 but code defaults to 0.6). These are pre-existing test/code mismatches.

### System dependency

`python3.12-venv` must be installed via apt for virtualenv creation. The update script handles `pip install` but assumes the venv already exists.
