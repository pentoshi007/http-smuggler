# AGENTS.md

## Cursor Cloud specific instructions

This is a Python CLI security tool (HTTP-Smuggler) for detecting HTTP request smuggling vulnerabilities. It is a single-package project with no external service dependencies (no databases, Docker, or frontend).

### Quick reference

- **Activate venv:** `source /workspace/venv/bin/activate`
- **Run tests:** `pytest tests/ -v` (see `pyproject.toml [tool.pytest.ini_options]` for config)
- **Run lint:** `make lint` (runs `black --check`, `isort --check-only`, `mypy`)
- **Format code:** `make format` (runs `black`, `isort`)
- **Run CLI:** `http-smuggler --help`
- **Install deps:** `pip install -e ".[dev]"` (editable install with dev extras)

### Non-obvious notes

- The `python3.12-venv` system package is required to create the virtualenv; it is not installed by default on the VM. The update script handles `pip install -e ".[dev]"` but the venv must already exist.
- `black --check` and `isort --check-only` both report pre-existing formatting violations across the entire codebase. This is the current state of the repo, not a sign of a broken environment.
- `mypy http_smuggler/` reports ~129 pre-existing type errors (mostly missing type annotations). This is also the current state of the repo.
- 2 of 15 pytest tests fail due to mismatched default values between the test expectations and the actual code (`test_init_with_defaults` for `TimingDetector` and `DifferentialDetector`). These are pre-existing test failures.
- The CLI entry point is `http-smuggler` (installed via `[project.scripts]` in `pyproject.toml`). All subcommands: `scan`, `detect`, `list-variants`, `list-obfuscations`, `listener`.
- Running `scan` or `detect` requires a live URL target. For quick verification, `http-smuggler list-variants` works offline.
