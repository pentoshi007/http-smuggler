# Contributing to HTTP-Smuggler

Thank you for your interest in contributing to HTTP-Smuggler! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help maintain a welcoming community

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - Python version
   - OS and version
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages/tracebacks

### Suggesting Features

1. Check existing issues/discussions
2. Describe the feature and use case
3. Explain why it would benefit users

### Submitting Code

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Write/update tests
5. Update documentation if needed
6. Submit a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/http-smuggler.git
cd http-smuggler

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Install dev dependencies
pip install pytest pytest-asyncio pytest-cov black isort mypy
```

## Code Style

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use descriptive variable names
- Document public functions with docstrings

### Formatting

```bash
# Format code
black http_smuggler/
isort http_smuggler/

# Check types
mypy http_smuggler/
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=http_smuggler --cov-report=term-missing

# Run specific test file
pytest tests/test_payloads.py -v
```

### Writing Tests

- Place tests in `tests/` directory
- Name test files `test_*.py`
- Use pytest fixtures from `conftest.py`
- Test both success and failure cases

Example:
```python
def test_payload_generation(sample_endpoint):
    """Test that payloads are generated correctly."""
    generator = CLTEPayloadGenerator()
    payloads = generator.generate_timing_payloads(sample_endpoint)
    
    assert len(payloads) > 0
    assert all(p.variant == SmugglingVariant.CL_TE for p in payloads)
```

## Adding New Smuggling Variants

1. Create payload generator in appropriate directory:
   - `payloads/classic/` for HTTP/1.1
   - `payloads/http2/` for HTTP/2
   - `payloads/websocket/` for WebSocket
   - `payloads/advanced/` for advanced techniques

2. Implement the `PayloadGenerator` interface:
```python
class NewVariantGenerator(PayloadGenerator):
    @property
    def variant(self) -> SmugglingVariant:
        return SmugglingVariant.NEW_VARIANT
    
    def generate_timing_payloads(self, endpoint: Endpoint) -> List[Payload]:
        ...
    
    def generate_differential_payloads(self, endpoint: Endpoint) -> List[Payload]:
        ...
```

3. Add variant to `SmugglingVariant` enum in `core/models.py`
4. Register generator in `core/engine.py`
5. Add tests

## Adding Transfer-Encoding Obfuscations

Add to `payloads/obfuscation.py`:

```python
TEObfuscation(
    header="Transfer-Encoding: new-mutation",
    category=ObfuscationCategory.YOUR_CATEGORY,
    description="Description of the mutation",
    risk_level="high",  # low, medium, high
)
```

## Documentation

- Update README.md for user-facing changes
- Update docs/ for architecture changes
- Include docstrings for new functions/classes
- Add comments for complex logic

## Pull Request Process

1. Update CHANGELOG.md (if present)
2. Ensure all tests pass
3. Update documentation
4. Request review from maintainers
5. Address feedback promptly

### PR Checklist

- [ ] Code follows project style
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No linter errors
- [ ] Commits are atomic and well-described

## Questions?

Open a discussion or issue if you have questions about contributing.

Thank you for helping make HTTP-Smuggler better! 🎉

