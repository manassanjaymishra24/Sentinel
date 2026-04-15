# Contributing to Sentinel

## Before You Start

- Search existing issues and pull requests
- Run `pytest tests/ -v` to ensure tests pass
- Follow Google-style docstrings for new code
- Maintain 100% type hints on core modules
- Use `ruff check sentinel/` and `ruff format sentinel/` for code quality

## Code Standards

### Type Hints
- **100% coverage** on core modules (`sentinel/llm.py`, `sentinel/storage.py`, etc.)
- Use PEP 604 union syntax (`str | int` instead of `Union[str, int]`)
- Define TypedDicts for structured data validation
- Run `mypy sentinel/ --strict` to validate

### Logging
- Use `sentinel.logging_config` for centralized logging
- Strategic log points: DEBUG for detailed traces, INFO for key events, WARNING for anomalies
- Auto-configured on import; no manual setup needed

### Docstrings
- Google-style docstrings on all public methods
- Complete Args/Returns/Raises sections
- Include usage examples where helpful

### Testing
- Every feature requires tests
- Use pytest fixtures for reusable test data
- Mock LLM providers to avoid real API calls in CI
- Aim for 80%+ code coverage

## Pull Request Process

1. **Create feature branch:**
   ```bash
   git checkout -b feature/your-feature
   ```

2. **Add tests and run validation:**
   ```bash
   pytest tests/ -v
   mypy sentinel/ --strict
   ruff check sentinel/
   ruff format sentinel/
   ```

3. **Commit with conventional style:**
   ```bash
   git commit -m "feat: add new detection capability"
   # Types: feat, fix, docs, refactor, perf, test, chore
   ```

4. **Open PR with description:**
   - What problem does this solve?
   - How was it tested?
   - Any breaking changes?
   - Screenshots of output if UI changes

5. **Address review feedback** and merge

## Development Setup

```bash
git clone https://github.com/yourusername/sentinel.git
cd sentinel
pip install -e ".[dev]"
pytest tests/ -v  # Should pass all 56 tests
```

## Architecture Guidelines

- **Safety Envelope:** LLM is optional safety-net, not core engine
- **Deterministic First:** Primary detection uses rules, not AI
- **Cost Control:** Token budgeting and response caching mandatory
- **Modular Design:** Each layer (events, perception, reasoning, response) is pluggable

## Security Considerations

- Never commit API keys or secrets
- All external API calls must be optional and mocked in tests
- Follow principle of least privilege in response actions
- Validate all LLM outputs against deterministic rules