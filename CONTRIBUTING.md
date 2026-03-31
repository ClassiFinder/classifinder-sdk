# Contributing to ClassiFinder Python SDK

Thanks for your interest in contributing! This is the official Python SDK for the [ClassiFinder](https://classifinder.ai) secret detection API.

## Getting Started

```bash
git clone https://github.com/ThomasParas/classifinder-python.git
cd classifinder-python
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Requires Python 3.10+.

## Ways to Contribute

### Bug Reports

[Open an issue](https://github.com/ThomasParas/classifinder-python/issues) with:

- SDK version (`pip show classifinder`)
- Python version
- Minimal code to reproduce the issue
- Expected vs actual behavior

### Feature Requests

If the SDK is missing a method, configuration option, or integration that would be useful, open an issue describing the use case.

### Code Contributions

Good first contributions:

- Improving error messages
- Adding type stubs or docstrings
- Writing additional tests
- Bug fixes

## Project Structure

```
src/classifinder/
├── _client.py          # Sync client (ClassiFinder)
├── _async_client.py    # Async client (AsyncClassiFinder)
├── _base.py            # Shared logic, retry handling
├── _models.py          # Pydantic v2 response models
├── _exceptions.py      # Exception hierarchy
└── integrations/
    └── langchain.py    # ClassiFinderGuard Runnable
```

## Code Style

- Python 3.10+ compatible
- Type hints on all public APIs
- Pydantic v2 for models
- httpx for HTTP (sync + async)
- PEP 8, 100-character line limit

## Testing

Tests use [respx](https://github.com/lundberg/respx) to mock HTTP — no live API calls.

```bash
python -m pytest tests/ -v
```

All PRs must pass the existing test suite. Add tests for any new functionality.

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Add or update tests
4. Run `python -m pytest tests/ -v` and ensure all tests pass
5. Open a PR with a clear description of what changed and why

## Security

If you discover a security vulnerability, please email security@classifinder.ai rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
