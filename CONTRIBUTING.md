# Contributing to NHI Scan MCP

Thank you for your interest in contributing to NHI Scan MCP! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/NHI-scan-mcp.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Install development dependencies: `pip install -e ".[dev]"`

## Development Setup

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Write clear, descriptive docstrings
- Keep functions focused and modular

## Testing

- Add tests for new features
- Ensure existing tests pass
- Use `moto` for mocking AWS services in tests
- Aim for good test coverage

## Pull Request Process

1. Update the README.md with details of changes if needed
2. Update the examples if you add new functionality
3. Ensure all tests pass
4. Update the version number following semantic versioning
5. Create a pull request with a clear description of changes

## Areas for Contribution

- Additional NHI detection patterns
- Support for more AWS services
- Performance improvements
- Documentation improvements
- Test coverage
- Bug fixes

## Questions?

Feel free to open an issue for any questions or discussions about contributing.
