# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Production-grade type hints across all core modules
- Centralized logging infrastructure with environment control
- CI/CD workflows (GitHub Actions):
  - Main CI pipeline with pytest matrix [3.10, 3.11, 3.12]
  - Automated release workflow with PyPI publishing via OIDC
  - Weekly security audit with CVE scanning and secret detection
  - PR validation and auto-labeling
- Comprehensive docstrings (Google style) for all public methods
- mypy strict type checking in CI
- ruff linting with security rules in CI
- Support for both Anthropic Claude and OpenAI GPT models

### Changed
- Enhanced logging with DEBUG/INFO/WARNING/ERROR levels
- Improved test coverage with mocked LLM providers
- Updated project dependencies with exact pinning

### Fixed
- Missing implementation in `SafetyEnvelopeReasoner._should_route()` method

## [0.1.0] - 2024-01-15

### Added
- Initial Sentinel security agent implementation
- LLM reasoning module with token budgeting and response caching
- SQLite-based incident storage with reputation scoring
- Behavioral drift detection using time window analysis
- Network threat detection (JA3 fingerprints, DNS anomalies)
- Zeek integration for network event parsing
- Windows Event Log support for security monitoring
- MITRE ATT&CK technique scoring
- Comprehensive test suite with 27 tests
- Production Hardening documentation

### Features
- **LLM Safety Envelope**: Validates LLM reasoning with deterministic fallback
- **Multi-factor Entity Scoring**: Combines multiple signals for entity reputation
- **Behavioral Drift Analysis**: Long-term detection of anomalous behavior changes
- **Network Forensics**: TLS/JA3 signature analysis, DNS anomaly detection
- **Cache Optimization**: Reduces LLM API calls by caching similar reasoning requests
- **Provider Abstraction**: Pluggable LLM providers (OpenAI, Anthropic)
- **Incident Tracking**: Persistent storage with advanced querying capabilities
