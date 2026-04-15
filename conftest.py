"""Global pytest fixtures and configuration for Sentinel tests.

This module provides:
- Mock LLM providers (Anthropic, OpenAI)
- Centralized test configuration
- Shared database fixtures
- Environment variable setup

All tests automatically use these fixtures and configuration.
"""

import json
import os
from typing import Any
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment() -> None:
    """Configure test environment variables globally."""
    os.environ["SENTINEL_ENV"] = "test"
    os.environ["LOG_LEVEL"] = "WARNING"
    os.environ["ANTHROPIC_API_KEY"] = "test-key-sentinel"
    os.environ["OPENAI_API_KEY"] = "test-key-sentinel"


@pytest.fixture
def mock_llm_response() -> dict[str, Any]:
    """Provide a mock LLM reasoning response."""
    return {
        "reasoning": "Entity shows high confidence pattern match.",
        "score": 0.92,
        "confidence": 0.88,
        "cache_hit": False,
        "tokens_used": 145,
    }


@pytest.fixture
def mock_anthropic_client() -> MagicMock:
    """Create a mock Anthropic client that doesn't make real API calls."""

    def mock_message_create(
        model: str,
        max_tokens: int,
        system: str | None = None,
        messages: list[dict[str, str]] | None = None,
        **kwargs: Any,
    ) -> MagicMock:
        """Mock message creation with structured output support."""
        response = MagicMock()
        response.content = [
            MagicMock(
                type="text",
                text=json.dumps(
                    {
                        "reasoning": "Test reasoning from Claude",
                        "score": 0.85,
                        "confidence": 0.80,
                    }
                ),
            )
        ]
        response.usage.input_tokens = 100
        response.usage.output_tokens = 50
        return response

    client = MagicMock()
    client.messages.create = MagicMock(side_effect=mock_message_create)
    return client


@pytest.fixture
def mock_openai_client() -> MagicMock:
    """Create a mock OpenAI client that doesn't make real API calls."""

    def mock_completion_create(
        model: str,
        messages: list[dict[str, str]] | None = None,
        response_format: dict[str, str] | None = None,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> MagicMock:
        """Mock completion creation."""
        response = MagicMock()
        response.choices = [
            MagicMock(
                message=MagicMock(
                    content=json.dumps(
                        {
                            "reasoning": "Test reasoning from GPT",
                            "score": 0.78,
                            "confidence": 0.75,
                        }
                    )
                )
            )
        ]
        response.usage.prompt_tokens = 120
        response.usage.completion_tokens = 60
        return response

    client = MagicMock()
    client.chat.completions.create = MagicMock(side_effect=mock_completion_create)
    return client


@pytest.fixture
def patch_llm_providers(
    mock_anthropic_client: MagicMock, mock_openai_client: MagicMock
) -> Any:
    """Patch both LLM providers for all tests that need them."""
    with patch("sentinel.llm.Anthropic", return_value=mock_anthropic_client), patch(
        "sentinel.llm.OpenAI", return_value=mock_openai_client
    ):
        yield


@pytest.fixture
def tmp_sqlite_db(tmp_path: Any) -> str:
    """Create a temporary SQLite database for testing.

    Args:
        tmp_path: pytest's temporary directory fixture

    Returns:
        Path to the test database file
    """
    db_path = str(tmp_path / "test_incidents.db")
    # Initialize empty database (IncidentStore.connect() creates schema)
    return db_path


@pytest.fixture(autouse=True)
def reset_logging() -> None:
    """Reset logging after each test."""
    import logging

    # Get all loggers and reset
    for logger_name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()

    yield

    # Clear handlers after test
    for logger_name in logging.Logger.manager.loggerDict:
        logger = logging.getLogger(logger_name)
        logger.handlers.clear()


@pytest.fixture
def sample_incident_event() -> dict[str, Any]:
    """Provide sample incident event data."""
    return {
        "entity": "192.168.1.100",
        "stage": "initial-compromise",
        "confidence": 0.85,
        "timestamp": "2024-01-15T10:30:00Z",
        "detection_method": "behavioral-analysis",
        "raw_data": {
            "process_name": "svchost.exe",
            "parent_process": "explorer.exe",
            "command_line": "svchost.exe -k netsvcs",
        },
    }


@pytest.fixture
def sample_network_finding() -> dict[str, Any]:
    """Provide sample network detection data."""
    return {
        "source_ip": "192.168.1.50",
        "destination_ip": "203.0.113.42",
        "ja3_hash": "fake_ja3_hash_known_bad",
        "certificate_issuer": "Untrusted CA",
        "dns_query": "suspicious.malware.com",
        "port": 443,
        "protocol": "TLS",
    }


@pytest.fixture
def sample_behavioral_profile() -> dict[str, Any]:
    """Provide sample behavioral profile for drift detection."""
    return {
        "entity": "workstation-42",
        "time_window": "1h",
        "process_count": 150,
        "unique_processes": 45,
        "network_connections": 32,
        "failed_authentications": 0,
        "anomaly_score": 0.12,
    }
