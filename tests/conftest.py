"""Pytest configuration and fixtures for HTTP-Smuggler tests."""

import pytest
import asyncio
from typing import Generator

from http_smuggler.core.config import ScanConfig, ScanMode, NetworkConfig
from http_smuggler.core.models import Endpoint


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_endpoint() -> Endpoint:
    """Create a sample endpoint for testing."""
    return Endpoint(
        url="https://example.com/api/test",
        method="POST",
        accepts_body=True,
        content_type="application/x-www-form-urlencoded",
    )


@pytest.fixture
def default_config() -> ScanConfig:
    """Create default scan configuration for testing."""
    return ScanConfig(
        target_url="https://example.com",
        mode=ScanMode.SAFE,
        skip_crawl=True,
    )


@pytest.fixture
def network_config() -> NetworkConfig:
    """Create network configuration for testing."""
    return NetworkConfig(
        connect_timeout=5.0,
        read_timeout=10.0,
    )

