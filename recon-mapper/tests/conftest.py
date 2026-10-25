"""
tests.conftest
==============
Shared pytest fixtures for the Recon Mapper test suite.

Fixtures Provided
-----------------
tmp_db_path : Path
    Unique SQLite database filepath inside pytest's temporary directory.
storage : ReconStorage
    Fresh, isolated, open ReconStorage instance backed by a temporary SQLite
    database file for each test, automatically closed on teardown.
tmp_storage : ReconStorage
    Alias for ``storage``.
sample_asset : Asset
    A populated, valid Asset instance with domain, IP, ports, and tech stack.
asset : Asset
    Alias for ``sample_asset``.
sample_finding : Finding
    A valid Finding instance linked to ``sample_asset`` with HIGH severity.
finding : Finding
    Alias for ``sample_finding``.

Note on HTTP Mocking
--------------------
The ``respx`` plugin is registered automatically via ``respx.plugin``.
To mock async ``httpx`` calls in tests, simply declare the ``respx_mock`` fixture:

    async def test_api_call(respx_mock):
        respx_mock.get("https://crt.sh/?q=example.com&output=json").respond(
            json=[{"name_value": "sub.example.com"}]
        )
        ...
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Generator
import uuid

import pytest

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage


# ---------------------------------------------------------------------------
# Storage Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Return a path to a test-isolated SQLite database file."""
    return tmp_path / "test_recon.db"


@pytest.fixture
def storage(tmp_db_path: Path) -> Generator[ReconStorage, None, None]:
    """Yield a connected, schema-initialised ReconStorage instance per test.

    The database is created in a temporary directory per test function and is
    cleanly committed and closed during fixture teardown.
    """
    store = ReconStorage(db_path=tmp_db_path)
    store.open()
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def tmp_storage(storage: ReconStorage) -> ReconStorage:
    """Alias for ``storage`` fixture for tests explicitly requesting tmp_storage."""
    return storage


# ---------------------------------------------------------------------------
# Model Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_asset() -> Asset:
    """Return a representative, pre-populated Asset instance for testing."""
    return Asset(
        domain="api.target.example",
        ip="93.184.216.34",
        ports=[80, 443, 8443],
        tech_stack=["nginx/1.24", "Python/3.12"],
        discovered_via="subdomain_enum",
        first_seen=datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        asset_id="11111111-2222-3333-4444-555555555555",
    )


@pytest.fixture
def asset(sample_asset: Asset) -> Asset:
    """Convenience alias for ``sample_asset``."""
    return sample_asset


@pytest.fixture
def sample_finding(sample_asset: Asset) -> Finding:
    """Return a representative Finding instance linked to ``sample_asset``."""
    return Finding(
        asset=sample_asset,
        category="tls",
        severity=Severity.HIGH,
        description="Expired TLS certificate detected on endpoint",
        evidence="Certificate expired on 2026-01-01T00:00:00Z (issuer: Let's Encrypt)",
        timestamp=datetime(2026, 1, 15, 12, 30, 0, tzinfo=timezone.utc),
        finding_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    )


@pytest.fixture
def finding(sample_finding: Finding) -> Finding:
    """Convenience alias for ``sample_finding``."""
    return sample_finding
