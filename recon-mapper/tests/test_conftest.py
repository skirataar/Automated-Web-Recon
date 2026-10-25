"""
tests.test_conftest
===================
Tests verifying the shared pytest setup, fixtures, async test runner,
and HTTP mocking via respx.
"""

from __future__ import annotations

import httpx
import pytest

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage


def test_sample_asset_fixture(sample_asset: Asset, asset: Asset) -> None:
    """Verify that sample_asset and its alias provide a valid Asset instance."""
    assert sample_asset.domain == "api.target.example"
    assert sample_asset.ip == "93.184.216.34"
    assert 443 in sample_asset.ports
    assert "nginx/1.24" in sample_asset.tech_stack
    assert sample_asset.discovered_via == "subdomain_enum"
    assert sample_asset.asset_id is not None
    # Verify alias points to the same object
    assert asset is sample_asset


def test_sample_finding_fixture(sample_finding: Finding, finding: Finding) -> None:
    """Verify that sample_finding and its alias provide a valid Finding instance."""
    assert sample_finding.category == "tls"
    assert sample_finding.severity == Severity.HIGH
    assert "Expired TLS certificate" in sample_finding.description
    assert sample_finding.asset.domain == "api.target.example"
    assert finding is sample_finding


def test_storage_fixture_isolation(
    storage: ReconStorage, sample_asset: Asset, sample_finding: Finding
) -> None:
    """Verify storage fixture is open, initialised, and isolated per test."""
    # Initially empty
    assert storage.get_assets() == []
    assert storage.get_findings() == []

    # Save asset and finding
    storage.save_asset(sample_asset)
    storage.save_finding(sample_finding)

    # Verify retrieval
    stored_assets = storage.get_assets()
    assert len(stored_assets) == 1
    assert stored_assets[0].domain == sample_asset.domain

    stored_findings = storage.get_findings()
    assert len(stored_findings) == 1
    assert stored_findings[0].category == "tls"
    assert stored_findings[0].severity == Severity.HIGH


def test_tmp_storage_alias(tmp_storage: ReconStorage, sample_asset: Asset) -> None:
    """Verify tmp_storage alias works and operates on an isolated database."""
    # Must be empty in this new test
    assert tmp_storage.get_assets() == []
    tmp_storage.save_asset(sample_asset)
    assert len(tmp_storage.get_assets()) == 1


async def test_async_by_default(storage: ReconStorage, sample_asset: Asset) -> None:
    """Verify async test functions run without an explicit @pytest.mark.asyncio decorator."""
    # Async test executing standard coroutines
    storage.save_asset(sample_asset)
    retrieved = storage.get_asset_by_id(sample_asset.asset_id)
    assert retrieved is not None
    assert retrieved.domain == "api.target.example"


async def test_respx_mock_async_http(respx_mock) -> None:
    """Verify that respx fixture intercepts and mocks async httpx requests."""
    route = respx_mock.get("https://crt.sh/?q=example.com&output=json").respond(
        status_code=200,
        json=[
            {"name_value": "api.example.com"},
            {"name_value": "auth.example.com"},
        ],
    )

    async with httpx.AsyncClient() as client:
        response = await client.get("https://crt.sh/?q=example.com&output=json")
        data = response.json()

    assert route.called
    assert len(data) == 2
    assert data[0]["name_value"] == "api.example.com"
