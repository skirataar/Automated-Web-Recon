"""
tests.test_storage
==================
Unit tests for core.storage (ReconStorage SQLite persistence).
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage


def test_save_and_retrieve_asset(storage: ReconStorage, sample_asset: Asset) -> None:
    """Verify storing and retrieving an Asset."""
    storage.save_asset(sample_asset)
    retrieved = storage.get_asset_by_id(sample_asset.asset_id)

    assert retrieved is not None
    assert retrieved.asset_id == sample_asset.asset_id
    assert retrieved.domain == sample_asset.domain
    assert retrieved.ip == sample_asset.ip
    assert retrieved.ports == sample_asset.ports
    assert retrieved.tech_stack == sample_asset.tech_stack
    assert retrieved.discovered_via == sample_asset.discovered_via


def test_asset_upsert(storage: ReconStorage, sample_asset: Asset) -> None:
    """Verify that saving an existing Asset updates its fields."""
    storage.save_asset(sample_asset)

    # Mutate and re-save
    sample_asset.ip = "192.168.1.100"
    sample_asset.ports.append(8080)
    sample_asset.tech_stack.append("Express")
    storage.save_asset(sample_asset)

    retrieved = storage.get_asset_by_id(sample_asset.asset_id)
    assert retrieved is not None
    assert retrieved.ip == "192.168.1.100"
    assert 8080 in retrieved.ports
    assert "Express" in retrieved.tech_stack


def test_save_and_retrieve_findings(
    storage: ReconStorage, sample_asset: Asset, sample_finding: Finding
) -> None:
    """Verify saving a finding and retrieving it by asset and severity."""
    storage.save_finding(sample_finding)

    # By asset
    findings = storage.get_findings(asset=sample_asset)
    assert len(findings) == 1
    assert findings[0].finding_id == sample_finding.finding_id
    assert findings[0].category == sample_finding.category
    assert findings[0].severity == Severity.HIGH

    # By exact severity
    high_findings = storage.get_findings_by_severity(Severity.HIGH)
    assert len(high_findings) == 1
    low_findings = storage.get_findings_by_severity(Severity.LOW)
    assert len(low_findings) == 0

    # By minimum severity
    min_medium = storage.get_findings_by_severity(Severity.MEDIUM, minimum=True)
    assert len(min_medium) == 1  # HIGH >= MEDIUM
    min_critical = storage.get_findings_by_severity(Severity.HIGH, minimum=True)
    assert len(min_critical) == 1


def test_finding_upsert(
    storage: ReconStorage, sample_finding: Finding
) -> None:
    """Verify saving a finding with the same ID updates it."""
    storage.save_finding(sample_finding)

    sample_finding.severity = Severity.MEDIUM
    sample_finding.description = "Updated description"
    storage.save_finding(sample_finding)

    findings = storage.get_findings()
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].description == "Updated description"
