"""
tests.test_models
=================
Unit tests for core.models (Asset, Finding, Severity).
"""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from core.models import Asset, Finding, Severity


class TestSeverity:
    def test_severity_ordering(self) -> None:
        """Test severity comparison operators."""
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH
        assert Severity.HIGH > Severity.LOW
        assert Severity.MEDIUM >= Severity.LOW
        assert Severity.INFO <= Severity.INFO

    def test_severity_str_serialization(self) -> None:
        """Test that Severity behaves as a string."""
        assert Severity.HIGH == "HIGH"
        assert Severity.INFO.value == "INFO"
        assert str(Severity.MEDIUM) == "Severity.MEDIUM"


class TestAsset:
    def test_valid_asset_creation(self) -> None:
        """Test creating an Asset with valid fields."""
        asset = Asset(
            domain="example.com",
            ip="93.184.216.34",
            ports=[80, 443],
            tech_stack=["nginx"],
            discovered_via="crt.sh",
        )
        assert asset.domain == "example.com"
        assert asset.ip == "93.184.216.34"
        assert asset.ports == [80, 443]
        assert asset.tech_stack == ["nginx"]
        assert asset.discovered_via == "crt.sh"
        assert asset.asset_id is not None
        assert isinstance(asset.first_seen, datetime)

    def test_asset_empty_domain_raises(self) -> None:
        """Asset with empty or invalid domain must raise ValueError."""
        with pytest.raises(ValueError, match="domain must be a non-empty string"):
            Asset(domain="")

        with pytest.raises(ValueError, match="domain must be a non-empty string"):
            Asset(domain=None)  # type: ignore[arg-type]


class TestFinding:
    def test_valid_finding_creation(self, sample_asset: Asset) -> None:
        """Test creating a Finding linked to an Asset."""
        finding = Finding(
            asset=sample_asset,
            category="dns",
            severity=Severity.INFO,
            description="SPF record configured with -all",
            evidence="v=spf1 include:_spf.google.com -all",
        )
        assert finding.asset == sample_asset
        assert finding.category == "dns"
        assert finding.severity == Severity.INFO
        assert finding.finding_id is not None
        assert isinstance(finding.timestamp, datetime)

    def test_finding_string_severity_coercion(self, sample_asset: Asset) -> None:
        """Finding should coerce valid string severities to enum."""
        finding = Finding(
            asset=sample_asset,
            category="dns",
            severity="medium",  # type: ignore[arg-type]
            description="Test finding",
            evidence="Evidence",
        )
        assert finding.severity == Severity.MEDIUM

    def test_finding_invalid_severity_raises(self, sample_asset: Asset) -> None:
        """Finding with invalid severity string should raise ValueError."""
        with pytest.raises(ValueError, match="Invalid severity"):
            Finding(
                asset=sample_asset,
                category="dns",
                severity="CRITICAL",  # type: ignore[arg-type]
                description="Test finding",
                evidence="Evidence",
            )

    def test_finding_missing_description_raises(self, sample_asset: Asset) -> None:
        """Finding with empty description should raise ValueError."""
        with pytest.raises(ValueError, match="description must be a non-empty string"):
            Finding(
                asset=sample_asset,
                category="dns",
                severity=Severity.LOW,
                description="",
                evidence="",
            )

    def test_finding_missing_category_raises(self, sample_asset: Asset) -> None:
        """Finding with empty category should raise ValueError."""
        with pytest.raises(ValueError, match="category must be a non-empty string"):
            Finding(
                asset=sample_asset,
                category="",
                severity=Severity.LOW,
                description="Test description",
                evidence="",
            )
