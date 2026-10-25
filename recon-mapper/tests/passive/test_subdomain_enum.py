"""
tests.passive.test_subdomain_enum
=================================
Tests for modules.passive.subdomain_enum using respx to mock HTTP calls.

Covers:
  (1) Returns deduped Asset list from valid crt.sh JSON with duplicates and wildcards.
  (2) Handles empty results gracefully without raising errors.
  (3) Falls back to HackerTarget passive-DNS when crt.sh returns HTTP 429.
  (4) Strips wildcard prefixes (*.sub.example.com) correctly.
"""

from __future__ import annotations

import httpx
import pytest

from core.models import Asset, Severity
from core.storage import ReconStorage
from modules.passive.subdomain_enum import (
    _normalise_hostname,
    _is_in_scope,
    run,
)


# ---------------------------------------------------------------------------
# Test Case 1: Deduplication & normalization from valid crt.sh response
# ---------------------------------------------------------------------------

async def test_returns_deduped_assets_from_crtsh(
    storage: ReconStorage, respx_mock
) -> None:
    """Test case 1: returns deduped Asset list from a valid crt.sh JSON response

    with duplicate and wildcard entries.
    """
    target = "example.com"
    crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"

    # Simulate realistic crt.sh payload with:
    # - Newline-separated multi-SAN entries
    # - Duplicate hostnames across different certificates
    # - Wildcards (*.example.com, *.api.example.com)
    # - Mixed casing (AUTH.EXAMPLE.COM vs auth.example.com)
    # - Out-of-scope certificates that SAN-bundled unrelated domains
    mock_payload = [
        {
            "name_value": "api.example.com\n*.example.com",
            "id": 1001,
        },
        {
            "name_value": "api.example.com\nAUTH.EXAMPLE.COM",
            "id": 1002,
        },
        {
            "name_value": "*.api.example.com\nauth.example.com",
            "id": 1003,
        },
        {
            "name_value": "unrelated.otherdomain.org\nportal.example.com",
            "id": 1004,
        },
    ]

    respx_mock.get(crtsh_url).respond(status_code=200, json=mock_payload)

    # Initial assets list is empty
    await run(assets=[], storage=storage, target=target)

    # Verify assets in storage
    saved_assets = storage.get_assets()
    domains = [a.domain for a in saved_assets]

    # Verify deduplication & normalization
    assert len(domains) == len(set(domains)), f"Found duplicate domains: {domains}"

    expected_domains = {
        "example.com",
        "api.example.com",
        "auth.example.com",
        "portal.example.com",
    }
    for expected in expected_domains:
        assert expected in domains, f"Missing expected domain: {expected}"

    # Ensure out-of-scope domain was rejected
    assert "unrelated.otherdomain.org" not in domains

    # Verify all assets have the expected source label
    for asset in saved_assets:
        if asset.domain != target:
            assert asset.discovered_via == "cert_ct/crt.sh"

    # Verify a summary finding was recorded on the target root asset
    findings = storage.get_findings()
    assert len(findings) == 1
    summary = findings[0]
    assert summary.category == "subdomain-enum"
    assert summary.severity == Severity.INFO
    assert "CT log enumeration discovered" in summary.description


# ---------------------------------------------------------------------------
# Test Case 2: Empty results handling
# ---------------------------------------------------------------------------

async def test_handles_empty_results_gracefully(
    storage: ReconStorage, respx_mock
) -> None:
    """Test case 2: handles empty results gracefully without errors or corrupt state."""
    target = "empty-domain.example"
    crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"

    respx_mock.get(crtsh_url).respond(status_code=200, json=[])

    # Should complete cleanly without raising exceptions
    await run(assets=[], storage=storage, target=target)

    # No assets should be added to storage
    assert storage.get_assets() == []
    assert storage.get_findings() == []


async def test_handles_non_list_json_gracefully(
    storage: ReconStorage, respx_mock
) -> None:
    """Verify that unexpected JSON shapes (e.g. error dict) are handled gracefully."""
    target = "invalid-shape.example"
    crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"

    respx_mock.get(crtsh_url).respond(status_code=200, json={"error": "none found"})

    await run(assets=[], storage=storage, target=target)
    assert storage.get_assets() == []


# ---------------------------------------------------------------------------
# Test Case 3: Secondary passive-DNS fallback on 429 rate limit
# ---------------------------------------------------------------------------

async def test_falls_back_to_secondary_passive_dns_on_rate_limit(
    storage: ReconStorage, respx_mock
) -> None:
    """Test case 3: falls back to the secondary passive-DNS source (HackerTarget)

    when crt.sh returns a 429/rate-limit.
    """
    target = "ratelimited.example"
    crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"
    ht_url = f"https://api.hackertarget.com/hostsearch/?q={target}"

    # Primary source returns HTTP 429
    crtsh_route = respx_mock.get(crtsh_url).respond(status_code=429)

    # Fallback source returns plain text "hostname,ip" records
    ht_body = (
        f"api.{target},192.0.2.1\n"
        f"mail.{target},192.0.2.2\n"
        f"vpn.{target},192.0.2.3\n"
    )
    ht_route = respx_mock.get(ht_url).respond(status_code=200, text=ht_body)

    await run(assets=[], storage=storage, target=target)

    # Both routes should have been called
    assert crtsh_route.called
    assert ht_route.called

    # Check assets saved from HackerTarget fallback
    saved_assets = storage.get_assets()
    domains = {a.domain for a in saved_assets}

    assert f"api.{target}" in domains
    assert f"mail.{target}" in domains
    assert f"vpn.{target}" in domains

    # Verify discovered_via indicates the fallback source
    fallback_assets = [a for a in saved_assets if a.domain != target]
    for asset in fallback_assets:
        assert asset.discovered_via == "cert_ct/hackertarget-fallback"

    # Verify summary finding reflects fallback
    findings = storage.get_findings()
    assert len(findings) == 1
    assert "hackertarget-fallback" in findings[0].description


# ---------------------------------------------------------------------------
# Test Case 4: Wildcard prefix stripping
# ---------------------------------------------------------------------------

def test_strips_wildcard_prefixes_unit() -> None:
    """Test case 4 (unit): verifies _normalise_hostname strips *. prefixes."""
    assert _normalise_hostname("*.sub.example.com") == "sub.example.com"
    assert _normalise_hostname("*.vpn.internal.example.com") == "vpn.internal.example.com"
    assert _normalise_hostname("*.EXAMPLE.COM") == "example.com"
    assert _normalise_hostname("  *.dev.example.com.  ") == "dev.example.com"
    assert _normalise_hostname("plain.example.com") == "plain.example.com"

    # Non-hostnames / invalid entries
    assert _normalise_hostname("192.168.1.1") is None
    assert _normalise_hostname("") is None
    assert _normalise_hostname("*.invalid..com") is None


async def test_strips_wildcard_prefixes_integration(
    storage: ReconStorage, respx_mock
) -> None:
    """Test case 4 (integration): verifies wildcard hostnames returned in crt.sh

    are saved without any wildcard characters (*.) in Asset.domain.
    """
    target = "wildcard.example"
    crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"

    respx_mock.get(crtsh_url).respond(
        status_code=200,
        json=[
            {"name_value": f"*.sub.{target}"},
            {"name_value": f"*.deep.cluster.{target}"},
            {"name_value": f"direct.{target}"},
        ],
    )

    await run(assets=[], storage=storage, target=target)

    saved_assets = storage.get_assets()
    domains = [a.domain for a in saved_assets]

    # None of the domains should contain asterisk
    for domain in domains:
        assert "*" not in domain, f"Domain contains unstripped wildcard: {domain}"

    assert f"sub.{target}" in domains
    assert f"deep.cluster.{target}" in domains
    assert f"direct.{target}" in domains


# ---------------------------------------------------------------------------
# Scope & Pre-existing Asset Tests
# ---------------------------------------------------------------------------

def test_scope_validation() -> None:
    """Verify that _is_in_scope correctly checks root and subdomains."""
    assert _is_in_scope("example.com", "example.com")
    assert _is_in_scope("sub.example.com", "example.com")
    assert _is_in_scope("deep.sub.example.com", "example.com")
    assert not _is_in_scope("other-example.com", "example.com")
    assert not _is_in_scope("example.com.evil.com", "example.com")


async def test_skips_preexisting_assets_in_storage(
    storage: ReconStorage, respx_mock
) -> None:
    """Verify that existing assets in storage are not duplicated."""
    target = "preexisting.example"
    crtsh_url = f"https://crt.sh/?q=%.{target}&output=json"

    respx_mock.get(crtsh_url).respond(
        status_code=200,
        json=[
            {"name_value": f"known.{target}"},
            {"name_value": f"new.{target}"},
        ],
    )

    existing_asset = Asset(domain=f"known.{target}", discovered_via="manual")
    storage.save_asset(existing_asset)

    # Pass the existing asset to run()
    await run(assets=[existing_asset], storage=storage, target=target)

    saved_assets = storage.get_assets()
    domains = [a.domain for a in saved_assets]
    assert domains.count(f"known.{target}") == 1
    assert f"new.{target}" in domains
