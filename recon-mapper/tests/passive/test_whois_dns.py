"""
tests.passive.test_whois_dns
============================
Unit and integration tests for modules.passive.whois_dns with mocked DNS resolution.

Test Cases Covered:
  (1) Correctly parses all record types from a mocked zone with A/AAAA/MX/TXT/NS/CNAME/SOA present.
  (2) Flags an SPF TXT record as a Finding and extracts third-party mail senders.
  (3) Flags DKIM, DMARC, and vendor verification TXT records as Findings.
  (4) Handles NXDOMAIN, timeout, and no-nameserver responses without crashing.
  (5) Handles a domain with zero TXT records cleanly without spurious findings.
  (6) Integrates with public async run() pipeline entry-point with mocked WHOIS and DNS.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import pytest

import dns.exception
import dns.resolver

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage
from modules.passive.whois_dns import (
    _classify_txt,
    _enumerate_dns,
    _extract_dmarc_policy,
    _extract_spf_includes,
    _identify_mx_provider,
    _identify_ns_provider,
    _make_resolver,
    _parse_soa_hostmaster,
    _query,
    run,
)


# ---------------------------------------------------------------------------
# Test Helpers & Mock RData
# ---------------------------------------------------------------------------

class MockRdata:
    """Mock dnspython rdata object providing to_text()."""

    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text

    def __repr__(self) -> str:
        return f"MockRdata({self._text!r})"


def setup_dns_mock(
    monkeypatch: pytest.MonkeyPatch,
    zone_data: Dict[str, Dict[str, List[str]]],
    default_empty: bool = True,
) -> None:
    """Monkeypatch dns.resolver.Resolver.resolve to return predefined mock answers.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Pytest monkeypatch fixture.
    zone_data : dict
        Mapping of domain -> rdtype -> list of string values.
        Example:
        {
            "example.com": {
                "A": ["93.184.216.34"],
                "MX": ["10 aspmx.l.google.com."],
            }
        }
    default_empty : bool
        If True, queries for unlisted record types return an empty list.
        If False, unlisted domains raise dns.resolver.NXDOMAIN.
    """
    def mock_resolve(
        self: dns.resolver.Resolver,
        qname: Any,
        rdtype: str = "A",
        *args: Any,
        **kwargs: Any,
    ) -> List[MockRdata]:
        domain = str(qname).rstrip(".").lower()
        rdtype_str = str(rdtype).upper()

        domain_records = zone_data.get(domain)
        if domain_records is None:
            if default_empty:
                return []
            raise dns.resolver.NXDOMAIN(f"Mock NXDOMAIN for {domain}")

        records = domain_records.get(rdtype_str, [])
        return [MockRdata(val) for val in records]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", mock_resolve)


# ---------------------------------------------------------------------------
# Test Case 1: All standard record types parsed from mocked zone
# ---------------------------------------------------------------------------

def test_parses_all_record_types_from_mocked_zone(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Test case 1: correctly parses all record types from a mocked zone

    with A/AAAA/MX/TXT/NS/CNAME/SOA present.
    """
    domain = sample_asset.domain  # "api.target.example"
    sample_asset.ip = None        # reset IP to test population

    zone = {
        domain: {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["10 aspmx.l.google.com.", "20 alt1.aspmx.l.google.com."],
            "TXT": ['"v=spf1 include:_spf.google.com ~all"'],
            "NS": ["ns1.cloudflare.com.", "ns2.cloudflare.com."],
            "CNAME": ["cluster-internal.target.example."],
            "SOA": [
                "ns1.cloudflare.com. hostmaster.cloudflare.com. 2026010101 3600 900 604800 300"
            ],
        }
    }
    setup_dns_mock(monkeypatch, zone)

    resolver = _make_resolver()
    storage.save_asset(sample_asset)
    _enumerate_dns(resolver, sample_asset, storage)

    # 1. Verify Asset fields were updated
    updated_asset = storage.get_asset_by_id(sample_asset.asset_id)
    assert updated_asset is not None
    assert updated_asset.ip == "93.184.216.34"

    # Verify tech_stack fingerprinting
    assert "ipv4:93.184.216.34" in updated_asset.tech_stack
    assert "ipv6:2606:2800:220:1:248:1893:25c8:1946" in updated_asset.tech_stack
    assert "email:Google Workspace" in updated_asset.tech_stack
    assert "dns:Cloudflare" in updated_asset.tech_stack
    assert "hostmaster:hostmaster@cloudflare.com" in updated_asset.tech_stack

    # 2. Verify Findings were recorded for each record type
    findings = storage.get_findings(asset=sample_asset)
    categories = {f.category for f in findings}

    assert "dns/a" in categories
    assert "dns/aaaa" in categories
    assert "dns/mx" in categories
    assert "dns/txt" in categories
    assert "dns/ns" in categories
    assert "dns/cname" in categories
    assert "dns/soa" in categories

    # Verify severity is INFO for DNS record disclosures
    for f in findings:
        assert f.severity == Severity.INFO


# ---------------------------------------------------------------------------
# Test Case 2: SPF TXT record flagged as a Finding with vendor disclosure
# ---------------------------------------------------------------------------

def test_flags_spf_txt_record_as_finding(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Test case 2: flags an SPF TXT record as a Finding, extracts third-party

    mail senders (include: clauses), and annotates the asset tech stack.
    """
    domain = sample_asset.domain
    spf_value = (
        '"v=spf1 include:_spf.google.com include:sendgrid.net '
        'include:mailchimpapp.net -all"'
    )

    zone = {
        domain: {
            "TXT": [spf_value],
        }
    }
    setup_dns_mock(monkeypatch, zone)

    resolver = _make_resolver()
    storage.save_asset(sample_asset)
    _enumerate_dns(resolver, sample_asset, storage)

    findings = storage.get_findings(asset=sample_asset)
    spf_finding = next((f for f in findings if f.category == "txt/spf"), None)

    assert spf_finding is not None
    assert spf_finding.severity == Severity.INFO
    assert "3 third-party mail sender(s) authorised" in spf_finding.description
    assert "_spf.google.com" in spf_finding.evidence
    assert "sendgrid.net" in spf_finding.evidence
    assert "mailchimpapp.net" in spf_finding.evidence

    # Verify third-party senders were added to asset tech stack
    updated_asset = storage.get_asset_by_id(sample_asset.asset_id)
    assert updated_asset is not None
    assert "mail-sender:_spf.google.com" in updated_asset.tech_stack
    assert "mail-sender:sendgrid.net" in updated_asset.tech_stack
    assert "mail-sender:mailchimpapp.net" in updated_asset.tech_stack


# ---------------------------------------------------------------------------
# Test Case 3: DKIM & vendor verification TXT records flagged as Findings
# ---------------------------------------------------------------------------

def test_flags_dkim_and_verification_txt_records(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Test case 3: flags a DKIM public key and third-party verification TXT

    records (Google, Atlassian, Microsoft, DMARC) as Findings.
    """
    domain = sample_asset.domain
    txt_records = [
        '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1234567890"',
        '"google-site-verification=rXOxyZounnZMTV7wbTTW6n9SooVNwWpk7Unjh8YZ5c0"',
        '"atlassian-domain-verification=mytokenABC123"',
        '"MS=ms987654321"',
        '"v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@target.example"',
    ]

    zone = {
        domain: {
            "TXT": txt_records,
        }
    }
    setup_dns_mock(monkeypatch, zone)

    resolver = _make_resolver()
    storage.save_asset(sample_asset)
    _enumerate_dns(resolver, sample_asset, storage)

    findings = storage.get_findings(asset=sample_asset)

    # 1. DKIM Finding
    dkim_finding = next((f for f in findings if f.category == "txt/dkim"), None)
    assert dkim_finding is not None
    assert dkim_finding.severity == Severity.INFO
    assert "DKIM public key record found" in dkim_finding.description

    # 2. DMARC Finding
    dmarc_finding = next((f for f in findings if f.category == "txt/dmarc"), None)
    assert dmarc_finding is not None
    assert "p=reject" in dmarc_finding.description
    assert "Policy is enforced" in dmarc_finding.description

    # 3. Vendor verification Findings
    vendor_findings = [f for f in findings if f.category == "txt/vendor-token"]
    assert len(vendor_findings) == 3

    vendor_descriptions = " ".join(f.description for f in vendor_findings)
    assert "Google site verification" in vendor_descriptions
    assert "Atlassian (Jira/Confluence)" in vendor_descriptions
    assert "Microsoft domain verification" in vendor_descriptions


# ---------------------------------------------------------------------------
# Test Case 4: Handles NXDOMAIN / no-record responses without crashing
# ---------------------------------------------------------------------------

def test_handles_nxdomain_and_dns_exceptions(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Test case 4: handles NXDOMAIN, timeout, and resolver errors gracefully

    without crashing or polluting storage.
    """
    resolver = _make_resolver()

    # Sub-case A: NXDOMAIN
    def mock_nxdomain(*args: Any, **kwargs: Any) -> Any:
        raise dns.resolver.NXDOMAIN("Mock Non-Existent Domain")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", mock_nxdomain)
    res_nx = _query(resolver, "nonexistent.example", "A")
    assert res_nx == []

    # Sub-case B: NoNameservers
    def mock_no_nameservers(*args: Any, **kwargs: Any) -> Any:
        raise dns.resolver.NoNameservers("Mock NoNameservers")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", mock_no_nameservers)
    res_ns = _query(resolver, "broken.example", "A")
    assert res_ns == []

    # Sub-case C: Timeout
    def mock_timeout(*args: Any, **kwargs: Any) -> Any:
        raise dns.exception.Timeout("Mock DNS Query Timeout")

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", mock_timeout)
    res_to = _query(resolver, "timeout.example", "A")
    assert res_to == []

    # Sub-case D: Full _enumerate_dns call under NXDOMAIN doesn't crash
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", mock_nxdomain)
    storage.save_asset(sample_asset)
    new_assets = _enumerate_dns(resolver, sample_asset, storage)

    assert new_assets == []
    # No DNS findings should be recorded for a dead domain
    assert storage.get_findings(asset=sample_asset) == []


# ---------------------------------------------------------------------------
# Test Case 5: Domain with zero TXT records
# ---------------------------------------------------------------------------

def test_handles_domain_with_zero_txt_records(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Test case 5: handles a domain with zero TXT records cleanly."""
    domain = sample_asset.domain

    zone = {
        domain: {
            "A": ["93.184.216.34"],
            "NS": ["ns1.example.com."],
            "TXT": [],  # explicitly zero TXT records
        }
    }
    setup_dns_mock(monkeypatch, zone)

    resolver = _make_resolver()
    storage.save_asset(sample_asset)
    _enumerate_dns(resolver, sample_asset, storage)

    findings = storage.get_findings(asset=sample_asset)
    categories = [f.category for f in findings]

    # A and NS records should be captured
    assert "dns/a" in categories
    assert "dns/ns" in categories

    # Absolutely no TXT findings should be present
    assert "dns/txt" not in categories
    assert not any(c.startswith("txt/") for c in categories)


# ---------------------------------------------------------------------------
# Takeover Detection & Pipeline run() Integration Test
# ---------------------------------------------------------------------------

def test_cname_takeover_candidate_detection(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Verify that vulnerable CNAME targets (e.g. GitHub Pages) emit a LOW finding."""
    zone = {
        sample_asset.domain: {
            "CNAME": ["myorg.github.io."],
        }
    }
    setup_dns_mock(monkeypatch, zone)

    resolver = _make_resolver()
    storage.save_asset(sample_asset)
    _enumerate_dns(resolver, sample_asset, storage)

    findings = storage.get_findings(asset=sample_asset)
    takeover_finding = next(
        (f for f in findings if f.category == "dns/cname-takeover-candidate"), None
    )
    assert takeover_finding is not None
    assert takeover_finding.severity == Severity.LOW
    assert "GitHub Pages" in takeover_finding.description


async def test_whois_dns_run_pipeline_integration(
    monkeypatch: pytest.MonkeyPatch,
    storage: ReconStorage,
    sample_asset: Asset,
) -> None:
    """Verify public async run() pipeline entry-point executes both DNS and WHOIS."""
    target = sample_asset.domain

    # Mock DNS
    zone = {
        target: {
            "A": ["93.184.216.34"],
            "NS": ["ns1.cloudflare.com."],
        }
    }
    setup_dns_mock(monkeypatch, zone)

    # Mock WHOIS lookup offline
    mock_whois_data = {
        "registrar": "MarkMonitor Inc.",
        "creation_date": datetime(2010, 5, 20, tzinfo=timezone.utc),
        "expiration_date": datetime(2030, 5, 20, tzinfo=timezone.utc),
        "updated_date": datetime(2025, 1, 1, tzinfo=timezone.utc),
        "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
        "org": "Target Corp",
        "country": "US",
        "dnssec": "unsigned",
    }
    monkeypatch.setattr("modules.passive.whois_dns._safe_whois", lambda domain: mock_whois_data)

    storage.save_asset(sample_asset)
    await run(assets=[sample_asset], storage=storage, target=target)

    # Verify both DNS and WHOIS findings were persisted
    findings = storage.get_findings(asset=sample_asset)
    categories = {f.category for f in findings}

    assert "dns/a" in categories
    assert "dns/ns" in categories
    assert "whois" in categories

    whois_finding = next(f for f in findings if f.category == "whois")
    assert whois_finding.severity == Severity.INFO
    assert "MarkMonitor Inc." in whois_finding.evidence
    assert "Target Corp" in whois_finding.evidence
