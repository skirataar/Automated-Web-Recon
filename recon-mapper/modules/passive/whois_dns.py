"""
modules.passive.whois_dns
=========================
DNS record enumeration and WHOIS / RDAP data collection.

Technique background
--------------------

DNS Record Types and What They Reveal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Every DNS record type leaks a different slice of an organisation's
infrastructure topology.  This module collects all standard types:

``A``
    Maps a hostname to an IPv4 address.  The address range reveals the
    hosting provider (AWS, GCP, Azure, Cloudflare, on-prem) and whether
    a CDN sits in front of the origin.  Historical A records (not covered
    here) can surface decommissioned servers.

``AAAA``
    Maps a hostname to an IPv6 address.  IPv6 endpoints often skip WAF
    inspection (many rules target IPv4 only).  Presence indicates dual-stack
    infrastructure.

``MX``
    Mail eXchange — hostname + priority for inbound SMTP.  Reveals the email
    provider (Google Workspace → ``aspmx.l.google.com``, Microsoft 365 →
    ``*.mail.protection.outlook.com``, Proofpoint, Mimecast, etc.).  MX
    records may expose internal relay FQDNs that do not appear in public DNS.

``TXT``
    Arbitrary text — the richest passive-recon record type:

    * **SPF** (``v=spf1 include:…``): lists every authorised outbound mail
      sender.  Each ``include:`` clause identifies a third-party SaaS product
      (Mailchimp, SendGrid, HubSpot, Zendesk, Salesforce, …).
    * **DKIM** selector records (``<selector>._domainkey.<domain>``): confirm
      which email platform signs mail; selector naming conventions reveal
      the provider (``google._domainkey.`` → Google Workspace).
    * **Site-verification tokens**: ``google-site-verification=``,
      ``MS=…`` (Microsoft), ``atlassian-domain-verification=``,
      ``facebook-domain-verification=``, ``apple-domain-verification=`` —
      each token proves the org has linked that SaaS product to the domain.
    * **DMARC** (``_dmarc.`` prefix): reveals the email security posture
      (``p=none`` = monitoring only, ``p=quarantine/reject`` = enforced).

``NS``
    Authoritative nameservers for the zone.  Reveals the DNS provider
    (Route 53, Cloudflare, dnsimple, NS1).  Multiple NS records from
    different providers may indicate a secondary/backup zone.  NS records
    are a prerequisite for zone-transfer attempts (AXFR).

``CNAME``
    Alias pointing to another hostname.  Reveals third-party hosting
    (``shop.example.com → example.myshopify.com``, ``cdn.example.com →
    example.cloudfront.net``).  When the target of a CNAME no longer
    exists, the alias is a **subdomain takeover** candidate.

``SOA``
    Start of Authority — contains the primary NS, a hostmaster email (often
    redacted but sometimes real), zone serial number (reveals update cadence),
    and TTL values.  Low refresh TTLs suggest dynamic / frequently-changing
    infrastructure.

WHOIS / RDAP and GDPR
~~~~~~~~~~~~~~~~~~~~~~
Pre-2018, WHOIS exposed registrant name, email, phone, and address.  The
GDPR (May 2018) and ICANN's Temporary Specification caused almost all gTLD
registrars to redact or proxy this PII.

What **reliably survives** post-GDPR:
- Registrar name and URL
- Domain creation, updated, and expiry dates
- Nameservers (same as NS records, from the registry's authoritative view)
- Registrant country and organisation (sometimes)
- DNSSEC status

What is **always redacted** (gTLDs: .com/.net/.org):
- Registrant name, email, phone, street address

ccTLDs (.uk, .de, .fr …) vary by country — some still expose PII.

This module queries WHOIS via ``python-whois`` and records surviving fields
as a single ``INFO``-severity Finding on the root-domain Asset.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import dns.exception
import dns.rdatatype
import dns.resolver
import whois  # python-whois

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Standard record types to enumerate for every domain
_RECORD_TYPES: List[str] = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

# DNS resolver timeout per query attempt (seconds)
_DNS_TIMEOUT: float = 5.0

# ── TXT record classifier patterns ─────────────────────────────────────────
# Each entry: (regex_pattern, human_label, severity)
# Ordered from most- to least-specific so the first match wins.
_TXT_PATTERNS: List[Tuple[re.Pattern[str], str, Severity]] = [
    # SPF
    (re.compile(r"^v=spf1", re.I),                       "SPF record",                   Severity.INFO),
    # DMARC (typically on _dmarc subdomain, but include here for TXT fallback)
    (re.compile(r"^v=DMARC1", re.I),                     "DMARC policy",                 Severity.INFO),
    # DKIM public key
    (re.compile(r"v=DKIM1",  re.I),                      "DKIM public key",              Severity.INFO),
    # Third-party verification tokens — these directly identify SaaS vendors
    (re.compile(r"google-site-verification=", re.I),     "Google site verification",     Severity.INFO),
    (re.compile(r"^MS=",                      re.I),     "Microsoft domain verification",Severity.INFO),
    (re.compile(r"atlassian-domain-verification=", re.I),"Atlassian (Jira/Confluence)",  Severity.INFO),
    (re.compile(r"facebook-domain-verification=", re.I), "Facebook domain verification", Severity.INFO),
    (re.compile(r"apple-domain-verification=", re.I),    "Apple domain verification",    Severity.INFO),
    (re.compile(r"docusign=",                 re.I),     "DocuSign verification",        Severity.INFO),
    (re.compile(r"hubspot-developer-verification=", re.I),"HubSpot verification",        Severity.INFO),
    (re.compile(r"stripe-verification=",      re.I),     "Stripe verification",          Severity.INFO),
    (re.compile(r"adobe-idp-site-verification=", re.I),  "Adobe IDP verification",       Severity.INFO),
    (re.compile(r"shopify-domain-verification=", re.I),  "Shopify verification",         Severity.INFO),
    (re.compile(r"status-page-domain-verification=", re.I),"Atlassian Statuspage",       Severity.INFO),
    (re.compile(r"segment-site-verification=", re.I),    "Twilio Segment verification",  Severity.INFO),
    (re.compile(r"Dynatrace",                 re.I),     "Dynatrace APM",                Severity.INFO),
    (re.compile(r"loaderio=",                 re.I),     "Loader.io load-test token",    Severity.INFO),
    (re.compile(r"brave-ledger-verification=",re.I),     "Brave Rewards verification",   Severity.INFO),
    # Generic catch-all for any remaining verification-style tokens
    (re.compile(r"verification|verify|token", re.I),     "Domain verification token",    Severity.INFO),
]

# SPF include: clause extractor — each clause names a third-party mail sender
_SPF_INCLUDE_RE = re.compile(r"include:(\S+)", re.I)

# DMARC policy extractor
_DMARC_POLICY_RE = re.compile(r"p=(none|quarantine|reject)", re.I)


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _make_resolver() -> dns.resolver.Resolver:
    """Return a configured dnspython Resolver with sensible timeouts."""
    r = dns.resolver.Resolver()
    r.lifetime = _DNS_TIMEOUT * 2   # total wall-clock limit per query
    r.timeout  = _DNS_TIMEOUT       # per-nameserver attempt limit
    return r


def _query(
    resolver: dns.resolver.Resolver,
    domain: str,
    rdtype: str,
) -> List[str]:
    """Run a single DNS query and return string representations of answers.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        Pre-configured resolver instance.
    domain : str
        FQDN to query.
    rdtype : str
        Record type string (``"A"``, ``"TXT"``, …).

    Returns
    -------
    List[str]
        Raw string representations of each answer rdata, or an empty list
        if the name / type does not exist or a network error occurs.
    """
    try:
        answers = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        return [rdata.to_text() for rdata in answers]
    except dns.resolver.NXDOMAIN:
        logger.debug("DNS NXDOMAIN: %s %s", rdtype, domain)
        return []
    except dns.resolver.NoNameservers:
        logger.debug("DNS NoNameservers: %s %s", rdtype, domain)
        return []
    except dns.exception.Timeout:
        logger.debug("DNS timeout: %s %s", rdtype, domain)
        return []
    except dns.exception.DNSException as exc:
        logger.debug("DNS error (%s %s): %s", rdtype, domain, exc)
        return []


def _classify_txt(record: str) -> Optional[Tuple[str, Severity]]:
    """Return ``(label, severity)`` if *record* matches a known TXT pattern.

    Parameters
    ----------
    record : str
        Raw TXT record string (with surrounding quotes already stripped).

    Returns
    -------
    Optional[Tuple[str, Severity]]
        ``(human_label, severity)`` on match, ``None`` otherwise.
    """
    for pattern, label, severity in _TXT_PATTERNS:
        if pattern.search(record):
            return label, severity
    return None


def _strip_txt_quotes(raw: str) -> str:
    """dnspython wraps TXT values in double-quotes; strip them."""
    return raw.strip('"').strip()


def _extract_spf_includes(spf_record: str) -> List[str]:
    """Return every ``include:`` domain listed in an SPF record.

    These domains directly identify third-party mail services the organisation
    uses (Mailchimp, SendGrid, HubSpot, Salesforce, …).
    """
    return _SPF_INCLUDE_RE.findall(spf_record)


def _extract_dmarc_policy(dmarc_record: str) -> str:
    """Return the DMARC ``p=`` policy value, or ``'unknown'`` if missing."""
    match = _DMARC_POLICY_RE.search(dmarc_record)
    return match.group(1).lower() if match else "unknown"


# ---------------------------------------------------------------------------
# Per-domain DNS enumeration
# ---------------------------------------------------------------------------

def _enumerate_dns(
    resolver: dns.resolver.Resolver,
    asset: Asset,
    storage: ReconStorage,
) -> List[Asset]:
    """Query all standard record types for *asset.domain* and persist findings.

    For each non-empty record type:
    - Stores a ``Finding(category="dns/<rdtype>", severity=INFO)``.
    - For ``A``/``AAAA`` records, updates ``asset.ip`` and ``asset.tech_stack``.
    - For ``TXT`` records, classifies each value and emits an additional
      labelled Finding per interesting token.
    - For ``NS`` records, appends authoritative nameservers to
      ``asset.tech_stack``.

    Parameters
    ----------
    resolver : dns.resolver.Resolver
        Pre-configured DNS resolver.
    asset : Asset
        The asset whose domain is being queried.  Mutated in place
        (``ip``, ``tech_stack``) and saved to storage.
    storage : ReconStorage
        Open storage for writing findings and the updated asset.

    Returns
    -------
    List[Asset]
        New Asset objects discovered during enumeration (e.g. MX / NS /
        CNAME targets that are in-scope).  Callers should persist these.
    """
    domain = asset.domain
    new_assets: List[Asset] = []
    tech_stack_additions: List[str] = []

    for rdtype in _RECORD_TYPES:
        records = _query(resolver, domain, rdtype)
        if not records:
            logger.debug("[dns] %s %s → (no records)", rdtype, domain)
            continue

        logger.debug("[dns] %s %s → %d record(s)", rdtype, domain, len(records))
        evidence_lines: List[str] = []

        for raw in records:
            value = raw.strip()

            # ── A record: update asset.ip, fingerprint hosting ────────────
            if rdtype == "A":
                if asset.ip is None:
                    asset.ip = value
                tech_stack_additions.append(f"ipv4:{value}")
                evidence_lines.append(value)

            # ── AAAA record: note dual-stack ──────────────────────────────
            elif rdtype == "AAAA":
                tech_stack_additions.append(f"ipv6:{value}")
                evidence_lines.append(value)

            # ── MX record: parse priority and mail server ─────────────────
            elif rdtype == "MX":
                # dnspython emits "10 aspmx.l.google.com."
                parts = value.split(None, 1)
                mail_host = parts[1].rstrip(".") if len(parts) == 2 else value.rstrip(".")
                evidence_lines.append(value)
                # Identify provider from well-known mail server patterns
                mx_label = _identify_mx_provider(mail_host)
                if mx_label:
                    tech_stack_additions.append(mx_label)

            # ── NS record: DNS provider fingerprint ───────────────────────
            elif rdtype == "NS":
                ns_host = value.rstrip(".")
                evidence_lines.append(ns_host)
                ns_label = _identify_ns_provider(ns_host)
                if ns_label:
                    tech_stack_additions.append(ns_label)

            # ── CNAME: note alias target, flag potential takeover ─────────
            elif rdtype == "CNAME":
                cname_target = value.rstrip(".")
                evidence_lines.append(cname_target)
                _check_cname_takeover(cname_target, asset, storage)

            # ── SOA: extract hostmaster email and zone metadata ───────────
            elif rdtype == "SOA":
                evidence_lines.append(value)
                hostmaster = _parse_soa_hostmaster(value)
                if hostmaster:
                    tech_stack_additions.append(f"hostmaster:{hostmaster}")

            # ── TXT: the richest record type ──────────────────────────────
            elif rdtype == "TXT":
                clean = _strip_txt_quotes(value)
                evidence_lines.append(clean)
                _process_txt_record(clean, asset, storage)

        # One consolidated Finding per record type
        if evidence_lines:
            storage.save_finding(Finding(
                asset=asset,
                category=f"dns/{rdtype.lower()}",
                severity=Severity.INFO,
                description=(
                    f"{rdtype} record(s) for {domain!r}: "
                    f"{len(evidence_lines)} value(s) found."
                ),
                evidence="\n".join(evidence_lines),
            ))

    # Flush tech_stack additions (deduplicated)
    for tag in tech_stack_additions:
        if tag not in asset.tech_stack:
            asset.tech_stack.append(tag)
    storage.save_asset(asset)

    return new_assets


def _process_txt_record(
    clean: str,
    asset: Asset,
    storage: ReconStorage,
) -> None:
    """Classify a TXT record value and emit an additional labelled Finding.

    For SPF records, also emits a separate Finding listing every ``include:``
    domain (third-party mail sender disclosure).

    For DMARC records, notes the policy enforcement level.
    """
    classification = _classify_txt(clean)
    if classification is None:
        return  # Unrecognised TXT — recorded in the parent dns/txt Finding

    label, severity = classification

    # SPF: extract and annotate include: clauses
    if clean.lower().startswith("v=spf1"):
        includes = _extract_spf_includes(clean)
        extra = ""
        if includes:
            extra = (
                "\nAuthorised third-party mail senders (include: clauses):\n  "
                + "\n  ".join(includes)
            )
            for inc_domain in includes:
                if inc_domain not in asset.tech_stack:
                    asset.tech_stack.append(f"mail-sender:{inc_domain}")
        storage.save_finding(Finding(
            asset=asset,
            category="txt/spf",
            severity=severity,
            description=(
                f"SPF record found for {asset.domain!r}. "
                f"{len(includes)} third-party mail sender(s) authorised."
            ),
            evidence=clean + extra,
        ))

    # DMARC: record policy enforcement level
    elif clean.lower().startswith("v=dmarc1"):
        policy = _extract_dmarc_policy(clean)
        storage.save_finding(Finding(
            asset=asset,
            category="txt/dmarc",
            severity=severity,
            description=(
                f"DMARC policy found for {asset.domain!r}: "
                f"p={policy}. "
                + (
                    "Policy is enforced (quarantine/reject)."
                    if policy in ("quarantine", "reject")
                    else "⚠️  Policy is 'none' — monitoring only, not enforced."
                )
            ),
            evidence=clean,
        ))

    # DKIM public key
    elif "v=dkim1" in clean.lower():
        storage.save_finding(Finding(
            asset=asset,
            category="txt/dkim",
            severity=severity,
            description=f"DKIM public key record found on {asset.domain!r}.",
            evidence=clean[:400],   # keys can be very long; truncate for readability
        ))

    # Third-party verification tokens
    else:
        storage.save_finding(Finding(
            asset=asset,
            category="txt/vendor-token",
            severity=severity,
            description=(
                f"{label} token found on {asset.domain!r}. "
                "This confirms the organisation uses this service."
            ),
            evidence=clean,
        ))


# ---------------------------------------------------------------------------
# Provider fingerprinting helpers
# ---------------------------------------------------------------------------

_MX_PROVIDERS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"google\.com$",          re.I), "email:Google Workspace"),
    (re.compile(r"googlemail\.com$",      re.I), "email:Google Workspace"),
    (re.compile(r"protection\.outlook\.com$", re.I), "email:Microsoft 365"),
    (re.compile(r"pphosted\.com$",        re.I), "email:Proofpoint"),
    (re.compile(r"mimecast\.com$",        re.I), "email:Mimecast"),
    (re.compile(r"mailgun\.org$",         re.I), "email:Mailgun"),
    (re.compile(r"sendgrid\.net$",        re.I), "email:SendGrid"),
    (re.compile(r"amazonses\.com$",       re.I), "email:Amazon SES"),
    (re.compile(r"zoho\.com$",            re.I), "email:Zoho Mail"),
    (re.compile(r"mailchimp\.com$",       re.I), "email:Mailchimp"),
    (re.compile(r"messagelabs\.com$",     re.I), "email:Symantec MessageLabs"),
    (re.compile(r"barracudanetworks\.com$",re.I), "email:Barracuda"),
]

_NS_PROVIDERS: List[Tuple[re.Pattern[str], str]] = [
    (re.compile(r"awsdns",               re.I), "dns:Amazon Route 53"),
    (re.compile(r"(?:\.ns|ns\d*)\.cloudflare\.com$", re.I), "dns:Cloudflare"),
    (re.compile(r"dnsimple\.com$",       re.I), "dns:DNSimple"),
    (re.compile(r"nsone\.net$",          re.I), "dns:NS1"),
    (re.compile(r"azure-dns\.",          re.I), "dns:Azure DNS"),
    (re.compile(r"\.googledomains\.com$",re.I), "dns:Google Cloud DNS"),
    (re.compile(r"domaincontrol\.com$",  re.I), "dns:GoDaddy"),
    (re.compile(r"registrar-servers\.com$", re.I), "dns:Namecheap"),
    (re.compile(r"ultradns\.",           re.I), "dns:Neustar UltraDNS"),
    (re.compile(r"akamaiedge\.",         re.I), "dns:Akamai"),
]


def _identify_mx_provider(mail_host: str) -> Optional[str]:
    for pattern, label in _MX_PROVIDERS:
        if pattern.search(mail_host):
            return label
    return None


def _identify_ns_provider(ns_host: str) -> Optional[str]:
    for pattern, label in _NS_PROVIDERS:
        if pattern.search(ns_host):
            return label
    return None


def _parse_soa_hostmaster(soa_text: str) -> Optional[str]:
    """Extract the hostmaster address from a raw SOA text record.

    dnspython returns SOA rdata as a space-separated string::

        ns1.example.com. hostmaster.example.com. 2024010101 3600 900 604800 300

    The second field is the mailbox in DNS dot-notation.  The **first
    unescaped dot** separates the local-part from the domain.  Escaped dots
    (``\\.``) inside the local-part represent literal dots in the final email.

    Examples::

        "hostmaster.example.com."   → "hostmaster@example.com"
        "john\\.doe.example.com."   → "john.doe@example.com"
    """
    parts = soa_text.split()
    if len(parts) < 2:
        return None
    raw = parts[1].rstrip(".")
    # Scan for the first *unescaped* dot — that is the local@domain boundary.
    # An escaped dot is the two-character sequence backslash+dot (r"\\.").
    i = 0
    while i < len(raw):
        if raw[i] == "\\" and i + 1 < len(raw) and raw[i + 1] == ".":
            i += 2  # skip over the escaped dot
            continue
        if raw[i] == ".":
            break   # found the unescaped boundary dot
        i += 1
    if i >= len(raw):
        return raw  # no domain part found; return as-is
    local  = raw[:i].replace("\\.", ".")   # unescape within local-part
    domain = raw[i + 1:]                   # everything after the boundary dot
    return f"{local}@{domain}"




def _check_cname_takeover(
    cname_target: str,
    asset: Asset,
    storage: ReconStorage,
) -> None:
    """Emit a Finding if the CNAME target looks like a dangling/takeover-prone service.

    This is a heuristic check only — manual verification is always required.
    """
    # Common services known for subdomain takeover vulnerability when the
    # linked account/project is deleted but the CNAME record remains.
    TAKEOVER_PRONE_PATTERNS: List[Tuple[re.Pattern[str], str]] = [
        (re.compile(r"\.github\.io$",          re.I), "GitHub Pages"),
        (re.compile(r"\.s3\.amazonaws\.com$",  re.I), "AWS S3"),
        (re.compile(r"\.s3-website",           re.I), "AWS S3 Website"),
        (re.compile(r"\.myshopify\.com$",      re.I), "Shopify"),
        (re.compile(r"\.azurewebsites\.net$",  re.I), "Azure Web Apps"),
        (re.compile(r"\.trafficmanager\.net$", re.I), "Azure Traffic Manager"),
        (re.compile(r"\.cloudapp\.azure\.com$",re.I), "Azure Cloud App"),
        (re.compile(r"\.heroku(app)?\.com$",   re.I), "Heroku"),
        (re.compile(r"\.netlify\.app$",        re.I), "Netlify"),
        (re.compile(r"\.vercel\.app$",         re.I), "Vercel"),
        (re.compile(r"\.ghost\.io$",           re.I), "Ghost"),
        (re.compile(r"\.surge\.sh$",           re.I), "Surge.sh"),
        (re.compile(r"\.readme\.io$",          re.I), "ReadMe"),
        (re.compile(r"\.zendesk\.com$",        re.I), "Zendesk"),
        (re.compile(r"\.statuspage\.io$",      re.I), "Atlassian Statuspage"),
        (re.compile(r"\.helpscoutdocs\.com$",  re.I), "HelpScout"),
        (re.compile(r"\.intercom\.help$",      re.I), "Intercom"),
        (re.compile(r"\.freshdesk\.com$",      re.I), "Freshdesk"),
        (re.compile(r"\.unbounce\.com$",       re.I), "Unbounce"),
        (re.compile(r"\.webflow\.io$",         re.I), "Webflow"),
    ]
    for pattern, service in TAKEOVER_PRONE_PATTERNS:
        if pattern.search(cname_target):
            storage.save_finding(Finding(
                asset=asset,
                category="dns/cname-takeover-candidate",
                severity=Severity.LOW,
                description=(
                    f"CNAME for {asset.domain!r} points to {service} "
                    f"({cname_target!r}). If the linked account/project no "
                    f"longer exists, this may be a subdomain takeover candidate."
                ),
                evidence=f"{asset.domain} CNAME → {cname_target}",
            ))
            logger.info(
                "[dns] Potential takeover candidate: %s → %s (%s)",
                asset.domain, cname_target, service,
            )
            break   # one Finding per CNAME is enough


# ---------------------------------------------------------------------------
# WHOIS / RDAP
# ---------------------------------------------------------------------------

def _safe_whois(domain: str) -> Optional[Dict[str, Any]]:
    """Run a WHOIS lookup and return the parsed data dict, or None on failure.

    python-whois can raise a variety of exceptions; all are caught here so
    a failing WHOIS lookup never crashes the pipeline.
    """
    try:
        data = whois.whois(domain)
        return dict(data) if data else None
    except Exception as exc:
        logger.warning("[whois] Lookup failed for %r: %s", domain, exc)
        return None


def _format_date(value: Any) -> str:
    """Stringify a date field that may be a list, datetime, or string."""
    if value is None:
        return "unknown"
    if isinstance(value, list):
        value = value[0]
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    return str(value)


def _enumerate_whois(asset: Asset, storage: ReconStorage) -> None:
    """Run WHOIS for *asset.domain* and persist a Finding with key fields.

    Fields captured (post-GDPR reality):
    - Registrar name
    - Domain creation, updated, expiry dates
    - Nameservers (registry view)
    - Registrant country and organisation (when not redacted)
    - DNSSEC status

    Parameters
    ----------
    asset : Asset
        The asset to look up.  Updated tech_stack entries for registrar /
        DNS provider are appended.
    storage : ReconStorage
        Open storage for writing the WHOIS Finding.
    """
    logger.info("[whois] Looking up: %s", asset.domain)
    data = _safe_whois(asset.domain)
    if data is None:
        logger.warning("[whois] No data returned for %r.", asset.domain)
        return

    # Extract surviving fields
    registrar      = data.get("registrar") or "unknown"
    creation_date  = _format_date(data.get("creation_date"))
    expiry_date    = _format_date(data.get("expiration_date"))
    updated_date   = _format_date(data.get("updated_date"))
    nameservers    = data.get("name_servers") or []
    registrant_org = data.get("org") or data.get("registrant_org") or "(redacted/unavailable)"
    registrant_country = data.get("country") or "(redacted/unavailable)"
    dnssec         = data.get("dnssec") or "unknown"

    # Normalise nameserver list
    if isinstance(nameservers, str):
        nameservers = [nameservers]
    nameservers = [ns.lower().rstrip(".") for ns in nameservers if ns]

    # Build evidence block
    evidence_lines = [
        f"Registrar:        {registrar}",
        f"Created:          {creation_date}",
        f"Updated:          {updated_date}",
        f"Expires:          {expiry_date}",
        f"Registrant org:   {registrant_org}",
        f"Registrant country: {registrant_country}",
        f"DNSSEC:           {dnssec}",
        f"Nameservers:      {', '.join(nameservers) or 'none'}",
    ]

    # Append registrar to tech_stack
    if registrar and registrar != "unknown":
        tag = f"registrar:{registrar}"
        if tag not in asset.tech_stack:
            asset.tech_stack.append(tag)
        storage.save_asset(asset)

    storage.save_finding(Finding(
        asset=asset,
        category="whois",
        severity=Severity.INFO,
        description=(
            f"WHOIS data for {asset.domain!r}: "
            f"registered with {registrar!r}, "
            f"created {creation_date}, "
            f"expires {expiry_date}."
        ),
        evidence="\n".join(evidence_lines),
    ))
    logger.info(
        "[whois] Saved: registrar=%r created=%s expires=%s",
        registrar, creation_date, expiry_date,
    )


# ---------------------------------------------------------------------------
# Public pipeline entry-point
# ---------------------------------------------------------------------------

async def run(
    assets: List[Asset],
    storage: ReconStorage,
    target: str,
) -> None:
    """Enumerate DNS records and WHOIS data for all known assets.

    Pipeline contract: async coroutine, registered with the ``passive`` phase.

    Workflow
    --------
    1. Build a shared dnspython Resolver.
    2. For the root target domain — if not already in assets — create and
       save a seed Asset.
    3. For every asset (root + all subdomains found by subdomain_enum):
       a. Query all standard DNS record types; persist per-type Findings.
       b. Classify TXT records for vendor disclosure; emit labelled Findings.
       c. Check CNAME targets for potential subdomain takeover (LOW severity).
    4. For the root target only, run WHOIS and persist a summary Finding.
    5. Run all DNS and WHOIS work in a thread pool (dnspython and python-whois
       are both synchronous libraries) so we do not block the event loop.

    Parameters
    ----------
    assets : List[Asset]
        Assets available at phase start (populated by subdomain_enum if run
        first; or an empty list if this is the first passive module).
    storage : ReconStorage
        Open storage instance.
    target : str
        Root domain under test (e.g. ``"example.com"``).
    """
    logger.info("whois_dns: starting for target=%r, %d known asset(s)", target, len(assets))

    loop = asyncio.get_event_loop()
    resolver = _make_resolver()

    # Ensure the root domain has an asset
    root_asset = next(
        (a for a in assets if a.domain.lower() == target.lower()), None
    )
    if root_asset is None:
        root_asset = Asset(domain=target, discovered_via="whois_dns/seed")
        storage.save_asset(root_asset)
        assets = [root_asset] + list(assets)

    # DNS enumeration runs for every known asset (root + subdomains)
    logger.info("whois_dns: querying DNS for %d asset(s).", len(assets))
    dns_tasks = [
        loop.run_in_executor(None, _enumerate_dns, resolver, asset, storage)
        for asset in assets
    ]
    await asyncio.gather(*dns_tasks)
    logger.info("whois_dns: DNS enumeration complete.")

    # WHOIS only for the root domain (avoid hammering registrar for every sub)
    logger.info("whois_dns: running WHOIS for root domain %r.", target)
    await loop.run_in_executor(None, _enumerate_whois, root_asset, storage)

    logger.info("whois_dns: complete.")
