"""
modules.passive.subdomain_enum
==============================
Passive subdomain enumeration via Certificate Transparency logs.

Technique background
--------------------
Every TLS certificate issued by a trusted CA must be submitted to at least
two public Certificate Transparency (CT) logs before browsers will honour it.
The certificate's Subject Alternative Name (SAN) field lists **all hostnames
the cert covers**, and those names are written verbatim into the CT log —
permanently, tamper-evidently, and world-readable.  This means:

  * Subdomains appear in CT logs even if they have no public DNS record.
  * Wildcard SANs (``*.internal.example.com``) reveal the domain structure.
  * Pre-certificate (PRECERT) entries are also logged, so certs that are
    revoked immediately still leave a permanent trail.
  * The leak is structural and unavoidable — it is a consequence of the
    RFC 9162 mandate, not a misconfiguration.

crt.sh
------
crt.sh (run by Sectigo) aggregates every major CT log shard in near-real
time and exposes a free JSON search API::

    GET https://crt.sh/?q=%.example.com&output=json

The ``%.`` prefix is a SQL ``LIKE``-style wildcard matching any subdomain.
Each result object contains a ``name_value`` field: a newline-separated
list of SANs, sometimes carrying multiple hostnames per certificate entry.

Fallback — HackerTarget Passive-DNS API
---------------------------------------
If crt.sh returns a 429 (rate-limited) or is unreachable, this module falls
back to the HackerTarget Passive-DNS host search::

    GET https://api.hackertarget.com/hostsearch/?q=example.com

HackerTarget returns plain-text ``hostname,ip`` pairs (free tier: ~100
results/day, no auth required).  It sources its data from passive DNS
sensors and independent crawl data rather than CT logs, so the two sources
are complementary and together improve recall.

Module interface
----------------
The public entry-point is the ``run()`` coroutine, which conforms to the
pipeline module contract::

    async def run(assets, storage, target) -> None
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from typing import List, Optional, Set, Tuple

import httpx

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# crt.sh JSON endpoint — %.domain expands to any subdomain depth
_CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"

# HackerTarget passive-DNS hostsearch — plain-text fallback
_HT_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

# HTTP client settings
_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=5.0, pool=5.0)
_HEADERS = {
    "User-Agent": "recon-mapper/0.1 (security research; authorised use only)",
    "Accept": "application/json, text/plain, */*",
}

# Regex: valid hostname label characters (RFC 1123)
_VALID_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)

# Wildcard prefix — crt.sh returns e.g. "*.example.com"; strip the "*." part
_WILDCARD_PREFIX_RE = re.compile(r"^\*\.")


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _is_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalise_hostname(raw: str) -> Optional[str]:
    """Strip wildcards, lowercase, and validate a candidate hostname.

    Parameters
    ----------
    raw : str
        A raw SAN entry, potentially containing wildcards, whitespace,
        or spurious characters.

    Returns
    -------
    Optional[str]
        A clean, lowercase FQDN, or ``None`` if the entry is invalid.
    """
    candidate = raw.strip().lower()

    # Remove wildcard prefix — "*.example.com" → "example.com"
    candidate = _WILDCARD_PREFIX_RE.sub("", candidate)

    # Discard IPs, empty strings, and syntactically invalid hostnames
    if not candidate or _is_ip(candidate):
        return None

    # Remove trailing dots (some CT tools emit "example.com.")
    candidate = candidate.rstrip(".")

    if not _VALID_HOSTNAME_RE.match(candidate):
        logger.debug("Discarding invalid hostname: %r", candidate)
        return None

    return candidate


def _is_in_scope(hostname: str, target: str) -> bool:
    """Return True if *hostname* is the target or a subdomain of it."""
    target_lower = target.lower().rstrip(".")
    hostname_lower = hostname.lower().rstrip(".")
    return hostname_lower == target_lower or hostname_lower.endswith("." + target_lower)


# ---------------------------------------------------------------------------
# crt.sh source
# ---------------------------------------------------------------------------

async def _fetch_crtsh(
    client: httpx.AsyncClient, domain: str
) -> Tuple[Set[str], bool]:
    """Query crt.sh and extract unique, normalised hostnames.

    Parameters
    ----------
    client : httpx.AsyncClient
        A shared async HTTP client.
    domain : str
        Root domain to query (e.g. ``"example.com"``).

    Returns
    -------
    Tuple[Set[str], bool]
        ``(hostnames, rate_limited)`` where ``rate_limited`` is ``True``
        when the response was HTTP 429 and the caller should switch to the
        fallback source.
    """
    url = _CRTSH_URL.format(domain=domain)
    logger.info("[crt.sh] Querying: %s", url)

    try:
        response = await client.get(url, timeout=_TIMEOUT)
    except httpx.TransportError as exc:
        logger.warning("[crt.sh] Network error: %s", exc)
        return set(), True  # treat transport failures like rate-limits → fallback

    if response.status_code == 429:
        logger.warning("[crt.sh] Rate-limited (HTTP 429). Switching to fallback.")
        return set(), True

    if response.status_code != 200:
        logger.warning("[crt.sh] Unexpected status %d.", response.status_code)
        return set(), False

    try:
        records = response.json()
    except Exception as exc:
        logger.error("[crt.sh] Failed to parse JSON: %s", exc)
        return set(), False

    if not isinstance(records, list):
        logger.warning("[crt.sh] Unexpected JSON shape (not a list).")
        return set(), False

    hostnames: Set[str] = set()
    for record in records:
        name_value = record.get("name_value", "")
        # name_value can be newline-separated when a cert covers multiple SANs
        for raw in name_value.split("\n"):
            normalised = _normalise_hostname(raw)
            if normalised and _is_in_scope(normalised, domain):
                hostnames.add(normalised)

    logger.info("[crt.sh] Extracted %d unique in-scope hostnames.", len(hostnames))
    return hostnames, False


# ---------------------------------------------------------------------------
# HackerTarget fallback source
# ---------------------------------------------------------------------------

async def _fetch_hackertarget(
    client: httpx.AsyncClient, domain: str
) -> Set[str]:
    """Query HackerTarget passive-DNS as a fallback source.

    The response format is plain-text, one ``hostname,ip`` pair per line::

        api.example.com,93.184.216.34
        mail.example.com,93.184.216.35

    Parameters
    ----------
    client : httpx.AsyncClient
        A shared async HTTP client.
    domain : str
        Root domain to query.

    Returns
    -------
    Set[str]
        Normalised hostnames discovered (IPs discarded from the result set).
    """
    url = _HT_URL.format(domain=domain)
    logger.info("[HackerTarget] Querying fallback: %s", url)

    try:
        response = await client.get(url, timeout=_TIMEOUT)
    except httpx.TransportError as exc:
        logger.warning("[HackerTarget] Network error: %s", exc)
        return set()

    if response.status_code != 200:
        logger.warning("[HackerTarget] Unexpected status %d.", response.status_code)
        return set()

    # Free-tier API error responses begin with "error" or "API count exceeded"
    text = response.text.strip()
    if text.lower().startswith(("error", "api count")):
        logger.warning("[HackerTarget] API limit reached: %r", text[:80])
        return set()

    hostnames: Set[str] = set()
    ip_map: dict[str, str] = {}

    for line in text.splitlines():
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        raw_host, raw_ip = parts[0].strip(), parts[1].strip()
        normalised = _normalise_hostname(raw_host)
        if normalised and _is_in_scope(normalised, domain):
            hostnames.add(normalised)
            if _is_ip(raw_ip):
                ip_map[normalised] = raw_ip

    logger.info(
        "[HackerTarget] Extracted %d unique in-scope hostnames.", len(hostnames)
    )
    return hostnames


# ---------------------------------------------------------------------------
# Asset builder
# ---------------------------------------------------------------------------

def _build_assets(
    hostnames: Set[str],
    existing_domains: Set[str],
    source_label: str,
) -> List[Asset]:
    """Convert a set of hostname strings into new Asset objects.

    Already-known domains (present in *existing_domains*) are skipped to
    avoid creating duplicate assets.

    Parameters
    ----------
    hostnames : Set[str]
        Normalised, in-scope hostnames to convert.
    existing_domains : Set[str]
        Domains already present in storage; used for deduplication.
    source_label : str
        Human-readable label for ``Asset.discovered_via``
        (e.g. ``"cert_ct/crt.sh"``).

    Returns
    -------
    List[Asset]
        New Asset objects (not yet persisted).
    """
    new_assets: List[Asset] = []
    for hostname in sorted(hostnames):
        if hostname in existing_domains:
            logger.debug("Skipping known domain: %s", hostname)
            continue
        new_assets.append(Asset(domain=hostname, discovered_via=source_label))
    return new_assets


# ---------------------------------------------------------------------------
# Public pipeline entry-point
# ---------------------------------------------------------------------------

async def run(
    assets: List[Asset],
    storage: ReconStorage,
    target: str,
) -> None:
    """Enumerate subdomains via CT logs (crt.sh) with HackerTarget fallback.

    This function conforms to the pipeline module contract and is registered
    with the ``passive`` phase.

    Workflow
    --------
    1. Collect the set of domains already in storage to enable deduplication.
    2. Query crt.sh JSON API for the target domain.
    3. If crt.sh is rate-limited or unreachable, query HackerTarget passive-DNS.
    4. Normalise and deduplicate all discovered hostnames.
    5. Persist each new hostname as an ``Asset``.
    6. Persist a single summary ``Finding`` with discovery metadata.

    Parameters
    ----------
    assets : List[Asset]
        Assets already known to the pipeline (from storage at phase start).
    storage : ReconStorage
        Open storage instance for reading and writing.
    target : str
        Root domain under test (e.g. ``"example.com"``).
    """
    logger.info("subdomain_enum: starting for target=%r", target)

    # ── Build existing-domain index for O(1) dedup ─────────────────────────
    existing_domains: Set[str] = {a.domain.lower() for a in assets}

    # ── HTTP client (shared across both sources) ────────────────────────────
    async with httpx.AsyncClient(headers=_HEADERS, follow_redirects=True) as client:

        # ── Primary source: crt.sh ──────────────────────────────────────────
        hostnames, rate_limited = await _fetch_crtsh(client, target)
        source_label = "cert_ct/crt.sh"

        # ── Fallback: HackerTarget passive-DNS ─────────────────────────────
        if rate_limited:
            logger.info("subdomain_enum: using HackerTarget as fallback source.")
            ht_hostnames = await _fetch_hackertarget(client, target)
            hostnames = hostnames | ht_hostnames  # merge (may be empty from crt.sh)
            source_label = "cert_ct/hackertarget-fallback"

    # Also try HackerTarget as a *complement* when crt.sh succeeds,
    # if you want maximum coverage — disabled by default to stay polite.
    # Uncomment the block below to enable dual-source mode:
    #
    # if not rate_limited:
    #     async with httpx.AsyncClient(headers=_HEADERS) as client2:
    #         ht_hostnames = await _fetch_hackertarget(client2, target)
    #     hostnames |= ht_hostnames

    # ── Convert to Asset objects ────────────────────────────────────────────
    new_assets = _build_assets(hostnames, existing_domains, source_label)

    if not new_assets and not hostnames:
        logger.warning(
            "subdomain_enum: no subdomains discovered for %r. "
            "Check network connectivity or try --log-level DEBUG.",
            target,
        )
        return

    # ── Persist new assets ──────────────────────────────────────────────────
    for asset in new_assets:
        storage.save_asset(asset)
        logger.debug("Saved: %s (via %s)", asset.domain, asset.discovered_via)

    logger.info(
        "subdomain_enum: %d new asset(s) saved (%d total discovered, %d already known).",
        len(new_assets),
        len(hostnames),
        len(hostnames) - len(new_assets),
    )

    # ── Persist a summary Finding on the root target asset ─────────────────
    # Find or create an Asset for the root target itself.
    root_asset = next(
        (a for a in assets if a.domain.lower() == target.lower()), None
    )
    if root_asset is None:
        root_asset = next(
            (a for a in new_assets if a.domain.lower() == target.lower()), None
        )
    if root_asset is None:
        stored = storage.get_assets()
        root_asset = next(
            (a for a in stored if a.domain.lower() == target.lower()), None
        )
    if root_asset is None:
        root_asset = Asset(domain=target, discovered_via="subdomain_enum/seed")
        storage.save_asset(root_asset)

    summary_finding = Finding(
        asset=root_asset,
        category="subdomain-enum",
        severity=Severity.INFO,
        description=(
            f"CT log enumeration discovered {len(hostnames)} unique subdomain(s) "
            f"for {target!r} via {source_label}. "
            f"{len(new_assets)} new asset(s) added to storage."
        ),
        evidence="\n".join(sorted(hostnames)) if hostnames else "(none)",
    )
    storage.save_finding(summary_finding)
    logger.info("subdomain_enum: summary finding saved.")
