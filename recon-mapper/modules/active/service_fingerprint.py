"""
modules.active.service_fingerprint
=================================
Service banner grabbing, technology fingerprinting, and TLS certificate inspection.

Technique background
--------------------

How Banner Grabbing Works
~~~~~~~~~~~~~~~~~~~~~~~~~
A service banner is a textual announcement transmitted by a listening network
daemon when a client initiates a connection. Banner grabbing inspects this
response to determine the exact software name, version, architecture, and
underlying operating system.

Two interaction patterns exist:

1. Unsolicited (Passive) Banners:
   - Certain protocols announce their software and version immediately upon
     TCP connection establishment without waiting for client input.
   - Prominent examples:
     * SSH: ``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6``
     * FTP: ``220 (vsFTPd 3.0.3)`` or ``220 ProFTPD 1.3.5 Server``
     * SMTP: ``220 mail.example.com ESMTP Postfix (Ubuntu)``
     * MySQL/MariaDB: Protocol handshake packet containing server version
   - The scanner connects, listens for a short window (e.g. 1.0s), and captures
     the greeting.

2. Solicited (Active Probe) Banners:
   - Many services wait silently for client input (e.g., HTTP, Redis, TLS).
   - If no initial greeting is received, the scanner transmits a benign,
     protocol-appropriate stimulus:
     * HTTP/HTTPS (ports 80, 443, 8080, 8443, etc.):
       Sends ``HEAD / HTTP/1.1\r\nHost: <host>\r\nConnection: close\r\n\r\n``
       The target responds with HTTP response headers:
       ``Server: nginx/1.24.0``
       ``X-Powered-By: PHP/8.2.1``
     * Redis (port 6379): Sends ``PING\r\n``; server responds ``+PONG`` or ``-NOAUTH``.
     * Generic services: Sends a newline ``\r\n`` probe to elicit error messages
       such as "500 Syntax error" or daemon identification.

What a TLS Certificate's SAN, Issuer, and Expiry Reveal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When establishing a TLS session on HTTPS services (ports 443, 8443, etc.),
the X.509 server certificate exposes critical reconnaissance metadata:

1. Subject Alternative Names (SAN):
   - In modern PKI (RFC 5280), the Common Name (CN) is deprecated in favor of
     the SAN extension. The SAN field lists **every hostname, domain, and IP**
     for which the certificate is valid.
   - Attack Surface Expansion: Multi-domain certs frequently bundle internal
     hostnames, staging servers, and administrative panels that lack public DNS
     pointers (e.g., ``vpn.example.com``, ``admin.staging.example.com``,
     ``api-internal.example.com``).
   - Wildcards: ``*.prod.example.com`` confirms organizational naming schemes.

2. Issuer (Certificate Authority - CA):
   - Identifies the signing entity.
   - CDN / Cloud Proxy Detection: An issuer of "Cloudflare Inc" or "Amazon"
     indicates an edge reverse proxy rather than the origin server.
   - Enterprise Internal PKI: An issuer like ``CN=Corp-Root-CA`` or ``O=Acme Internal``
     indicates an internal corporate system unintentionally exposed to the public.
   - Self-Signed Certificates (``Issuer == Subject``): Often indicates test systems,
     embedded hardware, or shadow IT lacking formal certificate lifecycle controls.

3. Validity & Expiry (``notBefore`` / ``notAfter``):
   - Expired Certificates: Points to abandoned, unmaintained, or decommissioned
     infrastructure. These "zombie" servers are prime candidates for unpatched
     vulnerabilities.
   - Certificates expiring in < 30 days highlight operational neglect.
   - Issue dates reveal when infrastructure was provisioned or updated.

4. Protocol Version & Cipher Suite:
   - Deprecated protocols (TLS 1.0, TLS 1.1, SSLv3) represent cryptographic
     weaknesses susceptible to BEAST, POODLE, and downgrade attacks.
   - Modern deployments enforce TLS 1.2 or TLS 1.3 with AEAD cipher suites.

Why Version Strings in Banners Matter for CVE Matching
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Accurate version extraction is the prerequisite for automated vulnerability mapping:

1. CPE (Common Platform Enumeration) Synthesis:
   - Scanners normalize version strings into standardized CPE identifiers, e.g.:
     ``Apache/2.4.49`` → ``cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*``
     ``OpenSSH_7.4p1`` → ``cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*``

2. NVD / CVE Correlation:
   - National Vulnerability Database (NVD) entries, GitHub Advisory Database,
     and vendor security bulletins index CVEs by vulnerable version ranges.
   - Knowing the exact version immediately surfaces known critical CVEs:
     * ``Apache/2.4.49`` → CVE-2021-41773 (Path traversal & Remote Code Execution)
     * ``OpenSSH_7.4`` → CVE-2018-15473 (User enumeration)
     * ``nginx/1.18.0`` → Informs patch level analysis and OS release cadence.

3. Attack Surface Categorization:
   - Differentiates legacy, high-risk systems from actively maintained services.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import re
import socket
import ssl
import tempfile
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT: float = 2.5
DEFAULT_CONCURRENCY: int = 10
DEFAULT_TLS_PORTS: frozenset[int] = frozenset({443, 8443})

# Regex patterns for technology and version detection from banners
_SERVER_HEADER_RE = re.compile(r"^server:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_POWERED_BY_RE = re.compile(r"^x-powered-by:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_SSH_VERSION_RE = re.compile(r"^(SSH-\d+\.\d+-[^\r\n]+)", re.MULTILINE)
_FTP_BANNER_RE = re.compile(r"^220[- ](?:.*?\b)?(vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|Microsoft FTP Service)[^\r\n]*", re.IGNORECASE | re.MULTILINE)
_SMTP_BANNER_RE = re.compile(r"^220[- ](?:.*?\b)?(Postfix|Exim|Sendmail|Microsoft ESMTP)[^\r\n]*", re.IGNORECASE | re.MULTILINE)

# Weak/deprecated TLS protocol versions
_WEAK_TLS_VERSIONS: frozenset[str] = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})


# ---------------------------------------------------------------------------
# Banner Grabbing
# ---------------------------------------------------------------------------

async def grab_banner(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> Optional[str]:
    """Attempt to capture a service banner from host:port.

    First listens briefly for unsolicited banners (SSH, FTP, SMTP, MySQL).
    If no response is received, sends a benign protocol-appropriate probe (HTTP HEAD
    for web ports, newline for others) and reads the reply.

    Returns the cleaned banner string, or None if no response was elicited.
    """
    reader = None
    writer = None
    banner_raw = b""

    try:
        connect_coro = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)

        # 1. Check for unsolicited banner (listen for up to 0.8s)
        try:
            banner_raw = await asyncio.wait_for(reader.read(1024), timeout=min(0.8, timeout))
        except (asyncio.TimeoutError, TimeoutError):
            banner_raw = b""

        # 2. If no unsolicited banner received, send a polite stimulus probe
        if not banner_raw:
            if port in {80, 8080, 8000, 8888, 3000, 5000, 8081, 8008, 443, 8443}:
                # HTTP probe
                probe = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: recon-mapper/0.1\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode("ascii", errors="replace")
            elif port == 6379:
                # Redis ping
                probe = b"PING\r\n"
            else:
                # Generic newline stimulus
                probe = b"\r\n\r\n"

            writer.write(probe)
            await writer.drain()

            try:
                banner_raw = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            except (asyncio.TimeoutError, TimeoutError):
                pass

    except (asyncio.TimeoutError, TimeoutError, ConnectionRefusedError, OSError) as exc:
        logger.debug("Banner grab failed for %s:%d: %s", host, port, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected error grabbing banner from %s:%d: %s", host, port, exc)
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    if not banner_raw:
        return None

    # Sanitize: convert bytes to printable string, stripping null bytes and control chars
    return _sanitize_banner(banner_raw)


def _sanitize_banner(raw_bytes: bytes) -> Optional[str]:
    """Clean raw banner bytes into a readable, printable ASCII/UTF-8 string."""
    text = raw_bytes.decode("utf-8", errors="replace")
    # Clean binary junk while preserving standard whitespace
    cleaned = "".join(ch for ch in text if ch.isprintable() or ch in "\r\n\t")
    cleaned = cleaned.strip()
    return cleaned if cleaned else None


# ---------------------------------------------------------------------------
# Technology & Version Extraction
# ---------------------------------------------------------------------------

def extract_technologies(banner: str, port: int) -> List[str]:
    """Parse software and version strings from a banner.

    Returns a list of technology tags (e.g. ["nginx/1.24.0", "OpenSSH/8.9p1"]).
    """
    technologies: Set[str] = set()

    # HTTP Server Header
    server_match = _SERVER_HEADER_RE.search(banner)
    if server_match:
        server_val = server_match.group(1).strip()
        for token in server_val.split():
            if "/" in token:
                technologies.add(token)
            elif token:
                technologies.add(token)

    # HTTP X-Powered-By Header
    powered_match = _POWERED_BY_RE.search(banner)
    if powered_match:
        powered_val = powered_match.group(1).strip()
        for token in powered_val.split():
            technologies.add(token)

    # SSH identification string (RFC 4253)
    ssh_match = _SSH_VERSION_RE.search(banner)
    if ssh_match:
        ssh_line = ssh_match.group(1).strip()
        parts = ssh_line.split("-", 2)
        if len(parts) >= 3:
            tokens = parts[2].split()
            technologies.add(tokens[0].replace("_", "/"))
        else:
            technologies.add(ssh_line)

    # FTP greeting
    ftp_match = _FTP_BANNER_RE.search(banner)
    if ftp_match:
        technologies.add(ftp_match.group(1))

    # SMTP greeting
    smtp_match = _SMTP_BANNER_RE.search(banner)
    if smtp_match:
        technologies.add(smtp_match.group(1))

    return sorted(list(technologies))


# ---------------------------------------------------------------------------
# TLS Certificate Inspection
# ---------------------------------------------------------------------------

def _parse_rdn_tuple(rdn_tuple: Any) -> str:
    """Format an X.509 RDN tuple into a human-readable string like 'CN=example.com, O=Corp'."""
    if not rdn_tuple:
        return "Unknown"
    parts = []
    for group in rdn_tuple:
        for k, v in group:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _parse_x509_der(der_bytes: bytes) -> Dict[str, Any]:
    """Parse DER-encoded X.509 certificate bytes into structured fields.

    Attempts to use ``cryptography`` if installed; otherwise falls back to Python's
    built-in standard library SSL decoder.
    """
    try:
        import cryptography.x509
        cert = cryptography.x509.load_der_x509_certificate(der_bytes)
        
        # Issuer & Subject
        issuer_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert.issuer)
        subject_str = ", ".join(f"{attr.oid._name}={attr.value}" for attr in cert.subject)

        # Validity dates
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:
            not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

        # Subject Alternative Names (SANs)
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                sans.append(str(name.value))
        except Exception:
            pass

        return {
            "issuer": issuer_str or "Unknown",
            "subject": subject_str or "Unknown",
            "not_before": not_before,
            "not_after": not_after,
            "sans": sorted(list(set(sans))),
            "is_self_signed": cert.issuer == cert.subject,
        }

    except ImportError:
        # Fallback: standard library OpenSSL PEM decoder
        pem_str = ssl.DER_cert_to_PEM_cert(der_bytes)
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as tmp:
            tmp.write(pem_str)
            tmp_name = tmp.name

        try:
            if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
                raw_dict = ssl._ssl._test_decode_cert(tmp_name)
            else:
                raw_dict = {}
        finally:
            import os
            if os.path.exists(tmp_name):
                os.remove(tmp_name)

        # Parse validity date string: "Nov 24 15:59:15 2026 GMT"
        not_after_str = raw_dict.get("notAfter", "")
        not_after = None
        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            except Exception:
                pass

        not_before_str = raw_dict.get("notBefore", "")
        not_before = None
        if not_before_str:
            try:
                not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
            except Exception:
                pass

        # Extract SAN list
        sans = []
        for item in raw_dict.get("subjectAltName", ()):
            if len(item) == 2:
                sans.append(item[1])

        issuer_str = _parse_rdn_tuple(raw_dict.get("issuer"))
        subject_str = _parse_rdn_tuple(raw_dict.get("subject"))

        return {
            "issuer": issuer_str,
            "subject": subject_str,
            "not_before": not_before,
            "not_after": not_after,
            "sans": sorted(list(set(sans))),
            "is_self_signed": issuer_str == subject_str and issuer_str != "Unknown",
        }


async def grab_tls_details(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> Optional[Dict[str, Any]]:
    """Establish a TLS handshake with host:port and extract certificate details.

    Retrieves:
      - protocol_version (e.g. 'TLSv1.3', 'TLSv1.2')
      - cipher_suite (e.g. 'TLS_AES_256_GCM_SHA384')
      - cipher_bits (e.g. 256)
      - issuer
      - subject
      - not_before, not_after (UTC datetime)
      - is_expired (boolean)
      - days_until_expiry (int)
      - sans (List of Subject Alternative Names)
      - is_self_signed (boolean)

    Uses ``verify_mode=CERT_NONE`` so self-signed, untrusted, or expired
    certificates are successfully inspected for security reporting.
    """
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    writer = None
    try:
        # SNI: use hostname if it is a domain, omit if raw IP
        server_hostname = None
        try:
            socket.inet_aton(host)
        except OSError:
            server_hostname = host

        connect_coro = asyncio.open_connection(
            host, port, ssl=ssl_ctx, server_hostname=server_hostname
        )
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            return None

        cipher_info = ssl_obj.cipher() or ("Unknown", "Unknown", 0)
        protocol_version = ssl_obj.version() or cipher_info[1]
        cipher_name = cipher_info[0]
        cipher_bits = cipher_info[2]

        der_bytes = ssl_obj.getpeercert(binary_form=True)
        if not der_bytes:
            return None

        cert_data = _parse_x509_der(der_bytes)
        now_utc = datetime.now(timezone.utc)

        is_expired = False
        days_until_expiry = None
        if cert_data.get("not_after"):
            not_after = cert_data["not_after"]
            is_expired = now_utc > not_after
            days_until_expiry = (not_after - now_utc).days

        return {
            "host": host,
            "port": port,
            "protocol_version": protocol_version,
            "cipher_suite": cipher_name,
            "cipher_bits": cipher_bits,
            "issuer": cert_data.get("issuer", "Unknown"),
            "subject": cert_data.get("subject", "Unknown"),
            "not_before": cert_data.get("not_before"),
            "not_after": cert_data.get("not_after"),
            "is_expired": is_expired,
            "days_until_expiry": days_until_expiry,
            "sans": cert_data.get("sans", []),
            "is_self_signed": cert_data.get("is_self_signed", False),
        }

    except (asyncio.TimeoutError, TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError) as exc:
        logger.debug("TLS handshake failed for %s:%d: %s", host, port, exc)
        return None
    except Exception as exc:
        logger.debug("Unexpected error during TLS check on %s:%d: %s", host, port, exc)
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Finding Constructors
# ---------------------------------------------------------------------------

def create_banner_finding(asset: Asset, port: int, banner: str, detected_tech: List[str]) -> Finding:
    """Construct a Finding for a captured service banner."""
    tech_summary = f" (Identified: {', '.join(detected_tech)})" if detected_tech else ""
    first_line = banner.splitlines()[0] if banner else ""
    short_banner = (first_line[:90] + "...") if len(first_line) > 90 else first_line

    return Finding(
        asset=asset,
        category="service-fingerprint",
        severity=Severity.INFO,
        description=f"Service banner captured on {asset.domain}:{port}{tech_summary}: {short_banner}",
        evidence=(
            f"Host:       {asset.domain} ({asset.ip or 'unresolved'})\n"
            f"Port:       {port}/TCP\n"
            f"Detected:   {', '.join(detected_tech) if detected_tech else '(generic)'}\n"
            f"Raw Banner:\n{banner}"
        ),
    )


def create_tls_finding(asset: Asset, tls_info: Dict[str, Any]) -> Finding:
    """Construct a Finding for TLS certificate audit details with contextual severity."""
    port = tls_info["port"]
    proto = tls_info["protocol_version"]
    cipher = tls_info["cipher_suite"]
    issuer = tls_info["issuer"]
    subject = tls_info["subject"]
    is_expired = tls_info["is_expired"]
    days_left = tls_info["days_until_expiry"]
    sans = tls_info["sans"]
    is_self_signed = tls_info["is_self_signed"]

    # Severity determination
    if is_expired:
        severity = Severity.HIGH
        status_note = f"EXPIRED (expired {abs(days_left) if days_left is not None else '?'} days ago)"
    elif days_left is not None and days_left <= 30:
        severity = Severity.MEDIUM
        status_note = f"EXPIRING SOON ({days_left} days remaining)"
    elif proto in _WEAK_TLS_VERSIONS:
        severity = Severity.MEDIUM
        status_note = f"DEPRECATED PROTOCOL ({proto})"
    elif is_self_signed and not asset.domain.endswith(".local") and asset.domain != "127.0.0.1":
        severity = Severity.LOW
        status_note = "SELF-SIGNED CERTIFICATE"
    else:
        severity = Severity.INFO
        status_note = "VALID"

    evidence_lines = [
        f"Host:           {asset.domain} ({asset.ip or 'unresolved'})",
        f"Port:           {port}/TCP",
        f"Protocol:       {proto}",
        f"Cipher Suite:   {cipher} ({tls_info['cipher_bits']} bits)",
        f"Subject:        {subject}",
        f"Issuer:         {issuer}",
        f"Valid From:     {tls_info['not_before'] or 'Unknown'}",
        f"Valid Until:    {tls_info['not_after'] or 'Unknown'}",
        f"Days Remaining: {days_left if days_left is not None else 'Unknown'}",
        f"Self-Signed:    {is_self_signed}",
        f"Audit Status:   {status_note}",
        f"SAN Count:      {len(sans)}",
        "Subject Alternative Names (SANs):",
    ]
    for san in sans:
        evidence_lines.append(f"  - {san}")

    description = (
        f"TLS service on {asset.domain}:{port} [{proto} / {cipher}]: "
        f"Cert for {subject} issued by {issuer} ({status_note})"
    )

    return Finding(
        asset=asset,
        category="tls",
        severity=severity,
        description=description,
        evidence="\n".join(evidence_lines),
    )


# ---------------------------------------------------------------------------
# Per-Asset Service Fingerprinter
# ---------------------------------------------------------------------------

async def fingerprint_asset(
    asset: Asset,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    tls_ports: Optional[Iterable[int]] = None,
) -> List[Finding]:
    """Inspect all open ports on an Asset, grabbing banners and TLS certificate details.

    Parameters
    ----------
    asset : Asset
        Target asset with populated ``asset.ports``.
    timeout : float
        Per-connection timeout in seconds.
    concurrency : int
        Maximum concurrent probes against the asset.
    tls_ports : Optional[Iterable[int]]
        Port numbers to inspect for TLS certificates (defaults to 443, 8443).

    Returns
    -------
    List[Finding]
        Generated banner and TLS findings.
    """
    if not asset.ports:
        logger.debug("No open ports recorded for %s; skipping service fingerprinting.", asset.domain)
        return []

    target_host = asset.ip or asset.domain
    tls_port_set = frozenset(tls_ports) if tls_ports is not None else DEFAULT_TLS_PORTS
    semaphore = asyncio.Semaphore(max(1, concurrency))

    findings: List[Finding] = []
    discovered_techs: Set[str] = set()

    async def _probe_port(port: int) -> None:
        async with semaphore:
            # 1. Banner Grab
            banner = await grab_banner(target_host, port, timeout=timeout)
            if banner:
                techs = extract_technologies(banner, port)
                if techs:
                    discovered_techs.update(techs)
                finding = create_banner_finding(asset, port, banner, techs)
                findings.append(finding)

            # 2. TLS Certificate Inspection (for 443, 8443 or specified TLS ports)
            if port in tls_port_set:
                tls_info = await grab_tls_details(target_host, port, timeout=timeout)
                if tls_info:
                    tls_finding = create_tls_finding(asset, tls_info)
                    findings.append(tls_finding)

    tasks = [_probe_port(p) for p in asset.ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Enrich Asset tech stack with detected software
    if discovered_techs:
        merged_stack = sorted(list(set(asset.tech_stack) | discovered_techs))
        asset.tech_stack = merged_stack
        logger.info(
            "Enriched %s tech stack: %s",
            asset.domain,
            ", ".join(discovered_techs),
        )

    return findings


# ---------------------------------------------------------------------------
# Pipeline Module Entrypoint
# ---------------------------------------------------------------------------

async def run(
    assets: List[Asset],
    storage: ReconStorage,
    target: str,
    timeout: float = DEFAULT_TIMEOUT,
    concurrency: int = DEFAULT_CONCURRENCY,
    tls_ports: Optional[Iterable[int]] = None,
) -> None:
    """Active service fingerprinting pipeline module conforming to the Pipeline contract.

    Iterates over target assets, attempts banner grabs on all open ports, pulls TLS
    certificate details for HTTPS/TLS ports (443/8443), enriches ``Asset.tech_stack``,
    and persists all findings to storage.
    """
    logger.info("Starting service fingerprinting phase for target: %r", target)

    target_assets = list(assets)
    if not target_assets:
        target_assets = storage.get_assets()

    if not target_assets:
        logger.info("No assets available for service fingerprinting.")
        return

    total_findings = 0
    scanned_assets = 0

    for asset in target_assets:
        if not asset.ports:
            continue

        try:
            findings = await fingerprint_asset(
                asset=asset,
                timeout=timeout,
                concurrency=concurrency,
                tls_ports=tls_ports,
            )
            scanned_assets += 1
            total_findings += len(findings)

            # Persist enriched asset
            storage.save_asset(asset)

            # Persist findings
            for finding in findings:
                storage.save_finding(finding)

        except Exception:
            logger.exception("Error fingerprinting services on asset %s", asset.domain)

    logger.info(
        "Service fingerprinting complete. Scanned %d asset(s), recorded %d finding(s).",
        scanned_assets,
        total_findings,
    )
