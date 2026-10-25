"""
tests.active.test_service_fingerprint
=====================================
Unit and integration tests for modules.active.service_fingerprint.

All tests operate strictly against local asyncio servers bound to 127.0.0.1:0.
Zero real network traffic is generated.

Test Cases:
  (1) Unsolicited banner grabbing (SSH greeting).
  (2) Solicited banner grabbing with HTTP probe (nginx / PHP headers).
  (3) Technology extraction regex and version normalization.
  (4) TLS certificate inspection on local SSL server (issuer, expiry, SAN list, protocol, cipher).
  (5) Expired TLS certificate detection and Severity.HIGH finding rating.
  (6) Asset tech stack enrichment and Finding persistence in ReconStorage.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
import ssl
import tempfile
from typing import AsyncGenerator, Dict, Tuple

import pytest

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage
from modules.active.service_fingerprint import (
    create_banner_finding,
    create_tls_finding,
    extract_technologies,
    fingerprint_asset,
    grab_banner,
    grab_tls_details,
    run as service_fingerprint_run,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_cert_bundle() -> Tuple[str, str]:
    """Generate a temporary self-signed TLS cert and private key with SANs."""
    tmpdir = tempfile.mkdtemp()
    cert_path = os.path.join(tmpdir, "cert.pem")
    key_path = os.path.join(tmpdir, "key.pem")

    os.system(
        f'openssl req -x509 -newkey rsa:2048 -keyout {key_path} -out {cert_path} '
        f'-days 30 -nodes -subj "/CN=test.local/O=TestCorp" '
        f'-addext "subjectAltName = DNS:test.local,DNS:api.test.local,IP:127.0.0.1" 2>/dev/null'
    )
    return cert_path, key_path


@pytest.fixture
async def tls_server(temp_cert_bundle: Tuple[str, str]) -> AsyncGenerator[Tuple[asyncio.Server, int], None]:
    """Spin up a local asyncio SSL server on an ephemeral port (127.0.0.1:0)."""
    cert_path, key_path = temp_cert_bundle
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert_path, key_path)

    async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(_handle_client, "127.0.0.1", 0, ssl=server_ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        yield server, port
    finally:
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

async def test_grab_banner_unsolicited_ssh() -> None:
    """Test capturing an unsolicited banner sent immediately on connection (e.g. SSH)."""
    ssh_banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    async def _handle_ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(ssh_banner)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_handle_ssh, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        captured = await grab_banner("127.0.0.1", port, timeout=1.0)
        assert captured is not None
        assert "OpenSSH_8.9p1" in captured

        techs = extract_technologies(captured, port)
        assert "OpenSSH/8.9p1" in techs


async def test_grab_banner_solicited_http() -> None:
    """Test capturing a solicited banner via HTTP HEAD stimulus probe."""
    http_response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0 (Ubuntu)\r\n"
        b"X-Powered-By: PHP/8.2.1\r\n"
        b"Content-Type: text/html\r\n\r\n"
    )

    async def _handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Wait for client probe
        req = await reader.read(256)
        if req:
            writer.write(http_response)
            await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(_handle_http, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    async with server:
        captured = await grab_banner("127.0.0.1", port, timeout=1.0)
        assert captured is not None
        assert "nginx/1.24.0" in captured

        techs = extract_technologies(captured, port)
        assert "nginx/1.24.0" in techs
        assert "PHP/8.2.1" in techs


def test_extract_technologies_regex() -> None:
    """Test technology extraction from various daemon banners."""
    # FTP
    ftp_banner = "220 (vsFTPd 3.0.3)\r\n"
    assert extract_technologies(ftp_banner, 21) == ["vsFTPd"]

    # SMTP
    smtp_banner = "220 mail.example.com ESMTP Postfix (Ubuntu)\r\n"
    assert extract_technologies(smtp_banner, 25) == ["Postfix"]


async def test_grab_tls_details_valid(tls_server: Tuple[asyncio.Server, int]) -> None:
    """Test pulling TLS certificate details from a local SSL server."""
    server, port = tls_server

    tls_info = await grab_tls_details("127.0.0.1", port=port, timeout=1.5)
    assert tls_info is not None

    # Protocol and cipher
    assert tls_info["protocol_version"] in ["TLSv1.2", "TLSv1.3"]
    assert len(tls_info["cipher_suite"]) > 0
    assert tls_info["cipher_bits"] > 0

    # Issuer & Subject
    assert "TestCorp" in tls_info["issuer"]
    assert "test.local" in tls_info["subject"]

    # SANs
    sans = tls_info["sans"]
    assert "test.local" in sans
    assert "api.test.local" in sans
    assert "127.0.0.1" in sans

    # Expiry
    assert tls_info["is_expired"] is False
    assert tls_info["days_until_expiry"] is not None
    assert tls_info["days_until_expiry"] > 20


def test_create_tls_finding_expired_severity() -> None:
    """Verify expired TLS certificate triggers a Severity.HIGH Finding."""
    asset = Asset(domain="example.com", ip="93.184.216.34")
    now = datetime.now(timezone.utc)
    expired_info: Dict = {
        "host": "example.com",
        "port": 443,
        "protocol_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "issuer": "Let's Encrypt",
        "subject": "CN=example.com",
        "not_before": now - timedelta(days=120),
        "not_after": now - timedelta(days=10),
        "is_expired": True,
        "days_until_expiry": -10,
        "sans": ["example.com"],
        "is_self_signed": False,
    }

    finding = create_tls_finding(asset, expired_info)
    assert finding.severity == Severity.HIGH
    assert "EXPIRED" in finding.evidence
    assert finding.category == "tls"


def test_create_tls_finding_weak_protocol_severity() -> None:
    """Verify deprecated TLS 1.0/1.1 protocol triggers a Severity.MEDIUM Finding."""
    asset = Asset(domain="example.com", ip="93.184.216.34")
    now = datetime.now(timezone.utc)
    weak_proto_info: Dict = {
        "host": "example.com",
        "port": 443,
        "protocol_version": "TLSv1.0",
        "cipher_suite": "ECDHE-RSA-AES128-SHA",
        "cipher_bits": 128,
        "issuer": "DigiCert",
        "subject": "CN=example.com",
        "not_before": now - timedelta(days=30),
        "not_after": now + timedelta(days=180),
        "is_expired": False,
        "days_until_expiry": 180,
        "sans": ["example.com"],
        "is_self_signed": False,
    }

    finding = create_tls_finding(asset, weak_proto_info)
    assert finding.severity == Severity.MEDIUM
    assert "DEPRECATED PROTOCOL" in finding.evidence


async def test_fingerprint_asset_end_to_end(tls_server: Tuple[asyncio.Server, int]) -> None:
    """Test full fingerprint_asset flow: banner grab + TLS cert inspection."""
    _, tls_port = tls_server

    # Set up HTTP server on port 0
    http_resp = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\n\r\n"
    async def _handle_http(r, w):
        await r.read(128)
        w.write(http_resp)
        await w.drain()
        w.close()
        await w.wait_closed()

    http_server = await asyncio.start_server(_handle_http, "127.0.0.1", 0)
    http_port = http_server.sockets[0].getsockname()[1]

    async with http_server:
        asset = Asset(domain="127.0.0.1", ip="127.0.0.1", ports=[http_port, tls_port])

        findings = await fingerprint_asset(asset, timeout=1.0, tls_ports=[tls_port])

        # Assert tech stack enriched
        assert "Apache/2.4.52" in asset.tech_stack

        # Assert findings created
        assert len(findings) >= 2
        categories = {f.category for f in findings}
        assert "service-fingerprint" in categories
        assert "tls" in categories


async def test_service_fingerprint_pipeline_run(
    storage: ReconStorage, tls_server: Tuple[asyncio.Server, int]
) -> None:
    """Test service_fingerprint run() pipeline integration with storage."""
    _, tls_port = tls_server

    asset = Asset(domain="127.0.0.1", ip="127.0.0.1", ports=[tls_port], discovered_via="port_scan")
    storage.save_asset(asset)

    await service_fingerprint_run(
        assets=[asset],
        storage=storage,
        target="127.0.0.1",
        timeout=1.0,
        tls_ports=[tls_port],
    )

    # Verify findings were saved to storage
    stored_findings = storage.get_findings(asset=asset)
    assert len(stored_findings) >= 1
    tls_findings = [f for f in stored_findings if f.category == "tls"]
    assert len(tls_findings) == 1
    assert "TestCorp" in tls_findings[0].evidence
