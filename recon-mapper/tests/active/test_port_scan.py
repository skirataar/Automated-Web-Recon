"""
tests.active.test_port_scan
===========================
Unit and integration tests for modules.active.port_scan.

Tests do NOT hit the real network. All interactions use local asyncio TCP servers
bound to 127.0.0.1 on OS-assigned ephemeral free ports (port 0) or mock connection
delays.

Test Cases Covered:
  (1) Detects the one open port among a scanned range.
  (2) Correctly reports closed ports as not open.
  (3) Respects the concurrency limit (assert no more than N simultaneous connections via a counter).
  (4) Times out correctly against a non-responsive port using a short test timeout.
  (5) Port specification parsing, range expansion, and input validation.
  (6) Security finding generation and risk classification.
  (7) Pipeline integration with ReconStorage and Asset enrichment.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import AsyncGenerator, List, Tuple
from unittest.mock import patch

import pytest

from core.models import Asset, Finding, Severity
from core.storage import ReconStorage
from modules.active.port_scan import (
    COMMON_SERVICES,
    DEFAULT_CONCURRENCY,
    DEFAULT_TIMEOUT,
    TOP_100_PORTS,
    TOP_1000_PORTS,
    check_port,
    create_port_findings,
    parse_ports,
    resolve_host,
    run as run_pipeline_port_scan,
    scan_asset,
    scan_host,
)


# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------

def get_closed_port() -> int:
    """Find a random ephemeral port that is guaranteed closed by binding and closing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def tcp_server() -> AsyncGenerator[Tuple[asyncio.Server, int], None]:
    """Spin up a local asyncio TCP server on a random free port on localhost (127.0.0.1:0).

    Yields (server, open_port) and ensures clean teardown.
    """
    async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(_handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield server, port
    finally:
        server.close()
        await server.wait_closed()


# ---------------------------------------------------------------------------
# Test Case 1: Detects the one open port among a scanned range
# ---------------------------------------------------------------------------

async def test_detects_one_open_port_among_scanned_range(
    tcp_server: Tuple[asyncio.Server, int]
) -> None:
    """(1) Spin up a local asyncio TCP server on a random free port and verify

    the scanner correctly identifies the single open port among a mixed range
    of open and closed ports.
    """
    server, open_port = tcp_server

    # Pick 4 guaranteed closed ports
    closed_ports = [get_closed_port() for _ in range(4)]
    while open_port in closed_ports or len(set(closed_ports)) < 4:
        closed_ports = [get_closed_port() for _ in range(4)]

    # Mixed port list containing exactly 1 open port and 4 closed ports
    scanned_ports = sorted([open_port] + closed_ports)

    # Scan localhost against the mixed range
    discovered = await scan_host(
        host="127.0.0.1",
        ports=scanned_ports,
        concurrency=10,
        timeout=0.5,
    )

    assert discovered == [open_port], (
        f"Expected to detect only open port {open_port}, but got {discovered}"
    )

    # Also test via scan_asset with Asset object
    asset = Asset(domain="127.0.0.1", ip="127.0.0.1")
    asset_discovered = await scan_asset(
        asset=asset,
        ports=scanned_ports,
        concurrency=10,
        timeout=0.5,
    )
    assert asset_discovered == [open_port]


# ---------------------------------------------------------------------------
# Test Case 2: Correctly reports closed ports as not open
# ---------------------------------------------------------------------------

async def test_reports_closed_ports_as_not_open() -> None:
    """(2) Verify that closed ports on localhost are correctly reported as not open

    both at the single-port probe level (check_port) and bulk scanner level (scan_host).
    """
    closed_port_1 = get_closed_port()
    closed_port_2 = get_closed_port()
    closed_ports = sorted(list({closed_port_1, closed_port_2}))

    # Single-port probe should return False
    for port in closed_ports:
        is_open = await check_port("127.0.0.1", port, timeout=0.2)
        assert is_open is False, f"Expected closed port {port} to return False, got True"

    # Bulk scan across only closed ports must return an empty list
    discovered = await scan_host(
        host="127.0.0.1",
        ports=closed_ports,
        concurrency=5,
        timeout=0.2,
    )
    assert discovered == [], f"Expected empty list for closed ports, got {discovered}"


# ---------------------------------------------------------------------------
# Test Case 3: Respects the concurrency limit (assert no more than N simultaneous)
# ---------------------------------------------------------------------------

async def test_respects_concurrency_limit() -> None:
    """(3) Verify that the scanner respects the concurrency limit N and never

    exceeds N simultaneous in-flight connections, measured via an active connection counter.
    """
    concurrency_limit = 3
    num_servers = 10

    active_connections = 0
    max_simultaneous = 0
    lock = asyncio.Lock()

    async def _concurrency_tracking_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal active_connections, max_simultaneous
        async with lock:
            active_connections += 1
            if active_connections > max_simultaneous:
                max_simultaneous = active_connections
        try:
            # Keep socket alive until client disconnects (EOF)
            await reader.read()
        finally:
            async with lock:
                active_connections -= 1
            writer.close()
            await writer.wait_closed()

    # Spin up 10 local servers on ephemeral ports, all using the tracking handler
    servers: List[asyncio.Server] = []
    ports: List[int] = []
    for _ in range(num_servers):
        s = await asyncio.start_server(_concurrency_tracking_handler, "127.0.0.1", 0)
        servers.append(s)
        ports.append(s.sockets[0].getsockname()[1])

    try:
        discovered = await scan_host(
            host="127.0.0.1",
            ports=ports,
            concurrency=concurrency_limit,
            timeout=1.0,
        )

        assert len(discovered) == num_servers
        # Assert that simultaneous connections never exceeded the concurrency limit N
        assert max_simultaneous <= concurrency_limit, (
            f"Concurrency limit breached: max simultaneous connections was {max_simultaneous}, "
            f"limit was {concurrency_limit}"
        )
        # Assert that connections actually ran concurrently (more than 1 simultaneous)
        assert max_simultaneous > 1, (
            f"Expected concurrent execution with overlap (> 1), got max {max_simultaneous}"
        )
    finally:
        for s in servers:
            s.close()
            await s.wait_closed()


# ---------------------------------------------------------------------------
# Test Case 4: Times out correctly against a non-responsive port
# ---------------------------------------------------------------------------

async def test_times_out_against_non_responsive_port() -> None:
    """(4) Verify that probing a non-responsive port (hanging connection) correctly

    times out using a short test timeout without stalling the scanner.
    """
    test_timeout = 0.05

    async def _mock_hanging_connect(host: str, port: int):
        # Simulate a packet blackhole/silent drop that hangs indefinitely
        await asyncio.sleep(2.0)
        return None, None

    with patch("asyncio.open_connection", side_effect=_mock_hanging_connect):
        start_time = time.monotonic()
        is_open = await check_port("127.0.0.1", 59999, timeout=test_timeout)
        duration = time.monotonic() - start_time

    assert is_open is False, "Non-responsive port should be reported as False (timed out)"
    assert duration < 0.3, (
        f"Probe took {duration:.3f}s; expected to abort near short timeout ({test_timeout}s)"
    )

    # Also test that scan_host with a mixture of open and hanging ports completes promptly
    async def _mock_do_connect(host: str, port: int, timeout: float) -> bool:
        if port == 59999:
            await asyncio.sleep(timeout + 0.1)
            return False
        return True

    with patch("modules.active.port_scan._do_connect", side_effect=_mock_do_connect):
        start = time.monotonic()
        res = await scan_host("127.0.0.1", ports=[80, 59999], timeout=test_timeout, concurrency=2)
        elapsed = time.monotonic() - start

    assert res == [80]
    assert elapsed < 0.3


# ---------------------------------------------------------------------------
# Additional Unit Tests: Port Parsing, Findings, and Resolution
# ---------------------------------------------------------------------------

def test_parse_ports() -> None:
    """(5) Test port specification parsing and range expansion."""
    p1000 = parse_ports(None)
    assert len(p1000) == 1000
    assert p1000 == parse_ports("top1000")

    p100 = parse_ports("top100")
    assert len(p100) == 100
    assert 80 in p100
    assert 443 in p100

    assert parse_ports("80, 443, 8080-8082") == [80, 443, 8080, 8081, 8082]
    assert parse_ports("8082-8080") == [8080, 8081, 8082]
    assert parse_ports([443, 80, 80, 22]) == [22, 80, 443]

    with pytest.raises(ValueError):
        parse_ports("invalid")
    with pytest.raises(ValueError):
        parse_ports("0")
    with pytest.raises(ValueError):
        parse_ports("65536")
    with pytest.raises(ValueError):
        parse_ports("")
    with pytest.raises(ValueError):
        parse_ports([])


async def test_resolve_host() -> None:
    """Test async IP resolution."""
    assert await resolve_host("127.0.0.1") == "127.0.0.1"
    assert await resolve_host("::1") == "::1"
    resolved = await resolve_host("localhost")
    assert resolved in ["127.0.0.1", "::1"]
    assert await resolve_host("nonexistent.invalid.domain.test") is None


def test_create_findings_classification() -> None:
    """(6) Test security finding generation and severity classification."""
    asset = Asset(domain="test.example.com", ip="192.0.2.1")
    open_ports = [23, 80, 445, 6379]

    findings = create_port_findings(asset, open_ports)
    assert len(findings) == 4

    summary = next(f for f in findings if f.category == "port-scan")
    assert summary.severity == Severity.INFO
    assert "Telnet" in summary.evidence
    assert "Redis" in summary.evidence

    telnet = next(f for f in findings if "port 23/TCP" in f.description)
    assert telnet.severity == Severity.HIGH

    smb = next(f for f in findings if "port 445/TCP" in f.description)
    assert smb.severity == Severity.HIGH

    redis = next(f for f in findings if "port 6379/TCP" in f.description)
    assert redis.severity == Severity.HIGH


async def test_port_scan_pipeline_run_integration(
    storage: ReconStorage, tcp_server: Tuple[asyncio.Server, int]
) -> None:
    """(7) Test full active port scan pipeline integration with storage and Asset."""
    server, open_port = tcp_server
    asset = Asset(domain="127.0.0.1", ip="127.0.0.1", discovered_via="seed")
    storage.save_asset(asset)

    await run_pipeline_port_scan(
        assets=[asset],
        storage=storage,
        target="127.0.0.1",
        ports=[open_port, get_closed_port()],
        concurrency=5,
        timeout=0.5,
    )

    updated = storage.get_asset_by_id(asset.asset_id)
    assert updated is not None
    assert open_port in updated.ports

    findings = storage.get_findings(asset=updated)
    assert len(findings) >= 1
    assert any(f.category == "port-scan" for f in findings)
