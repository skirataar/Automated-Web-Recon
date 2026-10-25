"""
core.storage
============
SQLite-backed persistence layer for the Recon Mapper pipeline.

All pipeline data (assets and findings) is written to a single SQLite
database file.  The storage layer is intentionally synchronous so that
modules can be written without async boilerplate; if concurrency is needed
later the interface can be wrapped with ``asyncio.to_thread``.

Classes
-------
ReconStorage
    Context-manager–friendly store that creates the schema on first use
    and exposes typed CRUD methods for Assets and Findings.

Usage
-----
>>> with ReconStorage("recon.db") as store:
...     store.save_asset(asset)
...     findings = store.get_findings_by_severity(Severity.HIGH)
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator, List, Optional

from core.models import Asset, Finding, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_CREATE_ASSETS_TABLE = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id       TEXT PRIMARY KEY,
    domain         TEXT NOT NULL,
    ip             TEXT,
    ports          TEXT NOT NULL DEFAULT '[]',   -- JSON array of ints
    tech_stack     TEXT NOT NULL DEFAULT '[]',   -- JSON array of strings
    discovered_via TEXT NOT NULL DEFAULT 'unknown',
    first_seen     TEXT NOT NULL                 -- ISO-8601 UTC
);
"""

_CREATE_FINDINGS_TABLE = """
CREATE TABLE IF NOT EXISTS findings (
    finding_id  TEXT PRIMARY KEY,
    asset_id    TEXT NOT NULL REFERENCES assets(asset_id),
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    timestamp   TEXT NOT NULL                    -- ISO-8601 UTC
);
"""

_CREATE_FINDINGS_SEVERITY_INDEX = """
CREATE INDEX IF NOT EXISTS idx_findings_severity
    ON findings (severity);
"""

_CREATE_FINDINGS_ASSET_INDEX = """
CREATE INDEX IF NOT EXISTS idx_findings_asset_id
    ON findings (asset_id);
"""


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    """Convert a datetime to a UTC ISO-8601 string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    """Parse an ISO-8601 string back to a timezone-aware datetime."""
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# ReconStorage
# ---------------------------------------------------------------------------

class ReconStorage:
    """Thread-safe, context-manager–compatible SQLite store.

    Parameters
    ----------
    db_path : str | Path
        Path to the SQLite database file.  Use ``":memory:"`` for tests.

    Examples
    --------
    As a context manager (recommended)::

        with ReconStorage("recon.db") as store:
            store.save_asset(asset)

    Or manage the lifecycle manually::

        store = ReconStorage("recon.db")
        store.open()
        store.save_asset(asset)
        store.close()
    """

    def __init__(self, db_path: str | Path = "recon.db") -> None:
        self._db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def open(self) -> "ReconStorage":
        """Open the database connection and create tables if they do not exist."""
        logger.debug("Opening database: %s", self._db_path)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()
        return self

    def close(self) -> None:
        """Commit any pending changes and close the connection."""
        if self._conn:
            self._conn.commit()
            self._conn.close()
            self._conn = None
            logger.debug("Database closed: %s", self._db_path)

    def __enter__(self) -> "ReconStorage":
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create tables and indexes on first run (idempotent)."""
        assert self._conn is not None
        with self._conn:
            self._conn.execute(_CREATE_ASSETS_TABLE)
            self._conn.execute(_CREATE_FINDINGS_TABLE)
            self._conn.execute(_CREATE_FINDINGS_SEVERITY_INDEX)
            self._conn.execute(_CREATE_FINDINGS_ASSET_INDEX)
        logger.debug("Schema initialised.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @contextmanager
    def _tx(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield the connection inside an implicit transaction."""
        assert self._conn is not None, (
            "ReconStorage is not open. Call open() or use as a context manager."
        )
        with self._conn:
            yield self._conn

    def _row_to_asset(self, row: sqlite3.Row) -> Asset:
        return Asset(
            asset_id=row["asset_id"],
            domain=row["domain"],
            ip=row["ip"],
            ports=json.loads(row["ports"]),
            tech_stack=json.loads(row["tech_stack"]),
            discovered_via=row["discovered_via"],
            first_seen=_parse_iso(row["first_seen"]),
        )

    def _row_to_finding(self, row: sqlite3.Row, asset: Asset) -> Finding:
        return Finding(
            finding_id=row["finding_id"],
            asset=asset,
            category=row["category"],
            severity=Severity(row["severity"]),
            description=row["description"],
            evidence=row["evidence"],
            timestamp=_parse_iso(row["timestamp"]),
        )

    # ------------------------------------------------------------------
    # Asset CRUD
    # ------------------------------------------------------------------

    def save_asset(self, asset: Asset) -> None:
        """Persist an Asset, updating it if it already exists (upsert).

        Parameters
        ----------
        asset : Asset
            The asset to persist.  ``asset.asset_id`` is used as the
            primary key; a re-save with the same ID updates all fields.
        """
        sql = """
        INSERT INTO assets
            (asset_id, domain, ip, ports, tech_stack, discovered_via, first_seen)
        VALUES
            (:asset_id, :domain, :ip, :ports, :tech_stack, :discovered_via, :first_seen)
        ON CONFLICT(asset_id) DO UPDATE SET
            domain         = excluded.domain,
            ip             = excluded.ip,
            ports          = excluded.ports,
            tech_stack     = excluded.tech_stack,
            discovered_via = excluded.discovered_via,
            first_seen     = excluded.first_seen;
        """
        params = {
            "asset_id": asset.asset_id,
            "domain": asset.domain,
            "ip": asset.ip,
            "ports": json.dumps(asset.ports),
            "tech_stack": json.dumps(asset.tech_stack),
            "discovered_via": asset.discovered_via,
            "first_seen": _iso(asset.first_seen),
        }
        with self._tx() as conn:
            conn.execute(sql, params)
        logger.debug("Saved asset: %s", asset.domain)

    def get_assets(self) -> List[Asset]:
        """Return all persisted assets ordered by first_seen ascending.

        Returns
        -------
        List[Asset]
            May be empty if no assets have been saved yet.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT * FROM assets ORDER BY first_seen ASC;"
        )
        return [self._row_to_asset(row) for row in cursor.fetchall()]

    def get_asset_by_id(self, asset_id: str) -> Optional[Asset]:
        """Look up a single asset by its UUID.

        Returns ``None`` if not found.
        """
        assert self._conn is not None
        cursor = self._conn.execute(
            "SELECT * FROM assets WHERE asset_id = ?;", (asset_id,)
        )
        row = cursor.fetchone()
        return self._row_to_asset(row) if row else None

    # ------------------------------------------------------------------
    # Finding CRUD
    # ------------------------------------------------------------------

    def save_finding(self, finding: Finding) -> None:
        """Persist a Finding, upserting on ``finding_id``.

        The referenced Asset must already be saved; an IntegrityError will
        be raised if the ``asset_id`` foreign-key constraint fails.

        Parameters
        ----------
        finding : Finding
            The finding to persist.
        """
        # Ensure the linked asset is present first (best-effort auto-save).
        self.save_asset(finding.asset)

        sql = """
        INSERT INTO findings
            (finding_id, asset_id, category, severity, description, evidence, timestamp)
        VALUES
            (:finding_id, :asset_id, :category, :severity, :description, :evidence, :timestamp)
        ON CONFLICT(finding_id) DO UPDATE SET
            category    = excluded.category,
            severity    = excluded.severity,
            description = excluded.description,
            evidence    = excluded.evidence,
            timestamp   = excluded.timestamp;
        """
        params = {
            "finding_id": finding.finding_id,
            "asset_id": finding.asset.asset_id,
            "category": finding.category,
            "severity": finding.severity.value,
            "description": finding.description,
            "evidence": finding.evidence,
            "timestamp": _iso(finding.timestamp),
        }
        with self._tx() as conn:
            conn.execute(sql, params)
        logger.debug(
            "Saved finding [%s] on %s", finding.severity.value, finding.asset.domain
        )

    def get_findings(self, asset: Optional[Asset] = None) -> List[Finding]:
        """Return all findings, optionally filtered by asset.

        Parameters
        ----------
        asset : Optional[Asset]
            When provided, only findings for this specific asset are returned.

        Returns
        -------
        List[Finding]
            Ordered by timestamp ascending.
        """
        assert self._conn is not None
        if asset:
            cursor = self._conn.execute(
                "SELECT * FROM findings WHERE asset_id = ? ORDER BY timestamp ASC;",
                (asset.asset_id,),
            )
        else:
            cursor = self._conn.execute(
                "SELECT * FROM findings ORDER BY timestamp ASC;"
            )

        rows = cursor.fetchall()
        results: List[Finding] = []
        for row in rows:
            linked_asset = self.get_asset_by_id(row["asset_id"])
            if linked_asset is None:
                logger.warning(
                    "Orphaned finding %s references missing asset %s",
                    row["finding_id"],
                    row["asset_id"],
                )
                continue
            results.append(self._row_to_finding(row, linked_asset))
        return results

    def get_findings_by_severity(
        self, severity: Severity, minimum: bool = False
    ) -> List[Finding]:
        """Return findings at a given severity level.

        Parameters
        ----------
        severity : Severity
            The severity to filter by.
        minimum : bool
            When ``True``, return findings at *or above* the given severity.
            When ``False`` (default), return findings at exactly that level.

        Returns
        -------
        List[Finding]
            Ordered by timestamp ascending.
        """
        assert self._conn is not None

        if minimum:
            # Build the set of levels >= the given severity, preserving order.
            levels = [s.value for s in Severity if s >= severity]
            placeholders = ",".join("?" * len(levels))
            cursor = self._conn.execute(
                f"SELECT * FROM findings WHERE severity IN ({placeholders}) "
                f"ORDER BY timestamp ASC;",
                levels,
            )
        else:
            cursor = self._conn.execute(
                "SELECT * FROM findings WHERE severity = ? ORDER BY timestamp ASC;",
                (severity.value,),
            )

        rows = cursor.fetchall()
        results: List[Finding] = []
        for row in rows:
            linked_asset = self.get_asset_by_id(row["asset_id"])
            if linked_asset is None:
                continue
            results.append(self._row_to_finding(row, linked_asset))
        return results
