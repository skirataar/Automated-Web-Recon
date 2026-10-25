"""
core.models
===========
Shared domain models for the Recon Mapper pipeline.

All data that flows between pipeline phases is expressed through these
dataclasses so that modules remain loosely coupled from the storage layer.

Classes
-------
Severity
    Enumeration of finding criticality levels: INFO → LOW → MEDIUM → HIGH.

Asset
    A discovered host / service, enriched progressively as phases run.

Finding
    A single observation tied to an Asset with a severity rating.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Finding criticality levels, ordered from least to most severe.

    Using ``str`` as a mixin makes JSON serialisation trivial (the enum
    member is already a valid string) and allows direct comparison with
    string constants.

    Example
    -------
    >>> Severity.HIGH > Severity.LOW
    True
    """

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

    # Support natural ordering (INFO < LOW < MEDIUM < HIGH)
    _order_ = "INFO LOW MEDIUM HIGH"

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        order = list(Severity)
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self == other or self > other


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------

@dataclass
class Asset:
    """A discovered host or service within scope.

    Attributes
    ----------
    domain : str
        The fully-qualified domain name (or bare hostname) of the target.
    ip : Optional[str]
        Resolved IP address. May be ``None`` until active probing occurs.
    ports : List[int]
        Open ports discovered during active scanning. Empty list until
        the active phase runs.
    tech_stack : List[str]
        Technology identifiers detected (e.g. ``["nginx/1.24", "PHP/8.2"]``).
        Populated progressively by multiple modules.
    discovered_via : str
        Human-readable label for the module that first observed this asset
        (e.g. ``"dns_enum"``, ``"cert_ct"``).
    first_seen : datetime
        UTC timestamp when the asset was first recorded. Defaults to now.
    asset_id : str
        Stable UUID assigned at creation; used as the primary key in storage.

    Notes
    -----
    All mutable defaults (lists) use ``field(default_factory=…)`` to avoid
    the classic shared-mutable-default pitfall.
    """

    domain: str
    ip: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    discovered_via: str = "unknown"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    asset_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        """Validate required fields on construction."""
        if not self.domain or not isinstance(self.domain, str):
            raise ValueError("Asset.domain must be a non-empty string.")

    def __repr__(self) -> str:
        return (
            f"Asset(domain={self.domain!r}, ip={self.ip!r}, "
            f"ports={self.ports!r}, discovered_via={self.discovered_via!r})"
        )


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single security-relevant observation attached to an Asset.

    Attributes
    ----------
    asset : Asset
        The asset this finding relates to.
    category : str
        Short category tag (e.g. ``"tls"``, ``"header"``, ``"cve"``,
        ``"cors"``, ``"open-port"``).
    severity : Severity
        Criticality level of the finding.
    description : str
        Human-readable description of what was observed.
    evidence : str
        Raw evidence string: HTTP headers, banner text, JSON snippet, etc.
        Kept as a plain string so it is trivially storable and auditable.
    timestamp : datetime
        UTC time the finding was recorded. Defaults to now.
    finding_id : str
        Stable UUID; used as the primary key in storage.

    Notes
    -----
    Findings are **observational only**.  The tool does not attempt
    exploitation; evidence is captured solely for reporting purposes.
    """

    asset: Asset
    category: str
    severity: Severity
    description: str
    evidence: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        """Coerce severity strings to the enum; validate required fields."""
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity.upper())
            except ValueError as exc:
                valid = [s.value for s in Severity]
                raise ValueError(
                    f"Invalid severity {self.severity!r}. Valid values: {valid}"
                ) from exc
        if not self.description:
            raise ValueError("Finding.description must be a non-empty string.")
        if not self.category:
            raise ValueError("Finding.category must be a non-empty string.")

    def __repr__(self) -> str:
        return (
            f"Finding(asset={self.asset.domain!r}, category={self.category!r}, "
            f"severity={self.severity.value!r})"
        )
