"""
reports.report_generator
========================
Serialise pipeline results from storage into structured output formats.

TODO: Implement report generation logic.

Planned formats:
  - JSON   : machine-readable, one object per finding
  - Markdown : human-readable summary table, grouped by severity
  - HTML   : styled, self-contained page for stakeholder delivery

Usage (planned)::

    generator = ReportGenerator(storage=store, output_dir=Path("./reports"))
    generator.write_json("report.json")
    generator.write_markdown("report.md")
    generator.write_html("report.html")
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional

from core.models import Finding, Severity
from core.storage import ReconStorage

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate output reports from ReconStorage data.

    Parameters
    ----------
    storage : ReconStorage
        An open storage instance to read assets and findings from.
    output_dir : Path
        Directory where report files will be written.  Created if it does
        not already exist.

    Notes
    -----
    All write methods are idempotent: calling them multiple times overwrites
    any previously written output at the same path.
    """

    def __init__(self, storage: ReconStorage, output_dir: Path) -> None:
        self._storage = storage
        self._output_dir = output_dir
        self._output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def write_json(self, filename: str = "report.json") -> Path:
        """Write all findings to a JSON file.

        TODO: implement serialisation of Asset and Finding objects.

        Parameters
        ----------
        filename : str
            Output filename relative to ``output_dir``.

        Returns
        -------
        Path
            Absolute path to the written file.
        """
        # TODO: Serialise all assets and findings from self._storage
        # TODO: Write structured JSON with metadata header (target, timestamp, counts)
        raise NotImplementedError("write_json is not yet implemented.")

    # ------------------------------------------------------------------
    # Markdown
    # ------------------------------------------------------------------

    def write_markdown(self, filename: str = "report.md") -> Path:
        """Write a Markdown summary grouped by severity.

        TODO: implement Markdown table rendering.

        Parameters
        ----------
        filename : str
            Output filename relative to ``output_dir``.

        Returns
        -------
        Path
            Absolute path to the written file.
        """
        # TODO: Build severity-grouped Markdown tables
        # TODO: Include asset inventory section
        raise NotImplementedError("write_markdown is not yet implemented.")

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------

    def write_html(self, filename: str = "report.html") -> Path:
        """Write a styled, self-contained HTML report.

        TODO: implement HTML template rendering (Jinja2 or string template).

        Parameters
        ----------
        filename : str
            Output filename relative to ``output_dir``.

        Returns
        -------
        Path
            Absolute path to the written file.
        """
        # TODO: Use a Jinja2 template or inline HTML string template
        # TODO: Embed severity colour-coding and asset table
        raise NotImplementedError("write_html is not yet implemented.")
