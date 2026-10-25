#!/usr/bin/env python3
"""
main.py — Recon Mapper CLI entrypoint
======================================
Wires argparse to the Pipeline so the tool can be driven from the command line.

Usage
-----
    python main.py --target example.com
    python main.py --target example.com --output ./reports/ --scope-confirm
    python main.py --target example.com --phases passive active --db recon.db
    python main.py --target example.com --log-level DEBUG

Examples
--------
Passive-only run (safe, no direct target interaction)::

    python main.py --target example.com --phases passive

Full pipeline with manual scope gate::

    python main.py --target example.com --scope-confirm --output ./reports/

Automated run (CI/CD — assumes pre-authorisation)::

    python main.py --target example.com --output ./reports/ --log-level WARNING
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from core.orchestrator import PHASES, Pipeline, ScopeConfirmationError
from core.storage import ReconStorage

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

def _configure_logging(level: str) -> None:
    """Configure root logger with a timestamped console handler."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Module auto-registration
# ---------------------------------------------------------------------------

def _register_modules(pipeline: Pipeline) -> None:
    """Import and register all implemented module stubs with the pipeline.

    As individual modules are implemented in modules/passive/, modules/active/,
    etc., add their registration calls here.

    TODO: Replace stubs with real module imports as each is implemented.
    """
    # ── Passive ────────────────────────────────────────────────────────────
    try:
        from modules.passive.subdomain_enum import run as subdomain_enum_run
        pipeline.register("passive", subdomain_enum_run)
    except ImportError as exc:
        logging.getLogger(__name__).debug("passive.subdomain_enum unavailable: %s", exc)

    try:
        from modules.passive.whois_dns import run as whois_dns_run
        pipeline.register("passive", whois_dns_run)
    except ImportError as exc:
        logging.getLogger(__name__).debug("passive.whois_dns unavailable: %s", exc)

    # ── Active ─────────────────────────────────────────────────────────────
    try:
        from modules.active.port_scan import run as port_scan_run
        pipeline.register("active", port_scan_run)
    except ImportError as exc:
        logging.getLogger(__name__).debug("active.port_scan unavailable: %s", exc)

    try:
        from modules.active.service_fingerprint import run as service_fingerprint_run
        pipeline.register("active", service_fingerprint_run)
    except ImportError as exc:
        logging.getLogger(__name__).debug("active.service_fingerprint unavailable: %s", exc)
    # TODO: from modules.active.http_probe  import run as http_probe_run
    # TODO: pipeline.register("active", http_probe_run)

    # ── Surface ────────────────────────────────────────────────────────────
    # TODO: from modules.surface.endpoint_crawler import run as crawler_run
    # TODO: pipeline.register("surface", crawler_run)

    # ── Vuln indicators ────────────────────────────────────────────────────
    # TODO: from modules.vuln_indicators.version_cve import run as cve_run
    # TODO: from modules.vuln_indicators.header_audit import run as header_run
    # TODO: pipeline.register("vuln_indicators", cve_run)
    # TODO: pipeline.register("vuln_indicators", header_run)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-mapper",
        description=(
            "Automated Web Recon & Attack Surface Mapper\n"
            "─────────────────────────────────────────────\n"
            "Detection and fingerprinting ONLY. No exploitation.\n"
            "Only run against targets you are authorised to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target example.com\n"
            "  python main.py --target example.com --scope-confirm --output ./out/\n"
            "  python main.py --target example.com --phases passive --log-level DEBUG\n"
        ),
    )

    # Required
    parser.add_argument(
        "--target",
        required=True,
        metavar="DOMAIN",
        help="Primary target domain or IP address (e.g. example.com).",
    )

    # Output / storage
    parser.add_argument(
        "--output",
        default="./reports/",
        metavar="DIR",
        help=(
            "Directory where reports will be written.  "
            "Created if it does not exist.  Default: ./reports/"
        ),
    )
    parser.add_argument(
        "--db",
        default="recon.db",
        metavar="FILE",
        help="Path to the SQLite database file.  Default: recon.db",
    )

    # Pipeline control
    parser.add_argument(
        "--phases",
        nargs="+",
        choices=PHASES,
        default=PHASES,
        metavar="PHASE",
        help=(
            f"Pipeline phases to execute (space-separated).  "
            f"Choices: {PHASES}.  Default: all phases."
        ),
    )
    parser.add_argument(
        "--scope-confirm",
        action="store_true",
        default=False,
        help=(
            "Interactively prompt for scope confirmation before each gated "
            "phase (active, surface, vuln_indicators).  "
            "Recommended for manual runs."
        ),
    )

    # Logging
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        metavar="LEVEL",
        help="Logging verbosity.  Default: INFO.",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """Parse arguments, open storage, build pipeline, and run.

    Returns
    -------
    int
        Exit code: 0 on success, non-zero on failure.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args.log_level)
    log = logging.getLogger(__name__)

    log.info("=" * 60)
    log.info("Recon Mapper — target: %s", args.target)
    log.info("Phases: %s", args.phases)
    log.info("Output: %s", args.output)
    log.info("DB:     %s", args.db)
    log.info("=" * 60)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with ReconStorage(args.db) as storage:
            pipeline = Pipeline(
                storage=storage,
                target=args.target,
                scope_confirm=args.scope_confirm,
                phases_to_run=args.phases,
            )
            _register_modules(pipeline)

            log.info("Pipeline configuration:\n%s", pipeline.summary())
            pipeline.run()

    except ScopeConfirmationError as exc:
        log.error("Scope gate rejected: %s", exc)
        return 1
    except KeyboardInterrupt:
        log.warning("Interrupted by user.")
        return 130
    except Exception:
        log.exception("Unhandled exception in pipeline.")
        return 2

    log.info("Done. Results stored in %s", args.db)
    return 0


if __name__ == "__main__":
    sys.exit(main())
