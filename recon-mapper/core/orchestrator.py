"""
core.orchestrator
=================
Phase-aware pipeline engine for the Recon Mapper.

The Pipeline class drives the four-phase reconnaissance workflow:

    passive  →  active  →  surface  →  vuln_indicators

Each phase is composed of one or more *module functions* that are registered
either via the ``@pipeline.module(phase)`` decorator or the ``register()``
method.  Modules receive the current list of Assets (fetched from storage)
and yield new Assets and/or Findings that are persisted before the next
phase begins.

Scope confirmation gate
-----------------------
Before the active, surface, and vuln_indicators phases the pipeline checks
whether interactive confirmation is required (``--scope-confirm`` CLI flag).
If enabled and the user declines, the remaining phases are aborted.

Module contract
---------------
Every registered module must be a (sync or async) callable with the
signature::

    def my_module(assets: List[Asset], storage: ReconStorage, target: str) -> None:
        ...
        storage.save_asset(new_asset)
        storage.save_finding(new_finding)

Modules write directly to storage; the orchestrator re-fetches the latest
asset list from storage between phases.

Usage
-----
>>> pipeline = Pipeline(storage=store, target="example.com")
>>> pipeline.register("passive", dns_enum_module)
>>> pipeline.run()
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import Callable, Dict, List, Optional

from core.models import Asset
from core.storage import ReconStorage

logger = logging.getLogger(__name__)

# Ordered pipeline phases — the order here is the execution order.
PHASES: List[str] = ["passive", "active", "surface", "vuln_indicators"]

# Phases that require scope confirmation before they may run.
GATED_PHASES: frozenset[str] = frozenset({"active", "surface", "vuln_indicators"})

ModuleCallable = Callable[[List[Asset], ReconStorage, str], None]


class ScopeConfirmationError(RuntimeError):
    """Raised when the user declines scope confirmation for a gated phase."""


class Pipeline:
    """Orchestrates registered modules across the four recon phases.

    Parameters
    ----------
    storage : ReconStorage
        An open storage instance (used to persist and retrieve assets/findings).
    target : str
        The primary domain / IP under investigation; passed to each module.
    scope_confirm : bool
        When ``True``, the pipeline will interactively prompt the user for
        consent before running gated phases.  Set to ``False`` (default) to
        skip prompts (e.g. in CI / automated runs — use with care).
    phases_to_run : Optional[List[str]]
        Subset of phase names to execute.  Defaults to all four phases in
        the canonical order.  Useful for running only passive recon, for
        example: ``phases_to_run=["passive"]``.

    Examples
    --------
    Decorator-style registration::

        pipeline = Pipeline(storage=store, target="example.com")

        @pipeline.module("passive")
        def my_dns_module(assets, storage, target):
            ...

        pipeline.run()

    Explicit registration::

        pipeline.register("active", port_scan_module)
        pipeline.run()
    """

    def __init__(
        self,
        storage: ReconStorage,
        target: str,
        scope_confirm: bool = False,
        phases_to_run: Optional[List[str]] = None,
    ) -> None:
        self._storage = storage
        self._target = target
        self._scope_confirm = scope_confirm
        self._phases_to_run: List[str] = phases_to_run or list(PHASES)

        # Validate requested phases
        unknown = set(self._phases_to_run) - set(PHASES)
        if unknown:
            raise ValueError(f"Unknown phase(s): {unknown}. Valid phases: {PHASES}")

        # Registry: phase_name → ordered list of module callables
        self._registry: Dict[str, List[ModuleCallable]] = {p: [] for p in PHASES}

    # ------------------------------------------------------------------
    # Registration API
    # ------------------------------------------------------------------

    def register(self, phase: str, fn: ModuleCallable) -> None:
        """Register a module callable for a given phase.

        Parameters
        ----------
        phase : str
            One of ``"passive"``, ``"active"``, ``"surface"``,
            ``"vuln_indicators"``.
        fn : ModuleCallable
            The module function to register.

        Raises
        ------
        ValueError
            If ``phase`` is not one of the four valid phase names.
        """
        if phase not in PHASES:
            raise ValueError(f"Unknown phase {phase!r}. Valid phases: {PHASES}")
        self._registry[phase].append(fn)
        logger.debug("Registered module '%s' for phase '%s'.", fn.__name__, phase)

    def module(self, phase: str) -> Callable[[ModuleCallable], ModuleCallable]:
        """Decorator that registers a module for the given phase.

        Usage::

            @pipeline.module("passive")
            def dns_enum(assets, storage, target):
                ...

        Parameters
        ----------
        phase : str
            Target pipeline phase name.

        Returns
        -------
        Callable
            The original function, unmodified (decorator passthrough).
        """

        def decorator(fn: ModuleCallable) -> ModuleCallable:
            self.register(phase, fn)
            return fn

        return decorator

    # ------------------------------------------------------------------
    # Scope gate
    # ------------------------------------------------------------------

    def _request_scope_confirmation(self, phase: str) -> bool:
        """Interactively ask the operator to confirm scope before a gated phase.

        Returns ``True`` if the phase should proceed, ``False`` to abort.

        When ``scope_confirm`` is ``False`` this method is bypassed entirely
        and always returns ``True`` (consent assumed via automation flag).
        """
        if not self._scope_confirm:
            return True

        print(
            f"\n⚠️  Scope confirmation required before phase: [{phase.upper()}]\n"
            f"   Target: {self._target}\n"
            f"   This phase will interact directly with the target system.\n"
            f"   Confirm you have written authorisation to test this target.\n"
        )
        answer = input("   Proceed? [yes/no]: ").strip().lower()
        if answer in {"yes", "y"}:
            logger.info("Scope confirmed for phase '%s'.", phase)
            return True

        logger.warning("Scope confirmation DECLINED for phase '%s'. Aborting.", phase)
        return False

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Execute all registered phases in canonical order.

        For each phase:
        1. Fetch the current asset list from storage.
        2. (Gated phases) Ask for scope confirmation; abort remaining phases
           if declined.
        3. Run each registered module in registration order.
        4. Log progress.

        Async module functions are automatically executed via
        ``asyncio.run()``.
        """
        logger.info(
            "Pipeline starting. Target: %s | Phases: %s",
            self._target,
            self._phases_to_run,
        )

        for phase in PHASES:
            if phase not in self._phases_to_run:
                logger.debug("Skipping phase '%s' (not in phases_to_run).", phase)
                continue

            modules = self._registry.get(phase, [])
            if not modules:
                logger.info("Phase '%s': no modules registered — skipping.", phase)
                continue

            # Gate check for active / surface / vuln_indicators
            if phase in GATED_PHASES:
                if not self._request_scope_confirmation(phase):
                    raise ScopeConfirmationError(
                        f"User declined scope confirmation for phase '{phase}'. "
                        "Pipeline halted."
                    )

            logger.info(
                "Phase '%s': running %d module(s) …", phase, len(modules)
            )

            assets = self._storage.get_assets()
            logger.debug(
                "Phase '%s': %d asset(s) available from storage.", phase, len(assets)
            )

            for fn in modules:
                module_name = getattr(fn, "__name__", repr(fn))
                logger.info("  → Running module: %s", module_name)
                try:
                    if inspect.iscoroutinefunction(fn):
                        asyncio.run(fn(assets, self._storage, self._target))
                    else:
                        fn(assets, self._storage, self._target)
                except Exception:
                    logger.exception(
                        "Module '%s' in phase '%s' raised an unhandled exception.",
                        module_name,
                        phase,
                    )
                    # Continue with remaining modules in this phase; don't crash
                    # the whole pipeline for one failing module.

            # Refresh asset list after each phase so the next phase sees new data.
            updated_count = len(self._storage.get_assets())
            logger.info(
                "Phase '%s' complete. Total assets in storage: %d.",
                phase,
                updated_count,
            )

        logger.info("Pipeline finished for target: %s", self._target)

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a human-readable summary of registered modules per phase."""
        lines = [f"Pipeline target: {self._target}"]
        for phase in PHASES:
            mods = self._registry.get(phase, [])
            names = [getattr(m, "__name__", repr(m)) for m in mods]
            status = ", ".join(names) if names else "(none)"
            lines.append(f"  [{phase}]: {status}")
        return "\n".join(lines)
