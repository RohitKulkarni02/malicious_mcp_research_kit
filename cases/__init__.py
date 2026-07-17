"""Discover case_* modules and call register_tools(mcp, config)."""
from __future__ import annotations

import importlib
import logging
import pkgutil
from pathlib import Path
from types import ModuleType
from typing import Any

from config import KitConfig

logger = logging.getLogger(__name__)

CASE_MODULE_PREFIX = "case_"


def discover_case_modules(cases_dir: str | Path | None = None) -> list[str]:
    """Return sorted case module names (e.g. case_01_url_exfil)."""

    if cases_dir is None:
        cases_dir = Path(__file__).parent
    else:
        cases_dir = Path(cases_dir)

    names: list[str] = []
    for module_info in pkgutil.iter_modules([str(cases_dir)]):
        if module_info.name.startswith(CASE_MODULE_PREFIX):
            names.append(module_info.name)
    return sorted(names)


def load_case_module(case_name: str, cases_package: str = "cases") -> ModuleType:
    """Import a case module by name."""

    module_path = f"{cases_package}.{case_name}"
    return importlib.import_module(module_path)


def get_case_card(case_module: ModuleType) -> dict[str, Any] | None:
    """Return the educational case_card dict if present."""

    card = getattr(case_module, "case_card", None)
    if card is None:
        return None
    if not isinstance(card, dict):
        logger.warning("case_card in %s is not a dict; ignoring", case_module.__name__)
        return None
    return card


def register_case_tools(
    mcp: Any,
    config: KitConfig,
    enabled_cases: list[str] | None = None,
) -> dict[str, list[str]]:
    """
    Load and register tools from enabled case modules.

    Returns a mapping of case_name -> registered tool names.
    """

    enabled = enabled_cases if enabled_cases is not None else config.enabled_cases
    available = set(discover_case_modules())
    registered: dict[str, list[str]] = {}

    for case_name in enabled:
        if case_name not in available:
            logger.error(
                "Unknown case '%s'. Available: %s",
                case_name,
                ", ".join(sorted(available)) or "(none)",
            )
            continue

        module = load_case_module(case_name)
        register_fn = getattr(module, "register_tools", None)
        if register_fn is None:
            logger.error("Case '%s' is missing register_tools()", case_name)
            continue

        tool_names = register_fn(mcp, config)
        if tool_names is None:
            tool_names = []
        registered[case_name] = list(tool_names)
        logger.info("Loaded case '%s' with tools: %s", case_name, ", ".join(tool_names))

    return registered


def collect_case_cards(enabled_cases: list[str]) -> dict[str, dict[str, Any]]:
    """Gather case_card metadata for enabled cases."""

    cards: dict[str, dict[str, Any]] = {}
    for case_name in enabled_cases:
        try:
            module = load_case_module(case_name)
        except ImportError:
            logger.exception("Failed to import case '%s'", case_name)
            continue
        card = get_case_card(module)
        if card:
            cards[case_name] = card
    return cards
