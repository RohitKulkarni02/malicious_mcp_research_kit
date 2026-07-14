"""
Configuration for the MCP security research kit.

Defaults are local-first and intentionally unauthenticated for lab use only.
Override via environment variables or CLI flags in server.py.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    return int(raw)


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class KitConfig:
    """Runtime configuration shared by the server and case modules."""

    # MCP server
    host: str = "127.0.0.1"
    port: int = 8000
    transport: str = "http"  # Streamable HTTP (FastMCP alias for streamable-http)
    server_name: str = "mcp-security-research-kit"

    # Case registry
    enabled_cases: list[str] = field(default_factory=lambda: ["case_01_url_exfil"])
    cases_dir: str = "cases"

    # Exfil listener target used by demonstration cases
    exfil_base_url: str = "http://127.0.0.1:9999"

    # Unique canary token for live engagements (case_05+ proof)
    shadow_canary: str = "CANARY-LOCAL-DEV-0000"

    # UNC/SMB target host for NetNTLM cases (case_07; point at Responder IP)
    unc_host: str = "127.0.0.1"

    # DNS exfil base domain for case_02 (zone you control or interactsh)
    dns_domain: str = "dns.exfil.attacker-controlled.example.com"

    # Cross-server demo mode for cases 04/06: canary (solo) or real (trusted connectors)
    cross_server_mode: str = "canary"
    trusted_connectors: list[str] = field(default_factory=list)

    # Logging
    log_level: str = "INFO"
    log_requests: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "transport": self.transport,
            "server_name": self.server_name,
            "enabled_cases": self.enabled_cases,
            "cases_dir": self.cases_dir,
            "exfil_base_url": self.exfil_base_url,
            "shadow_canary": self.shadow_canary,
            "unc_host": self.unc_host,
            "dns_domain": self.dns_domain,
            "cross_server_mode": self.cross_server_mode,
            "trusted_connectors": self.trusted_connectors,
            "log_level": self.log_level,
            "log_requests": self.log_requests,
        }


def load_config(
    *,
    host: str | None = None,
    port: int | None = None,
    transport: str | None = None,
    enabled_cases: list[str] | None = None,
    exfil_base_url: str | None = None,
    shadow_canary: str | None = None,
    unc_host: str | None = None,
    dns_domain: str | None = None,
    cross_server_mode: str | None = None,
    trusted_connectors: list[str] | None = None,
    log_level: str | None = None,
) -> KitConfig:
    """Build config from defaults, environment variables, and CLI overrides."""

    cfg = KitConfig(
        host=os.getenv("MCP_KIT_HOST", "127.0.0.1"),
        port=_env_int("MCP_KIT_PORT", 8000),
        transport=os.getenv("MCP_KIT_TRANSPORT", "http"),
        server_name=os.getenv("MCP_KIT_NAME", "mcp-security-research-kit"),
        enabled_cases=_env_list("MCP_KIT_CASES", ["case_01_url_exfil"]),
        cases_dir=os.getenv("MCP_KIT_CASES_DIR", "cases"),
        exfil_base_url=os.getenv("MCP_KIT_EXFIL_URL", "http://127.0.0.1:9999"),
        shadow_canary=os.getenv("MCP_KIT_CANARY", "CANARY-LOCAL-DEV-0000"),
        unc_host=os.getenv("MCP_KIT_UNC_HOST", "127.0.0.1"),
        dns_domain=os.getenv(
            "MCP_KIT_DNS_DOMAIN",
            "dns.exfil.attacker-controlled.example.com",
        ),
        cross_server_mode=os.getenv("MCP_KIT_CROSS_SERVER_MODE", "canary"),
        trusted_connectors=_env_list("MCP_KIT_TRUSTED_CONNECTORS", []),
        log_level=os.getenv("MCP_KIT_LOG_LEVEL", "INFO"),
        log_requests=_env_bool("MCP_KIT_LOG_REQUESTS", True),
    )

    if host is not None:
        cfg.host = host
    if port is not None:
        cfg.port = port
    if transport is not None:
        cfg.transport = transport
    if enabled_cases is not None:
        cfg.enabled_cases = enabled_cases
    if exfil_base_url is not None:
        cfg.exfil_base_url = exfil_base_url
    if shadow_canary is not None:
        cfg.shadow_canary = shadow_canary
    if unc_host is not None:
        cfg.unc_host = unc_host
    if dns_domain is not None:
        cfg.dns_domain = dns_domain
    if cross_server_mode is not None:
        cfg.cross_server_mode = cross_server_mode
    if trusted_connectors is not None:
        cfg.trusted_connectors = trusted_connectors
    if log_level is not None:
        cfg.log_level = log_level

    return cfg
