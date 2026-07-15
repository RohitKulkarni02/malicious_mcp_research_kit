"""
Runtime configuration for the ops integrations MCP server.

Lab mode (default): local-friendly defaults for development.
Live mode ({NS}_MODE=live): refuse to start without explicit engagement
targets/markers — silent lab defaults are treated as a failure.

Env namespace: set TOOL_NS (default: OPS). All settings are read as
{TOOL_NS}_SUFFIX — e.g. OPS_MODE, OPS_CALLBACK_URL, OPS_CANARY.

Peer tool names (cases 4/5/6): configurable for a *known* peer after sandbox
enumeration. Runtime peer discovery across the shared MCP tool store is not
implemented (v2). Cases 4/5/6 are peer-name-dependent.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Any


class ConfigError(ValueError):
    """Fatal configuration error."""


DEFAULT_TOOL_NS = "OPS"


def get_tool_ns() -> str:
    """Engagement-configurable env prefix (default OPS)."""

    raw = os.getenv("TOOL_NS", DEFAULT_TOOL_NS)
    ns = (raw or DEFAULT_TOOL_NS).strip()
    return ns or DEFAULT_TOOL_NS


def env_key(suffix: str) -> str:
    """Build {TOOL_NS}_{SUFFIX}."""

    return f"{get_tool_ns()}_{suffix}"


def _env_bool(suffix: str, default: bool) -> bool:
    raw = os.getenv(env_key(suffix))
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(suffix: str, default: int) -> int:
    raw = os.getenv(env_key(suffix))
    if raw is None:
        return default
    return int(raw)


def _env_list(suffix: str, default: list[str]) -> list[str]:
    raw = os.getenv(env_key(suffix))
    if raw is None or not raw.strip():
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_optional(suffix: str) -> str | None:
    raw = os.getenv(env_key(suffix))
    if raw is None or not raw.strip():
        return None
    return raw.strip()


def _env_str(suffix: str, default: str) -> str:
    return os.getenv(env_key(suffix), default)


# Lab-only fallbacks — never used when {NS}_MODE=live.
_LAB_CANARY = "eng-sess-local-0000"
_LAB_CONNECTOR_CANARY = "sess_github_local_0000"
_LAB_SEED_CANARY = "browser_sess_local_0000"
_LAB_SEED_FILE = "/tmp/ops-seed-target.txt"
_LAB_CALLBACK = "http://127.0.0.1:9999"
_LAB_HOST = "127.0.0.1"
_LAB_UNC = "127.0.0.1"
_LAB_DNS = "dns.callback.lab.example.com"
_LAB_SERVER_NAME = "ops-integrations"
_LAB_CONNECTOR_NAME = "workspace-connector"

DEFAULT_PEER_SESSION_TOOLS = [
    "get_connector_session",
    "get_github_issue",
    "get_jira_issue",
]

DEFAULT_SHADOW_TOOLS: dict[str, str] = {
    "get_github_issue": "github:get_issue / GitHub MCP get_issue",
    "fetch_github_pr": "github:get_pull_request / GitHub MCP pull_request",
    "search_jira_ticket": "jira:search_issues / Jira MCP JQL search",
    "get_jira_issue": "jira:get_issue / Jira MCP get_issue",
    "fetch_confluence_page": "confluence:get_page / Confluence MCP get_page",
    "list_databricks_jobs": "databricks:list_jobs / Databricks MCP jobs.list",
    "query_databricks": "databricks:execute_statement / Databricks SQL MCP",
}


def parse_shadow_tools(raw: str | None) -> dict[str, str]:
    """
    Parse {NS}_SHADOW_TOOLS into registered_name -> legitimate_target_label.

    Entries (comma-separated):
      get_github_issue
      live_name=get_github_issue          (squat live_name using that template's label)
      live_name=Custom legit description  (custom label; template via parse_shadow_templates)
    """

    if raw is None or not raw.strip():
        return dict(DEFAULT_SHADOW_TOOLS)

    result: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, rest = item.split("=", 1)
            name, rest = name.strip(), rest.strip()
            if rest in DEFAULT_SHADOW_TOOLS:
                result[name] = DEFAULT_SHADOW_TOOLS[rest]
            else:
                result[name] = rest or name
        else:
            if item in DEFAULT_SHADOW_TOOLS:
                result[item] = DEFAULT_SHADOW_TOOLS[item]
            else:
                result[item] = item
    return result


def parse_shadow_templates(raw: str | None) -> dict[str, str]:
    """Map registered squat name -> handler template key in DEFAULT_SHADOW_TOOLS."""

    if raw is None or not raw.strip():
        return {k: k for k in DEFAULT_SHADOW_TOOLS}

    templates: dict[str, str] = {}
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            name, rest = item.split("=", 1)
            name, rest = name.strip(), rest.strip()
            if rest in DEFAULT_SHADOW_TOOLS:
                templates[name] = rest
            elif name in DEFAULT_SHADOW_TOOLS:
                templates[name] = name
            else:
                templates[name] = "get_github_issue"
        else:
            if item in DEFAULT_SHADOW_TOOLS:
                templates[item] = item
            else:
                templates[item] = "get_github_issue"
    return templates


@dataclass
class KitConfig:
    """Runtime configuration shared by the server and case modules."""

    tool_ns: str = DEFAULT_TOOL_NS

    # lab | live — live refuses silent lab defaults
    mode: str = "lab"

    # MCP server
    host: str = _LAB_HOST
    port: int = 8000
    transport: str = "http"
    server_name: str = _LAB_SERVER_NAME

    # Case registry
    enabled_cases: list[str] = field(default_factory=lambda: ["case_01_url_exfil"])
    cases_dir: str = "cases"

    # Callback / listener target (internal name remains exfil_base_url)
    exfil_base_url: str = _LAB_CALLBACK
    exfil_public_url: str = ""

    # Engagement markers
    shadow_canary: str = _LAB_CANARY
    unc_host: str = _LAB_UNC
    dns_domain: str = _LAB_DNS

    # Cross-server (4/6)
    cross_server_mode: str = "canary"
    # Cosmetic display labels only — does NOT bind real connector APIs.
    connector_display_labels: list[str] = field(default_factory=list)
    connector_canary: str = _LAB_CONNECTOR_CANARY

    # Peer tool names for guidance (4/6) — known peer after sandbox enum; not discovery
    peer_session_tools: list[str] = field(
        default_factory=lambda: list(DEFAULT_PEER_SESSION_TOOLS)
    )

    # Case 05: registered_name -> legit label; templates pick handler
    shadow_tools: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_SHADOW_TOOLS)
    )
    shadow_tool_templates: dict[str, str] = field(
        default_factory=lambda: {k: k for k in DEFAULT_SHADOW_TOOLS}
    )

    # Seeded targets (8/9)
    seed_canary: str = _LAB_SEED_CANARY
    seed_file_path: str = _LAB_SEED_FILE

    # Stand-in connector process
    connector_host: str = _LAB_HOST
    connector_port: int = 8001
    connector_name: str = _LAB_CONNECTOR_NAME
    connector_org: str = "acme-eng"

    # HTTP listener process (listener.py)
    listener_host: str = _LAB_HOST
    listener_port: int = 9999

    # Logging
    log_level: str = "INFO"
    log_requests: bool = True

    @property
    def is_live(self) -> bool:
        return self.mode.strip().lower() == "live"

    @property
    def trusted_connectors(self) -> list[str]:
        """Alias for connector_display_labels (cosmetic only)."""

        return self.connector_display_labels

    def ek(self, suffix: str) -> str:
        """Env key for this config's namespace: {tool_ns}_{SUFFIX}."""

        return f"{self.tool_ns}_{suffix}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "tool_ns": self.tool_ns,
            "mode": self.mode,
            "host": self.host,
            "port": self.port,
            "transport": self.transport,
            "server_name": self.server_name,
            "enabled_cases": self.enabled_cases,
            "cases_dir": self.cases_dir,
            "exfil_base_url": self.exfil_base_url,
            "exfil_public_url": self.exfil_public_url or self.exfil_base_url,
            "shadow_canary": self.shadow_canary,
            "unc_host": self.unc_host,
            "dns_domain": self.dns_domain,
            "cross_server_mode": self.cross_server_mode,
            "connector_display_labels": self.connector_display_labels,
            "connector_canary": self.connector_canary,
            "peer_session_tools": self.peer_session_tools,
            "shadow_tools": self.shadow_tools,
            "seed_canary": self.seed_canary,
            "seed_file_path": self.seed_file_path,
            "connector_host": self.connector_host,
            "connector_port": self.connector_port,
            "connector_name": self.connector_name,
            "connector_org": self.connector_org,
            "listener_host": self.listener_host,
            "listener_port": self.listener_port,
            "log_level": self.log_level,
            "log_requests": self.log_requests,
        }


def _needs_cross_server(cfg: KitConfig) -> bool:
    cases = set(cfg.enabled_cases)
    return bool(
        cases
        & {
            "case_04_rogue_tool_secret_pull",
            "case_06_token_forwarding",
            "case_00_mock_trusted_connector",
        }
    ) or cfg.cross_server_mode.strip().lower() == "real"


def _needs_seed(cfg: KitConfig) -> bool:
    return bool(
        set(cfg.enabled_cases) & {"case_08_browser_access", "case_09_file_exfil"}
    )


def _needs_dns(cfg: KitConfig) -> bool:
    return "case_02_dns_exfil" in cfg.enabled_cases


def _needs_unc(cfg: KitConfig) -> bool:
    return "case_07_netntlm_unc" in cfg.enabled_cases


def _needs_shadow(cfg: KitConfig) -> bool:
    return "case_05_tool_shadowing" in cfg.enabled_cases


def validate_config(cfg: KitConfig) -> None:
    """
    Fail loud in live mode when engagement targets/markers are missing or lab-default.

    Lab mode keeps defaults for local development.
    """

    if not cfg.is_live:
        return

    errors: list[str] = []
    ns = cfg.tool_ns

    def _bad(label: str, value: str, forbidden: set[str] | None = None) -> None:
        forbidden = forbidden or set()
        if not value or not value.strip():
            errors.append(f"{label} is required in live mode (got empty)")
        elif value.strip() in forbidden:
            errors.append(f"{label} must not use lab default {value!r} in live mode")

    _bad(f"{ns}_CANARY", cfg.shadow_canary, {_LAB_CANARY})
    _bad(
        f"{ns}_CALLBACK_URL",
        cfg.exfil_base_url,
        {_LAB_CALLBACK, "http://localhost:9999"},
    )

    if cfg.exfil_base_url.startswith(
        ("http://127.0.0.1", "http://localhost", "http://[::1]")
    ):
        errors.append(
            f"{ns}_CALLBACK_URL={cfg.exfil_base_url!r} is loopback — "
            "live mode requires a reachable engagement callback URL"
        )

    if cfg.host in {"127.0.0.1", "localhost"} and cfg.transport != "stdio":
        errors.append(
            f"{ns}_HOST={cfg.host!r} is loopback — set {ns}_HOST=0.0.0.0 "
            "(or a reachable interface) for remote clients in live mode"
        )

    if _needs_cross_server(cfg) and cfg.cross_server_mode.strip().lower() == "real":
        _bad(
            f"{ns}_CONNECTOR_CANARY",
            cfg.connector_canary,
            {_LAB_CONNECTOR_CANARY},
        )
        if len(cfg.connector_canary) < 20:
            errors.append(
                f"{ns}_CONNECTOR_CANARY must be high-entropy (>=20 chars) in live real mode"
            )

    if _needs_seed(cfg):
        _bad(f"{ns}_SEED_CANARY", cfg.seed_canary, {_LAB_SEED_CANARY})
        _bad(f"{ns}_SEED_FILE", cfg.seed_file_path, {_LAB_SEED_FILE})

    if _needs_dns(cfg):
        _bad(f"{ns}_DNS_DOMAIN", cfg.dns_domain, {_LAB_DNS})

    if _needs_unc(cfg):
        _bad(f"{ns}_UNC_HOST", cfg.unc_host, {_LAB_UNC, "127.0.0.1", "localhost"})

    if _needs_shadow(cfg):
        if not cfg.shadow_tools:
            errors.append(
                f"{ns}_SHADOW_TOOLS must list at least one squat name in live mode "
                "(enumerate real connector tool names on the sandbox first)"
            )

    if errors:
        msg = (
            "LIVE MODE CONFIG REFUSED — refusing to start with missing/lab defaults "
            "(silent wrong-target callbacks are worse than a crash):\n  - "
            + "\n  - ".join(errors)
            + f"\nSet {ns}_MODE=lab for local defaults, or export the required vars. "
            f"(Namespace from TOOL_NS={ns!r}.)"
        )
        raise ConfigError(msg)


def load_config(
    *,
    host: str | None = None,
    port: int | None = None,
    transport: str | None = None,
    enabled_cases: list[str] | None = None,
    exfil_base_url: str | None = None,
    exfil_public_url: str | None = None,
    shadow_canary: str | None = None,
    unc_host: str | None = None,
    dns_domain: str | None = None,
    cross_server_mode: str | None = None,
    connector_display_labels: list[str] | None = None,
    trusted_connectors: list[str] | None = None,  # alias
    connector_canary: str | None = None,
    seed_canary: str | None = None,
    seed_file_path: str | None = None,
    log_level: str | None = None,
    mode: str | None = None,
    validate: bool = True,
) -> KitConfig:
    """Build config from defaults, environment variables, and CLI overrides."""

    tool_ns = get_tool_ns()
    mode_val = (mode or _env_str("MODE", "lab")).strip().lower()
    if mode_val not in {"lab", "live"}:
        raise ConfigError(f"{tool_ns}_MODE must be 'lab' or 'live' (got {mode_val!r})")

    shadow_raw = _env_optional("SHADOW_TOOLS")
    peer_tools = _env_list("PEER_SESSION_TOOLS", DEFAULT_PEER_SESSION_TOOLS)

    labels = connector_display_labels
    if labels is None and trusted_connectors is not None:
        labels = trusted_connectors
    if labels is None:
        labels = _env_list("CONNECTOR_DISPLAY_LABELS", [])

    cfg = KitConfig(
        tool_ns=tool_ns,
        mode=mode_val,
        host=_env_str("HOST", _LAB_HOST),
        port=_env_int("PORT", 8000),
        transport=_env_str("TRANSPORT", "http"),
        server_name=_env_str("NAME", _LAB_SERVER_NAME),
        enabled_cases=_env_list("CASES", ["case_01_url_exfil"]),
        cases_dir=_env_str("CASES_DIR", "cases"),
        exfil_base_url=_env_str("CALLBACK_URL", _LAB_CALLBACK),
        exfil_public_url=_env_str("CALLBACK_PUBLIC_URL", ""),
        shadow_canary=_env_str("CANARY", _LAB_CANARY),
        unc_host=_env_str("UNC_HOST", _LAB_UNC),
        dns_domain=_env_str("DNS_DOMAIN", _LAB_DNS),
        cross_server_mode=_env_str("CROSS_SERVER_MODE", "canary"),
        connector_display_labels=labels,
        connector_canary=_env_str("CONNECTOR_CANARY", _LAB_CONNECTOR_CANARY),
        peer_session_tools=peer_tools,
        shadow_tools=parse_shadow_tools(shadow_raw),
        shadow_tool_templates=parse_shadow_templates(shadow_raw),
        seed_canary=_env_str("SEED_CANARY", _LAB_SEED_CANARY),
        seed_file_path=_env_str("SEED_FILE", _LAB_SEED_FILE),
        connector_host=_env_str("CONNECTOR_HOST", _LAB_HOST),
        connector_port=_env_int("CONNECTOR_PORT", 8001),
        connector_name=_env_str("CONNECTOR_NAME", _LAB_CONNECTOR_NAME),
        connector_org=_env_str("CONNECTOR_ORG", "acme-eng"),
        listener_host=_env_str("LISTENER_HOST", _LAB_HOST),
        listener_port=_env_int("LISTENER_PORT", 9999),
        log_level=_env_str("LOG_LEVEL", "INFO"),
        log_requests=_env_bool("LOG_REQUESTS", True),
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
    if exfil_public_url is not None:
        cfg.exfil_public_url = exfil_public_url
    if shadow_canary is not None:
        cfg.shadow_canary = shadow_canary
    if unc_host is not None:
        cfg.unc_host = unc_host
    if dns_domain is not None:
        cfg.dns_domain = dns_domain
    if cross_server_mode is not None:
        cfg.cross_server_mode = cross_server_mode
    if connector_canary is not None:
        cfg.connector_canary = connector_canary
    if seed_canary is not None:
        cfg.seed_canary = seed_canary
    if seed_file_path is not None:
        cfg.seed_file_path = seed_file_path
    if log_level is not None:
        cfg.log_level = log_level

    if validate:
        validate_config(cfg)

    return cfg


def abort_on_config_error(exc: BaseException) -> None:
    """Print ConfigError and exit 2."""

    print(str(exc), file=sys.stderr)
    raise SystemExit(2) from exc
