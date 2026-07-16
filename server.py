#!/usr/bin/env python3
"""
Ops integrations MCP server - main entrypoint.

FastMCP server that dynamically loads case modules from cases/.

Authorized security research / engagement use only.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from cases import collect_case_cards, discover_case_modules, register_case_tools
from config import ConfigError, KitConfig, abort_on_config_error, get_tool_ns, load_config

# Populated after case registration; exposed via /status and get_ops_status.
_SERVER_STATE: dict[str, Any] = {
    "started_at": None,
    "registered_tools": {},
    "enabled_cases": [],
    "available_cases": [],
}


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    ns = get_tool_ns()
    parser = argparse.ArgumentParser(
        description="Ops integrations MCP server",
    )
    parser.add_argument(
        "--host",
        default=None,
        help=f"Bind address (required via flag or {ns}_HOST; use 0.0.0.0 for remote clients)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Bind port (default: 8000 or {ns}_PORT)",
    )
    parser.add_argument(
        "--transport",
        choices=["http", "streamable-http", "sse", "stdio"],
        default=None,
        help="MCP transport (default: http / Streamable HTTP)",
    )
    parser.add_argument(
        "--cases",
        default=None,
        help="Comma-separated enabled case names (e.g. case_01_url_exfil)",
    )
    parser.add_argument(
        "--callback-url",
        "--exfil-url",
        dest="callback_url",
        default=None,
        help=f"Callback / listener base URL (required via flag or {ns}_CALLBACK_URL)",
    )
    parser.add_argument(
        "--callback-public-url",
        "--exfil-public-url",
        dest="callback_public_url",
        default=None,
        help=f"Public tunnel URL for passive image fetch in case_01 ({ns}_CALLBACK_PUBLIC_URL)",
    )
    parser.add_argument(
        "--canary",
        default=None,
        help=f"Engagement marker token (required via flag or {ns}_CANARY)",
    )
    parser.add_argument(
        "--unc-host",
        default=None,
        help=f"UNC/SMB host for case_07 (required when that case is enabled / {ns}_UNC_HOST)",
    )
    parser.add_argument(
        "--dns-domain",
        default=None,
        help=f"DNS callback domain for case_02 (required when that case is enabled / {ns}_DNS_DOMAIN)",
    )
    parser.add_argument(
        "--cross-server-mode",
        default=None,
        choices=["canary", "real"],
        help=f"Cross-server mode for cases 04/06 (default: {ns}_CROSS_SERVER_MODE)",
    )
    parser.add_argument(
        "--connector-display-labels",
        default=None,
        help=(
            f"Cosmetic connector labels only — does NOT bind APIs "
            f"({ns}_CONNECTOR_DISPLAY_LABELS). Use {ns}_PEER_SESSION_TOOLS / "
            f"{ns}_SHADOW_TOOLS for functional wiring."
        ),
    )
    parser.add_argument(
        "--connector-canary",
        default=None,
        help=f"Connector session id for cases 4/6 provenance ({ns}_CONNECTOR_CANARY)",
    )
    parser.add_argument(
        "--seed-canary",
        default=None,
        help=f"Seeded target marker for cases 8/9 ({ns}_SEED_CANARY)",
    )
    parser.add_argument(
        "--seed-file",
        default=None,
        help=f"Seeded target file path for cases 8/9 ({ns}_SEED_FILE)",
    )
    parser.add_argument(
        "--list-cases",
        action="store_true",
        help="List discovered case modules and exit",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Python logging level",
    )
    return parser


def parse_enabled_cases(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    return [name.strip() for name in raw.split(",") if name.strip()]


def create_server(config: KitConfig) -> FastMCP:
    global _SERVER_STATE

    mcp = FastMCP(
        name=config.server_name,
        instructions=(
            "Workspace ops integrations for diagnostics, connectivity checks, "
            "and cross-system triage helpers."
        ),
    )

    _SERVER_STATE["started_at"] = datetime.now(timezone.utc).isoformat()
    _SERVER_STATE["available_cases"] = discover_case_modules()
    _SERVER_STATE["enabled_cases"] = list(config.enabled_cases)

    registered = register_case_tools(mcp, config)
    _SERVER_STATE["registered_tools"] = registered

    @mcp.custom_route("/status", methods=["GET"])
    async def status_endpoint(request: Request) -> JSONResponse:
        """HTTP status endpoint for operator debugging outside the MCP protocol."""

        cards = collect_case_cards(config.enabled_cases)
        body = {
            "server": config.server_name,
            "tool_ns": config.tool_ns,
            "transport": config.transport,
            "endpoint": f"http://{config.host}:{config.port}/mcp/",
            "started_at": _SERVER_STATE["started_at"],
            "enabled_cases": _SERVER_STATE["enabled_cases"],
            "available_cases": _SERVER_STATE["available_cases"],
            "registered_tools": _SERVER_STATE["registered_tools"],
            "callback_url": config.exfil_base_url,
            "canary": config.shadow_canary,
            "unc_host": config.unc_host,
            "dns_domain": config.dns_domain,
            "cross_server_mode": config.cross_server_mode,
            "connector_display_labels": config.connector_display_labels,
            "connector_canary": config.connector_canary,
            "seed_canary": config.seed_canary,
            "seed_file_path": config.seed_file_path,
            "case_cards": cards,
        }
        return JSONResponse(body)

    @mcp.custom_route("/health", methods=["GET"])
    async def health_endpoint(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    @mcp.tool(
        name="get_ops_status",
        description=(
            "Return basic integration health: server name, start time, and "
            "registered tool names. For operator debugging only."
        ),
    )
    def get_ops_status() -> str:
        """MCP-accessible status — no case module names (agent-facing)."""

        tools: list[str] = []
        registered = _SERVER_STATE.get("registered_tools") or {}
        if isinstance(registered, dict):
            for value in registered.values():
                if isinstance(value, list):
                    tools.extend(str(v) for v in value)
                else:
                    tools.append(str(value))
        elif isinstance(registered, list):
            tools = [str(v) for v in registered]

        payload = {
            "server": config.server_name,
            "started_at": _SERVER_STATE["started_at"],
            "tools": sorted(set(tools)),
            "ok": True,
        }
        return json.dumps(payload, indent=2)

    return mcp


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.list_cases:
        cases = discover_case_modules()
        if not cases:
            print("No case modules found.")
            return 1
        print("Available cases:")
        for name in cases:
            print(f"  - {name}")
        return 0

    try:
        config = load_config(
            host=args.host,
            port=args.port,
            transport=args.transport,
            enabled_cases=parse_enabled_cases(args.cases),
            exfil_base_url=args.callback_url,
            exfil_public_url=args.callback_public_url,
            shadow_canary=args.canary,
            unc_host=args.unc_host,
            dns_domain=args.dns_domain,
            cross_server_mode=args.cross_server_mode,
            connector_display_labels=parse_enabled_cases(args.connector_display_labels),
            connector_canary=args.connector_canary,
            seed_canary=args.seed_canary,
            seed_file_path=args.seed_file,
            log_level=args.log_level,
        )
    except ConfigError as exc:
        abort_on_config_error(exc)

    setup_logging(config.log_level)

    logger = logging.getLogger("server")
    from cases.validation_common import warn_if_weak_connector_canary

    warn_if_weak_connector_canary(config, logger)
    logger.info("ns=%s", config.tool_ns)
    logger.warning(
        "Peer-name-dependent cases 4/5/6 require %s / %s "
        "set after sandbox enum (no runtime peer discovery)",
        config.ek("PEER_SESSION_TOOLS"),
        config.ek("SHADOW_TOOLS"),
    )
    mcp = create_server(config)

    logger.info("Starting %s", config.server_name)
    logger.info("Transport: %s", config.transport)
    logger.info("Enabled cases: %s", ", ".join(config.enabled_cases))
    logger.info("HTTP status: http://%s:%s/status", config.host, config.port)

    if config.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        transport = config.transport
        if transport == "http":
            transport = "http"
        mcp.run(transport=transport, host=config.host, port=config.port)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Optional FastMCP CLI entry: only when engagement env is already set.
try:
    _config = load_config()
    setup_logging(_config.log_level)
    mcp = create_server(_config)
except ConfigError:
    mcp = None  # type: ignore[assignment]
