#!/usr/bin/env python3
"""
Malicious MCP Research Kit - main server entrypoint.

Local-first FastMCP server for authorized MCP security research. Dynamically
loads demonstration cases from the cases/ package.

FOR AUTHORIZED SECURITY RESEARCH AND LOCAL LAB USE ONLY.
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
from config import KitConfig, load_config

# Populated after case registration; exposed via /status and get_kit_status.
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
    parser = argparse.ArgumentParser(
        description="MCP Security Research Kit - local malicious MCP server",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind address (default: 127.0.0.1 or MCP_KIT_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (default: 8000 or MCP_KIT_PORT)",
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
        "--exfil-url",
        default=None,
        help="Base URL for case exfil demonstrations (default: http://127.0.0.1:9999)",
    )
    parser.add_argument(
        "--canary",
        default=None,
        help="Canary token for case proof (default: MCP_KIT_CANARY)",
    )
    parser.add_argument(
        "--unc-host",
        default=None,
        help="UNC/SMB host for case_07 NetNTLM (default: MCP_KIT_UNC_HOST)",
    )
    parser.add_argument(
        "--dns-domain",
        default=None,
        help="DNS exfil domain for case_02 (default: MCP_KIT_DNS_DOMAIN)",
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
            "Security research MCP kit for authorized red-team testing. "
            "Tools demonstrate MCP invocation risks in a controlled lab setting."
        ),
    )

    _SERVER_STATE["started_at"] = datetime.now(timezone.utc).isoformat()
    _SERVER_STATE["available_cases"] = discover_case_modules()
    _SERVER_STATE["enabled_cases"] = list(config.enabled_cases)

    registered = register_case_tools(mcp, config)
    _SERVER_STATE["registered_tools"] = registered

    @mcp.custom_route("/status", methods=["GET"])
    async def status_endpoint(request: Request) -> JSONResponse:
        """HTTP status endpoint for debugging outside the MCP protocol."""

        cards = collect_case_cards(config.enabled_cases)
        body = {
            "server": config.server_name,
            "transport": config.transport,
            "endpoint": f"http://{config.host}:{config.port}/mcp/",
            "started_at": _SERVER_STATE["started_at"],
            "enabled_cases": _SERVER_STATE["enabled_cases"],
            "available_cases": _SERVER_STATE["available_cases"],
            "registered_tools": _SERVER_STATE["registered_tools"],
            "exfil_base_url": config.exfil_base_url,
            "shadow_canary": config.shadow_canary,
            "unc_host": config.unc_host,
            "dns_domain": config.dns_domain,
            "case_cards": cards,
        }
        return JSONResponse(body)

    @mcp.custom_route("/health", methods=["GET"])
    async def health_endpoint(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    @mcp.tool(
        name="get_kit_status",
        description="Return server status, enabled cases, and registered tools.",
    )
    def get_kit_status() -> str:
        """MCP-accessible status for debugging during client sessions."""

        payload = {
            "server": config.server_name,
            "started_at": _SERVER_STATE["started_at"],
            "enabled_cases": _SERVER_STATE["enabled_cases"],
            "registered_tools": _SERVER_STATE["registered_tools"],
            "exfil_base_url": config.exfil_base_url,
            "shadow_canary": config.shadow_canary,
            "unc_host": config.unc_host,
            "dns_domain": config.dns_domain,
            "http_status_url": f"http://{config.host}:{config.port}/status",
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

    config = load_config(
        host=args.host,
        port=args.port,
        transport=args.transport,
        enabled_cases=parse_enabled_cases(args.cases),
        exfil_base_url=args.exfil_url,
        shadow_canary=args.canary,
        unc_host=args.unc_host,
        dns_domain=args.dns_domain,
        log_level=args.log_level,
    )
    setup_logging(config.log_level)

    logger = logging.getLogger("server")
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
            transport = "http"  # FastMCP streamable HTTP alias
        mcp.run(transport=transport, host=config.host, port=config.port)

    return 0


# FastMCP CLI imports this module and looks for a module-level `mcp` instance.
_config = load_config()
setup_logging(_config.log_level)

if __name__ != "__main__":
    mcp = create_server(_config)


if __name__ == "__main__":
    raise SystemExit(main())
