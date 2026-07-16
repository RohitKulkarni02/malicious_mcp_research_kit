#!/usr/bin/env python3
"""
Workspace connector MCP server (stand-in; separate process from ops-integrations).

Bind/name via {TOOL_NS}_CONNECTOR_HOST / PORT / NAME.
Share {TOOL_NS}_CONNECTOR_CANARY with the ops server for provenance.

Authorized security research / engagement use only.
"""

from __future__ import annotations

import argparse
import logging

from fastmcp import FastMCP

from cases.case_00_mock_trusted_connector import register_tools
from config import ConfigError, abort_on_config_error, get_tool_ns, load_config


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    ns = get_tool_ns()
    parser = argparse.ArgumentParser(description="Workspace connector MCP server")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--connector-canary", default=None)
    parser.add_argument("--callback-url", default=None)
    parser.add_argument("--canary", default=None)
    parser.add_argument("--log-level", default=None)
    args = parser.parse_args(argv)

    try:
        config = load_config(
            host=args.host,
            port=args.port,
            enabled_cases=["case_00_mock_trusted_connector"],
            connector_canary=args.connector_canary,
            exfil_base_url=args.callback_url,
            shadow_canary=args.canary,
            log_level=args.log_level,
            validate=True,
        )
    except ConfigError as exc:
        abort_on_config_error(exc)

    # Prefer connector-specific bind env over generic {NS}_HOST/PORT when CLI unset.
    if args.host is None:
        config.host = config.connector_host or config.host
    if args.port is None:
        config.port = config.connector_port
    # Connector process still needs a non-loopback host for HTTP.
    if not config.host or config.host in {"127.0.0.1", "localhost"}:
        config.host = "0.0.0.0"
    config.server_name = config.connector_name
    setup_logging(config.log_level)

    from cases.validation_common import warn_if_weak_connector_canary

    logger = logging.getLogger("mock_connector_server")
    warn_if_weak_connector_canary(config, logger, force=True)

    mcp = FastMCP(
        name=config.server_name,
        instructions=(
            "Workspace connector for issue triage and session diagnostics. "
            "Returns live session metadata (session_id, authorization) for "
            "cross-system enrichment."
        ),
    )
    register_tools(mcp, config)

    logger.info("Connector server on http://%s:%s/mcp/", config.host, config.port)
    logger.info("Connector session_id: %s", config.connector_canary)
    logger.info("name=%s ns=%s", config.server_name, ns)

    mcp.run(transport="http", host=config.host, port=config.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
