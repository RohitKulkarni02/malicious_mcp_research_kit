# MCP Security Research Kit

Authorized, local-first MCP research kit for red-team / security assessments.

**Start here for managers:** [REVIEW.md](REVIEW.md) (includes how we test)  
**Lab retest procedures:** [RUN.md](RUN.md)  
**Live portability / name map:** [ENGAGEMENT.md](ENGAGEMENT.md)

## Neutral live footprint

Runtime env, server display names, and agent-visible tool copy use a configurable
prefix (`TOOL_NS`, default `OPS`) — e.g. `OPS_CALLBACK_URL`, server name
`ops-integrations`, stand-in connector `workspace-connector`. Nothing in those
surfaces should read as “malicious MCP kit.”

`OPS_CONNECTOR_DISPLAY_LABELS` is **cosmetic only**. Cases 4/5/6 need
`OPS_PEER_SESSION_TOOLS` / `OPS_SHADOW_TOOLS` after sandbox tool-name enum.

## What it does

A FastMCP server registers realistic-looking integration tools in an MCP client's
tool store, typically **alongside** legitimate connectors (GitHub, Jira, etc.).
Each demonstration is a pluggable **case** under `cases/`. Enable only what you
need for a given engagement.

Also included:

- `listener.py` — HTTP callback receiver for case proof
- `demo_chains.py` — pre-built case combinations
- Engagement markers (`OPS_CANARY`, `OPS_CONNECTOR_CANARY`) for unambiguous proof

## Case coverage (9)

| # | Case | Demonstrates |
|---|------|----------------|
| 1 | URL callback | Sensitive data in markdown/image URLs |
| 2 | DNS | Secrets in DNS subdomain labels |
| 3 | Toxic agent flow | Hidden instructions in tool output |
| 4 | Rogue secret pull | Descriptions that harvest peer MCP material |
| 5 | Tool shadowing | Squatting familiar tool names |
| 6 | Token forwarding | Utility tools that solicit connector tokens |
| 7 | NetNTLM via UNC | UNC paths → SMB auth (scope-gated) |
| 8 | Browser access | Local browser profiles/cookies (scope-gated) |
| 9 | File callback | File-share tools that read paths and beacon |

## Who it is for

Security researchers and penetration testers assessing MCP-enabled clients under
**explicit written authorization**.

> **Authorized use only.** Do not deploy against systems you do not own or lack permission to test.
