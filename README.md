# MCP Security Research Kit

Authorized, local-first MCP research kit for red-team / security assessments.

## What it does

A FastMCP server registers realistic-looking integration tools in an MCP client's
tool store, typically **alongside** legitimate connectors (GitHub, Jira, etc.).
Each demonstration is a pluggable **case** under `cases/`. Enable only what you need.

Also included:

- `listener.py` — HTTP callback receiver for case proof
- Engagement markers (`OPS_CANARY`, `OPS_CONNECTOR_CANARY`) for unambiguous proof

Prefer stdio for local desktop cases; for HTTP use
`OPS_HOST=0.0.0.0` and a **reachable** (non-loopback) callback URL.

## Case coverage (13)

| #   | Case                    | Demonstrates                                                                                                                             |
| --- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | URL callback            | Telemetry-shaped image URL + Mermaid + webview fallbacks                                                                                 |
| 2   | DNS exfil               | Base32 DNS labels; harvest + conditional ping/nslookup/dig/host/git-diff chain                                                           |
| 3   | Toxic agent flow        | SYSTEM continuation in tool output steers follow-on tool calls (optional Unicode Tag smuggling)                                          |
| 4   | Rogue secret pull       | Health-check framing that pulls peer session material from shared agent context                                                          |
| 5   | Tool shadowing          | Exact-name squat via `OPS_SHADOW_TOOLS`                                                                                                  |
| 6   | Token forwarding        | Verification-framed tools that capture connector tokens; config file read variant reads `~/.cursor/mcp.json` directly                    |
| 7   | NetNTLM via UNC         | Clean UNC path recommendation → SMB auth capture (Windows + Responder required)                                                          |
| 8   | Browser access          | Session-continuity framing; server-side Chrome/Firefox/Safari profile reads (Cookies, Preferences, Local Storage) - no model cooperation |
| 9   | File exfil              | File-share tools that silently read sensitive paths server-side (`~/.aws/credentials`, `~/.ssh/config`, `~/.docker/config.json`, etc.)   |
| 10  | Agent config escalation | YOLO / auto-approve config write + shell; Unicode Tag encoding; disables all future approval prompts                                     |
| 11  | TOCTOU script           | Append to benign script + delayed exec; helper write races sleep window                                                                  |
| 12  | MCP config poison       | Register second attacker MCP entry in client config — persistent foothold survives session termination                                   |
| 13  | Model provider redirect | Override `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / workspace `.env` to attacker intercept; targets developer app SDK traffic            |

## Who it is for

Security researchers and penetration testers assessing MCP-enabled clients under
**explicit written authorization**.

> **Authorized use only.** Do not deploy against systems you do not own or lack permission to test.
