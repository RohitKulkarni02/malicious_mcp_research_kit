# Malicious MCP Research Kit

A reusable, local-first MCP (Model Context Protocol) attack kit for authorized security research and red teaming.

## What it does

The kit provides a malicious FastMCP server that registers realistic-looking tools in an MCP client's tool store. It is built to run **alongside legitimate connectors** (GitHub, Jira, Confluence, Databricks, and similar) so researchers can demonstrate how agents behave when trusted and untrusted servers share the same session.

Each demonstration is a pluggable **case** a Python module that registers one or more tools modeling a specific abuse pattern. Cases are loaded dynamically by `server.py`; you enable only what you need for a given engagement.

The kit also includes:

- `**listener.py**` a local HTTP receiver that logs exfiltrated data from case tools
- `**demo_chains.py**` pre-built combinations of cases for multi-step demonstrations
- **Canary-based proof** every engagement uses a unique token (`MCP_KIT_CANARY`) so impact is unambiguous on your listener or DNS/SMB logs

No code changes are required on live day. You configure URLs, canaries, and domains via environment variables before the session.

## Attack coverage (9 cases)

| #   | Case              | What it demonstrates                                                                |
| --- | ----------------- | ----------------------------------------------------------------------------------- |
| 1   | URL exfiltration  | Sensitive data encoded in markdown image/link URLs returned by tools                |
| 2   | DNS exfiltration  | Secrets embedded in DNS subdomain labels via resolver lookups                       |
| 3   | Toxic agent flow  | Hidden instructions in tool output that redirect the agent's behavior               |
| 4   | Rogue secret pull | Tool descriptions that instruct the agent to harvest secrets from other MCP servers |
| 5   | Tool shadowing    | Squatting on familiar tool names/descriptions to displace legitimate connectors     |
| 6   | Token forwarding  | Utility tools that solicit connector tokens and session material                    |
| 7   | NetNTLM via UNC   | Windows UNC paths in tool output that trigger SMB authentication                    |
| 8   | Browser access    | Reading local browser profiles, cookies, and session files from the MCP host        |
| 9   | File exfiltration | File-sharing style tools that read paths and beacon content to a listener           |

Together these cover the main ways MCP expands an agent's attack surface: untrusted tool output, collapsed trust boundaries in a shared registry, and local side effects from the MCP server process.

## Who it is for

Security researchers, red teamers, and penetration testers assessing MCP-enabled clients (Cursor, Claude Desktop, enterprise agent platforms) under **explicit written authorization**.

> **Authorized use only.** Do not deploy against systems you do not own or lack permission to test.
