<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the OpenAI Agents SDK, Python (Apache-2.0)

`pantherclaw-openai-agents` makes every call of an OpenAI Agents SDK function tool go through PantherClaw before it runs (M14 PN-016.3; HR-328, HR-329). It is built on the core client [`pantherclaw`](../../../sdk/python). Supported: `openai-agents` 0.23.1 or later, below 0.24 (extra `agents`); Python 3.11 or later, tested on 3.13 and 3.14. Every decision is **PARTIAL**: the agent's process runs the tool with its own access (HR-024).

```python
from agents import Agent, Runner
from pantherclaw import pap
from pantherclaw.client import Client
from pantherclaw_openai_agents import gateway_mcp_server, guard_tools

client = Client(pap.KeyFile.read("agent.key.json"), gateway="https://gateway.example.com")
github = gateway_mcp_server("https://gateway.example.com", "github", "agent.key.json")  # enforced at the gateway
agent = Agent(name="support", tools=guard_tools([create_refund], client, "payments"), mcp_servers=[github])
```

- **Each call** of a guarded `FunctionTool` goes to the gateway's `/sdk` face of `connection` (an `http` or `mcp` connection with access mode `agent_held` or `target_enforced`) as the MCP tool `mcp__<connection>__<tool name>` of the server named after the connection, so the connection's package maps the tool by its name, with the model's call id. The model sees the same tool.
- **Allow** runs the tool. On a target-enforced connection the allow carries PantherClaw's own request: `on_dispatch(call_id, outbound)` sends it and its return value is the tool's output (the tool's own function does not run); without `on_dispatch` the call is refused.
- **A hold** waits in PantherClaw (`wait` seconds, 300 by default), resubmits the identical call with the same action id once it is approved, and runs the tool only on PantherClaw's allow.
- **Anything else** (a deny, a hold that ends without an allow, PantherClaw unreachable or an answer it cannot check, an error inside the wrapper) returns `PantherClaw refused this call: <code> (transaction <id>)` to the model as the tool's output, without running the tool, or raises `PantherClawRefused` with `raise_on_refusal=True` (the runner raises it as the cause of its `UserError`). The codes: the deny's own code (for example `GRANT_AMOUNT_EXCEEDED`, `unknown_tool`, `use_gateway_face`), `denied`, `hold_declined`, `hold_timeout`, `cannot_decide`, `dispatch_required`, `wrapper_error`.
- **A tool the package does not map** is refused (`unknown_tool`) unless `observe_unmapped=True`.
- **An identical retry** (same tool, same arguments) of a held call, by any tool of one `guard_tools` call, reuses its action id; changed arguments are a new decision.
- The guarded tool's `__wrapped__` raises and its invoker is PantherClaw's: the original function is not reachable through it. Like every wrapper this is cooperative: code in the agent's process could still call the original tool.
- **MCP servers:** `gateway_mcp_server(gateway, connection, key_file, run="")` returns an `MCPServerStdio` that runs `pclaw mcp proxy`, so the agent reaches the connection's MCP server through the gateway's MCP face, where PantherClaw decides and enforces every call. Other keyword arguments go to `MCPServerStdio`.

The tests (`uv run --locked python -m unittest discover -s tests`, or `task sdk:check`) run every case of [`sdk/conformance/wrappers.json`](../../../sdk/conformance/wrappers.json) through the decision core, through the tool's invoker and through a real `Runner` run with the SDK's `ScriptedModel`, against a fake PantherClaw on 127.0.0.1, offline. `openai-agents` 0.23.1 is dev-only, pinned in `uv.lock`. The decision core (`_guard.py`) and the conformance runner (`tests/conformance.py`) are the same files in every Python wrapper; the tests check that. The PyPI name is not reserved yet (Day-0 item 4).
