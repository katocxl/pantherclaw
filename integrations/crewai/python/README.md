<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for CrewAI, Python (Apache-2.0)

`pantherclaw-crewai` makes every call of a CrewAI tool go through PantherClaw before it runs (M14 PN-016.3; HR-328, HR-329). It is built on the core client [`pantherclaw`](../../../sdk/python). Supported: `crewai` 1.15.27 or later, below 2 (extra `crewai`), on the Pythons CrewAI supports (tested on 3.13, the newest it installs on). Every decision is **PARTIAL**: the agent's process runs the tool with its own access (HR-024).

```python
from crewai import Agent
from pantherclaw import pap
from pantherclaw.client import Client
from pantherclaw_crewai import guard_tools

client = Client(pap.KeyFile.read("agent.key.json"), gateway="https://gateway.example.com")
agent = Agent(role="support", goal="Resolve tickets", backstory="…", tools=guard_tools([create_refund], client, "payments"))
```

- **Each call** of a guarded tool, sync or async, goes to the gateway's `/sdk` face of `connection` (an `http` or `mcp` connection with access mode `agent_held` or `target_enforced`) as the MCP tool `mcp__<connection>__<tool name>` of the server named after the connection, so the connection's package maps the tool by its name. The agent sees the same tool: name, description, schema and `result_as_answer`. A guarded tool's results are never cached: CrewAI's cache would answer a later call without a decision, and a cached refusal would outlive its approval.
- **Allow** runs the tool. On a target-enforced connection the allow carries PantherClaw's own request: `on_dispatch(call_id, outbound)` sends it and its return value is the tool's result (the tool's own function does not run); without `on_dispatch` the call is refused.
- **A hold** waits in PantherClaw (`wait` seconds, 300 by default), resubmits the identical call with the same action id once it is approved, and runs the tool only on PantherClaw's allow.
- **Anything else** (a deny, a hold that ends without an allow, PantherClaw unreachable or an answer it cannot check, an error inside the wrapper) returns `PantherClaw refused this call: <code> (transaction <id>)` to the agent, without running the tool, or raises `PantherClawRefused` with `raise_on_refusal=True` (CrewAI retries a tool that raised; each retry is refused again). The codes: the deny's own code (for example `GRANT_AMOUNT_EXCEEDED`, `unknown_tool`, `use_gateway_face`), `denied`, `hold_declined`, `hold_timeout`, `cannot_decide`, `dispatch_required`, `wrapper_error`.
- **A tool the package does not map** is refused (`unknown_tool`) unless `observe_unmapped=True`.
- **An identical retry** (same tool, same arguments) of a held call, by any tool of one `guard_tools` call, reuses its action id; changed arguments are a new decision.
- The wrapped tool is not an attribute of the guarded one, and the structured tool CrewAI builds from it calls PantherClaw's code. Like every wrapper this is cooperative: code in the agent's process could still call the original tool.
- **MCP servers:** reach a governed MCP server through the gateway's MCP face, where PantherClaw enforces every call (`pclaw mcp proxy` as a stdio MCP server), not through a wrapper.

The tests (`uv run --locked python -m unittest discover -s tests`, or `task sdk:check`) run every case of [`sdk/conformance/wrappers.json`](../../../sdk/conformance/wrappers.json) through the decision core and through `run`, `arun` and the structured tool a crew calls, against a fake PantherClaw on 127.0.0.1, offline. No committed lock contains CrewAI (it requires chromadb, every release of which has open advisories; M14 D60), so these run on a stand-in for the CrewAI tool interface the wrapper uses (`tests/standin`), on Python 3.13 and 3.14. `task sdk:crewai-real` runs the same tests inside the real CrewAI 1.15.27 on Python 3.13, in a throwaway environment (`uv run --isolated`, the 7-day cooldown): every case also goes through a real `Crew` whose scripted LLM makes the tool call (the raising case only through `run` and `arun`, since a crew retries a tool that raised), with CrewAI's telemetry and tracing off, and the stand-in is checked against the real interface. The decision core (`_guard.py`) and the conformance runner (`tests/conformance.py`) are the same files in every Python wrapper; the tests check that. The PyPI name is not reserved yet (Day-0 item 4).
