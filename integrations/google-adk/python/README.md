<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the Google Agent Development Kit, Python (Apache-2.0)

`pantherclaw-adk` asks PantherClaw about every tool call of a Google ADK agent before the tool runs (G0 M34 D996; HR-767). It is built on the core client [`pantherclaw`](../../../sdk/python). Python 3.11 or later. Every decision is **PARTIAL**: the agent's code runs the tool with its own access, and code that drops the callback is not asked about (R-84).

```python
from google.adk.agents import Agent
from pantherclaw import pap
from pantherclaw.client import Client
from pantherclaw_adk import before_tool_callback

client = Client(pap.KeyFile.read("agent.key.json"), gateway="https://gateway.example.com")
agent = Agent(
    name="support",
    model="gemini-2.5-flash",
    tools=[create_refund],
    before_tool_callback=before_tool_callback(client, "payments"),
)
```

- **Each call** goes to the gateway's `/sdk` face of `connection` (an `mcp` or `http` connection with access mode `agent_held`) through `Client.authorize`, as the MCP tool `mcp__<connection>__<tool name>` of the server named after the connection, so the connection's package maps the tool by its name. The model's function call id is the call id.
- **Allow** returns `None`, and ADK runs the tool.
- **Anything else** returns a refusal dict in place of the tool's result, and the tool does not run: `{"status": "refused", "error": "PantherClaw refused this call: <code> (transaction <id>): <reason>", "code": <code>, "transaction_id": <id>}`. The codes: the deny's own code (for example `unknown_tool`), `denied`, `held`, `cannot_decide` (PantherClaw unreachable, or an answer the client cannot check), `dispatch_required` (a `target_enforced` connection, whose request only PantherClaw sends), `wrapper_error`.
- **A hold** is not waited on. The model is told the call is "held for a person's approval in PantherClaw; ask again after". Once a person approves it in PantherClaw, the identical call (same tool, same arguments) asked again reuses the held call's action id, so it is the approved action. A held call's action id is remembered for a day.

## Vertex AI Agent Engine

Vertex AI Agent Engine has no gateway hook: the ADK callback inside the agent is the only place a tool call can be asked about. Deploy the agent with the callback set, and give it:

- the PantherClaw workload key file (or an enrolment through `gcp_workload` attestation, with a trusted issuer for the Agent Engine's service account);
- the gateway URL, reachable from the Agent Engine's network;
- a connection per tool set, with the package that maps the tools.

The daily discovery of reasoning engines (D997) lists agents deployed in Agent Engine whether or not they carry the callback.
