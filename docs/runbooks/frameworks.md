# Framework wrappers

**Milestone:** M14 ([G0 M14](../g0/M14.md) D34–D39, D47, D53). **Audience:** developers adding PantherClaw to an agent built with LangChain/LangGraph, the OpenAI Agents SDK, CrewAI, the Vercel AI SDK or the MCP TypeScript SDK. API names below follow the brief; the M14 exit status records any change. The wrappers are Apache-2.0 and not yet published to PyPI or npm; install them from the repository.

The wrappers put a PantherClaw decision in front of every tool call the framework makes, on the gateway's `/sdk` face. They are **cooperative**: they run inside the agent process, so routes they cover are labelled `PARTIAL` (R-45). For enforced routes, put credentials in PantherClaw custody and send traffic through the gateway faces (`/mcp/{conn}`, the HTTP face) instead, as §4 shows for MCP servers.

## 1. Packages

| Framework | Package | Entry points |
|---|---|---|
| LangChain, LangGraph (Python) | `pantherclaw-langchain` (`integrations/langchain/python`) | `guard_tools(tools, client, connection, **opts)`; `PantherClawToolNode` for LangGraph |
| OpenAI Agents SDK (Python) | `pantherclaw-openai-agents` (`integrations/openai-agents/python`) | `guard_tools(tools, …)`; `gateway_mcp_server(…)` |
| CrewAI (Python 3.13) | `pantherclaw-crewai` (`integrations/crewai/python`) | `guard_tools(tools, …)` |
| Vercel AI SDK (TypeScript) | `@pantherclaw/vercel-ai` (`integrations/vercel-ai/typescript`) | `guardTools(tools, {client, connection, onHold, wait})` |
| MCP TypeScript SDK | `@pantherclaw/mcp` (`integrations/mcp/typescript`) | `gatewayFetch(client, connection)`; `guardClient(mcpClient, {client, connection, server})` |

Each needs the core client (`pantherclaw` for Python, `@pantherclaw/sdk` for TypeScript) set up with the agent's enrolled workload identity ([workload-identity runbook](workload-identity.md)). The framework itself is an optional extra (Python) or optional peer dependency (TypeScript).

## 2. Example (LangChain)

```python
from pantherclaw import Client
from pantherclaw.pap import KeyFile
from pantherclaw_langchain import guard_tools

client = Client(KeyFile.read("agent.key.json"), gateway="https://gateway.example.com")
tools = guard_tools([refund_tool, lookup_tool], client, connection="payments")
# hand `tools` to your LangChain agent or LangGraph graph as usual
```

A framework tool `t` on connection `c` is authorized as tool `mcp__c__t` on server `c`, so the connection's package maps it by the tool's name.

## 3. What happens on each call

| PantherClaw answer | Wrapper behaviour |
|---|---|
| allow | Run the tool. If the answer carries `send` (the gateway built the outbound request) and the wrapper has an `on_dispatch` handler, call `on_dispatch(call_id, outbound)` and return its result **instead of** running the tool (D53); without a handler, refuse with `dispatch_required` |
| observe (monitor routes) | Run the tool |
| hold | Default `on_hold="wait"`: wait through `client.resume` up to `wait` seconds (default 300) and run only on allow. LangGraph's `PantherClawToolNode` also offers `on_hold="interrupt"`, which raises a LangGraph interrupt with the transaction, action id and deadline and resumes later |
| deny, cannot-decide, timeout, wrapper error | Do not run; return a refusal to the model (HR-328) |

The refusal text is `PantherClaw refused this call: <code> (transaction <id>)` (the transaction part is left out when there is none). Codes (D47):

| Code | When |
|---|---|
| the answer's own code (for example `GRANT_AMOUNT_EXCEEDED`, `unknown_tool`, `use_gateway_face`), else `denied` | deny |
| `hold_declined` | a hold that ended declined or expired |
| `hold_timeout` | a hold whose wait ran out or failed |
| `cannot_decide` | any other cannot-decide |
| `dispatch_required` | allow with `send` and no `on_dispatch` handler |
| `wrapper_error` | an exception inside the wrapper |

Pass `raise_on_refusal=True` to raise instead of returning the refusal. Unmapped tools are refused unless `observe_unmapped=True`. An identical retry (same tool, server and arguments, in the same wrapper instance) reuses the action id, so a held call resumes rather than starting over; changed arguments are a new decision (HR-329). The wrapped tool's original function is not reachable through the wrapper object; do not keep another reference to it in the agent.

## 4. MCP servers

- **Python frameworks:** run MCP servers through the gateway's MCP face with `pclaw mcp proxy` (stdio). For the OpenAI Agents SDK, `gateway_mcp_server(...)` returns an `MCPServerStdio` that starts the proxy.
- **MCP TypeScript SDK:** pass `fetch: gatewayFetch(client, connection)` to the Streamable HTTP client transport; every request to `/mcp/{conn}` is signed with PAP/1 and decided at the gateway (an enforced route). For servers the agent reaches directly (`agent_held`), `guardClient` wraps `callTool` through `/sdk` instead (cooperative).

## 5. Checks

The wrapper conformance group `sdk/conformance/wrappers.json` holds the shared cases (hold then allow, hold then timeout, deny, cannot-decide, unmapped, send without a handler, changed arguments after a hold). Every wrapper replays every case in `task sdk:check`; its drift test runs in `task test`. `pclaw scan` reports projects that use the Vercel `ai` package along with the other frameworks it detects.
