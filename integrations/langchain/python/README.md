<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for LangChain and LangGraph, Python (Apache-2.0)

`pantherclaw-langchain` makes every call of a LangChain tool go through PantherClaw before it runs (M14 PN-016.3; HR-328, HR-329). It is built on the core client [`pantherclaw`](../../../sdk/python). Supported: `langchain-core` 1.6.9 or later, below 2 (extra `langchain`), and `langgraph` 1.2.14 or later, below 2 (extra `langgraph`); Python 3.11 or later, tested on 3.13 and 3.14. Every decision is **PARTIAL**: the agent's process runs the tool with its own access (HR-024).

```python
from pantherclaw import pap
from pantherclaw.client import Client
from pantherclaw_langchain import PantherClawToolNode, guard_tools

client = Client(pap.KeyFile.read("agent.key.json"), gateway="https://gateway.example.com")
tools = guard_tools([create_refund, lookup_order], client, "payments")    # LangChain tools or plain functions
node = PantherClawToolNode([create_refund], client, "payments", on_hold="interrupt")  # a LangGraph ToolNode
```

- **Each call** of a guarded tool goes to the gateway's `/sdk` face of `connection` (an `http` or `mcp` connection with access mode `agent_held` or `target_enforced`) as the MCP tool `mcp__<connection>__<tool name>` of the server named after the connection, so the connection's package maps the tool by its name. Only the arguments the model gave are decided: arguments LangGraph injects (state, store, the call id) are left out. The model sees the same tool: name, description and schema.
- **Allow** runs the tool. On a target-enforced connection the allow carries PantherClaw's own request: `on_dispatch(call_id, outbound)` sends it and its return value is the tool's result (the tool's own function does not run); without `on_dispatch` the call is refused.
- **A hold** waits in PantherClaw (`on_hold="wait"`, `wait` seconds, 300 by default), resubmits the identical call with the same action id once it is approved, and runs the tool only on PantherClaw's allow. In a `PantherClawToolNode` with `on_hold="interrupt"`, a hold interrupts the graph with `{"pantherclaw": {"transaction_id", "action_id", "deadline"}}` (a checkpointer is required); once an eligible person approved it in PantherClaw, resume the graph with any `Command(resume=…)`: the node runs again, resubmits the identical call with the same action id and runs the tool only on the allow. The resume value is never an approval.
- **Anything else** (a deny, a hold that ends without an allow, PantherClaw unreachable or an answer it cannot check, an error inside the wrapper) returns `PantherClaw refused this call: <code> (transaction <id>)` to the model as an error `ToolMessage`, without running the tool, or raises `PantherClawRefused` with `raise_on_refusal=True`. The codes: the deny's own code (for example `GRANT_AMOUNT_EXCEEDED`, `unknown_tool`, `use_gateway_face`), `denied`, `hold_declined`, `hold_timeout`, `cannot_decide`, `dispatch_required`, `wrapper_error`.
- **A tool the package does not map** is refused (`unknown_tool`) unless `observe_unmapped=True`.
- **An identical retry** (same tool, same arguments) of a held call, by any tool of one `guard_tools` call, reuses its action id; changed arguments are a new decision.
- The wrapped tool is not an attribute of the guarded one. Like every wrapper this is cooperative: code in the agent's process could still call the original tool. A tool that takes LangGraph's `ToolRuntime` through its function signature alone does not get it once guarded.
- **MCP servers:** reach a governed MCP server through the gateway's MCP face, where PantherClaw enforces every call (`pclaw mcp proxy` as a stdio MCP server), not through a wrapper.

The tests (`uv run --locked python -m unittest discover -s tests`, or `task sdk:check`) run every case of [`sdk/conformance/wrappers.json`](../../../sdk/conformance/wrappers.json) through the decision core, through `invoke` and `ainvoke`, and through a real LangGraph `StateGraph` with a `PantherClawToolNode`, against a fake PantherClaw on 127.0.0.1; a fake chat model makes the tool calls, offline. `langchain-core` 1.6.9 and `langgraph` 1.2.14 are dev-only, pinned in `uv.lock`. The decision core (`_guard.py`) and the conformance runner (`tests/conformance.py`) are the same files in every Python wrapper; the tests check that. The PyPI name is not reserved yet (Day-0 item 4).
