<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the Claude Agent SDK, Python (Apache-2.0)

`pantherclaw-claude-agent-sdk` makes every tool call of an agent built on `claude-agent-sdk` (0.2.165 or later, below 0.3) go through PantherClaw before it runs (G0 M8 decision 2 and design decision 8, HR-200). It is built on the core client [`pantherclaw`](../../../sdk/python). Every decision is **PARTIAL**: the agent runs the tool with its own access (HR-024).

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from pantherclaw_claude_agent_sdk import PantherClaw

pc = PantherClaw.from_key_file(
    "agent.key.json",
    gateway="https://gateway.example.com",
    connection="github",        # the http or mcp connection that records built-in tools' calls
    shell_connection="laptop",  # a local connection: the /hook face decides Bash, PowerShell and Monitor (pc.shell)
)
options = ClaudeAgentOptions(**pc.options(permission_mode="default", mcp_servers={"github": github_server}))

async def prompts():  # can_use_tool needs a streaming prompt
    yield {"type": "user", "message": {"role": "user", "content": "Merge the release pull request"}}

async with ClaudeSDKClient(options=options) as agent:
    await agent.query(prompts())
    async for message in agent.receive_response():
        ...
```

It decides exactly as the TypeScript integration does ([its README](../typescript/README.md)):

- **The `PreToolUse` hook** sees every tool call, a subagent's included, in every permission mode. A tool of an MCP server listed in `gateway_mcp_servers` and configured with a URL under the gateway's `/mcp/` path passes (the gateway enforces it). `Bash`, `PowerShell` and `Monitor`, every tool that runs shell commands (HR-186), go to the local connection's `/hook` face (`shell_connection`) in their final working directory: a `Monitor` command as a `bash` command, and a `Monitor` without one (a WebSocket watch) is denied. Without a local connection the integration refuses to start unless `shell="observe"`, which only records them. Every other tool goes to the `/sdk` face. A connection governs the one MCP server named after it, so name each governed MCP server after its connection: an MCP tool goes to the connection named after its server, and a built-in to `connection`, which records it. A server whose name no connection can have (lowercase letters, digits and hyphens, at most 63 characters), and a tool whose name two configured servers' names fit, are denied without a request. `BUILTIN_TOOLS` is exactly the face's list (`sdk/conformance/sdk_face.json`); the SDK's other built-ins (`UNDECIDED_TOOLS`) can be neither decided nor recorded, so `options()` adds them to `disallowed_tools` and the model is never offered them.
- It answers `allow` on PantherClaw's allow (on a target-enforced connection, only with `on_dispatch` to send PantherClaw's own request), and `deny` on a deny or whenever PantherClaw cannot decide (unreachable, timed out, an error, an answer it cannot read or check). The hook body never raises, and its deadline (`deadline`, 10 s) is shorter than the timeout it registers.
- **Built-in tools** are recorded `OBSERVE_ONLY` and get no decision. **Other unmapped tools** are denied unless `observe_unmapped=True`.
- **A hold** never runs without PantherClaw's later allow:
  - The hook answers `ask` only when this integration's `can_use_tool` is installed, the call's mode is `default` (`ASK_MODES`), no settings files are loaded (`setting_sources=[]`, given explicitly: an omitted one may load every source) and no allow rule names the tool (the tool with any specifier, its server, `mcp__<server>__*` or any matching wildcard). `can_use_tool` then waits (`wait`, 5 minutes), resubmits the identical call and allows only on PantherClaw's allow, with the original input.
  - Otherwise the hook denies with the transaction to approve.
  - A held call is never handed to your own `can_use_tool`, even without its `tool_use_id`. Calls PantherClaw did not hold go to your own `can_use_tool`, or are denied without one.
- Blocking calls run on PantherClaw's own bounded threads, never the event loop's default executor, and a wait that ends at its deadline never resubmits afterwards. `from_key_file` gives the client a timeout no longer than the hook's deadline; a client you build yourself needs `builtins=BUILTIN_TOOLS`.

**Pass `permission_mode` explicitly**: `options()` refuses to run without it.

**The streaming-prompt workaround:** the Agent SDK documents that `can_use_tool` needs a streaming prompt, an async iterable of messages rather than a string, and a `PreToolUse` hook that keeps the stream open. PantherClaw's hook is that hook, so pass the prompt as an async iterable.

The `PermissionResultAllow`, `PermissionResultDeny` and `HookMatcher` types come from `claude_agent_sdk` when it is installed (`pip install "pantherclaw-claude-agent-sdk[agent-sdk]"`). The tests (`python -m unittest discover -s tests`, or `task sdk:check`) run the hook and the callback against a fake PantherClaw that serves the `/sdk` and `/hook` contracts, with stand-ins for those types. They do not run the Agent SDK itself: the TypeScript integration's tests run inside the real TypeScript SDK (its README says what they prove), and the same tests for the Python SDK need a `uv.lock` (DEPENDENCY_POLICY §2), so they wait for `uv` (Day-0 item 5). The PyPI names are not reserved yet (Day-0 item 4).
