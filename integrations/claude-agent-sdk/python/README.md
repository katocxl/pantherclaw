<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the Claude Agent SDK, Python (Apache-2.0)

`pantherclaw-claude-agent-sdk` makes every tool call of an agent built on `claude-agent-sdk` (0.2.165 or later, below 0.3) go through PantherClaw before it runs (G0 M8 decision 2, HR-200). It is built on the core client [`pantherclaw`](../../../sdk/python). Every decision is **PARTIAL**: the agent runs the tool with its own access (HR-024).

```python
from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
from pantherclaw import pap
from pantherclaw.client import Client
from pantherclaw_claude_agent_sdk import PantherClaw

client = Client(pap.KeyFile.read("agent.key.json"), gateway="https://gateway.example.com")
pantherclaw = PantherClaw(client, "local")
options = ClaudeAgentOptions(**pantherclaw.options(permission_mode="default", mcp_servers={"github": github_server}))

async def prompts():  # can_use_tool needs a streaming prompt
    yield {"type": "user", "message": {"role": "user", "content": "Merge the release pull request"}}

async with ClaudeSDKClient(options=options) as agent:
    await agent.query(prompts())
    async for message in agent.receive_response():
        ...
```

It decides exactly as the TypeScript integration does ([its README](../typescript/README.md)):

- **The `PreToolUse` hook** runs on every tool in every permission mode. It answers `allow` on PantherClaw's allow, and `deny` on a deny or whenever PantherClaw cannot decide (unreachable, timed out, an error, an answer it cannot read or check). The hook body never raises, and its deadline (`deadline`, 10 s) is shorter than the timeout it registers.
- **Unmapped built-in tools** are recorded `OBSERVE_ONLY` and get no decision. **Unmapped other tools** are denied unless `observe_unmapped=True`.
- **A hold** never runs without PantherClaw's later allow:
  - The hook answers `ask` only when this integration's `can_use_tool` is installed, the mode is neither `bypassPermissions` nor `dontAsk`, and no allow rule covers the tool. `can_use_tool` then waits (`wait`, 5 minutes), resubmits the identical call and allows only on PantherClaw's allow, with the original input.
  - Otherwise the hook denies with the transaction to approve.
  - Calls PantherClaw did not hold go to your own `can_use_tool`, or are denied without one.

**Pass `permission_mode` explicitly**: `options()` refuses to run without it.

**The streaming-prompt workaround:** the Agent SDK documents that `can_use_tool` needs a streaming prompt, an async iterable of messages rather than a string, and a `PreToolUse` hook that keeps the stream open. PantherClaw's hook is that hook, so pass the prompt as an async iterable.

The `PermissionResultAllow`, `PermissionResultDeny` and `HookMatcher` types come from `claude_agent_sdk` when it is installed (`pip install "pantherclaw-claude-agent-sdk[agent-sdk]"`). The tests (`python -m unittest discover -s tests`, or `task sdk:check`) run the hook and the callback against a fake PantherClaw that serves the `/sdk` contract, with stand-ins for those types. They do not run the Agent SDK itself. The PyPI names are not reserved yet (Day-0 item 4).
