<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the Claude Agent SDK, TypeScript (Apache-2.0)

`@pantherclaw/claude-agent-sdk` makes every tool call of an agent built on `@anthropic-ai/claude-agent-sdk` (0.3.286 or later, below 0.4) go through PantherClaw before it runs (G0 M8 decision 2, HR-200). It is built on the core client [`@pantherclaw/sdk`](../../../sdk/typescript). Every decision is **PARTIAL**: the agent runs the tool with its own access, so PantherClaw decides and records but cannot stop a tool that bypasses the SDK (HR-024). For enforced routes, put the service behind PantherClaw's gateway or a target verifier.

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { Client, readKeyFile } from "@pantherclaw/sdk";
import { PantherClaw } from "@pantherclaw/claude-agent-sdk";

const client = new Client({ keyFile: await readKeyFile("agent.key.json"), gateway: "https://gateway.example.com" });
const pantherclaw = new PantherClaw({ client, connection: "local" });
for await (const message of query({
  prompt,
  options: pantherclaw.options({ permissionMode: "default", mcpServers: { github: githubServer } }),
})) {
  // …
}
```

## How it decides

- **The `PreToolUse` hook** has no matcher, so it sees every tool call. It sends the call to the gateway's `/sdk/{connection}` face: the tool's name, its MCP server, its input as the agent produced it, its `tool_use_id`, and the working directory for `Bash` and `PowerShell`. The hook runs in every permission mode, including `bypassPermissions`.
  - On PantherClaw's allow it answers `allow`. An allow does not override the application's own deny or ask rules.
  - A deny, an unreachable gateway, a timeout, an error, or an answer it cannot read or check is `deny` (fail closed). The hook's own deadline (`deadlineMs`, 10 s) is shorter than the timeout it registers with the SDK, and the hook body never throws.
- **An unmapped built-in tool** (`Read`, `Edit`, `Write`, `Glob`, `Grep` and the rest, `BUILTIN_TOOLS`) is recorded by PantherClaw as `OBSERVE_ONLY` and gets no decision from the hook, so the application's own permission mode applies.
- **A tool that is neither mapped nor built in** is denied, unless you set `observeUnmapped: true`.
- **MCP tools** appear as `mcp__<server>__<tool>`. The server comes from the hook input or from the `mcpServers` keys, so a server name may contain `__`. Servers you list in `gatewayMcpServers` are reached through PantherClaw's gateway `/mcp` face, are already enforced there, and are not asked again.
- **A hold** (an approval or step-up in PantherClaw) never runs without PantherClaw's later allow:
  - The hook answers `ask` only when this integration's `canUseTool` is installed, the mode is neither `bypassPermissions` nor `dontAsk`, and no allow rule covers the tool. `canUseTool` then waits on the hold (`waitMs`, 5 minutes), resubmits the identical call and allows only on PantherClaw's allow, with the original input.
  - Otherwise the hook denies with the transaction to approve, and an identical later call resubmits the same action.
  - It never asks the local user to approve a PantherClaw hold. Calls that PantherClaw did not hold go to your own `canUseTool`, if you pass one in the options; without one they are denied.
  - The Agent SDK documentation does not yet state in so many words that a hook's `ask` reaches `canUseTool` in every mode. The integration relies on that only under the three conditions above, and denies otherwise.

**Pass `permissionMode` explicitly** (`options()` refuses to run without it): a session that starts without one may start in a mode the application did not choose, such as `auto`.

## Status

- The npm names are not reserved yet (Day-0 item 4), so the package is `private`. Until the core client is published, it imports `@pantherclaw/sdk` by its path in this repository.
- The tests (`node --test "test/**/*.test.ts"`, or `task sdk:check`) run the hook and the callback against a fake PantherClaw that serves the `/sdk` contract. They do not run the Agent SDK itself, which is not installed in this repository.
