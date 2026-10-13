<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the Claude Agent SDK, TypeScript (Apache-2.0)

`@pantherclaw/claude-agent-sdk` makes every tool call of an agent built on `@anthropic-ai/claude-agent-sdk` (0.3.286 or later, below 0.4) go through PantherClaw before it runs (G0 M8 decision 2 and design decision 8, HR-200). It is built on the core client [`@pantherclaw/sdk`](../../../sdk/typescript). Every decision is **PARTIAL**: the agent runs the tool with its own access, so PantherClaw decides and records but cannot stop a tool that bypasses the SDK (HR-024). For enforced routes, put the service behind PantherClaw's gateway or a target verifier.

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { PantherClaw } from "@pantherclaw/claude-agent-sdk";

const pc = await PantherClaw.fromKeyFile("agent.key.json", {
  gateway: "https://gateway.example.com",
  connection: "github",        // the http or mcp connection that records built-in tools' calls
  shellConnection: "laptop",   // a local connection: the /hook face decides Bash, PowerShell and Monitor (pc.shell)
});
for await (const message of query({
  prompt,
  options: pc.options({ permissionMode: "default", mcpServers: { github: githubServer } }),
})) {
  // …
}
```

`options()` must see the whole query options (`permissionMode`, `allowedTools`, `settingSources`, `mcpServers`, your own `canUseTool` and hooks) to know when a hold may be asked, so pass them through it rather than taking the hook alone. A hold is asked only with `settingSources: []`: when it is omitted the SDK loads every settings source, whose allow rules the integration cannot see.

## How it decides

The `PreToolUse` hook has no matcher, so it sees every tool call, a subagent's included, in every permission mode, `bypassPermissions` included. It sorts each call into one of three classes:

1. **A tool of an MCP server served by the gateway's `/mcp` face** (listed in `gatewayMcpServers` and configured with a URL under the gateway's `/mcp/` path) passes: the gateway enforces it. A listed server configured anywhere else is decided at `/sdk` like any other.
2. **`Bash`, `PowerShell` and `Monitor`**, every tool that runs shell commands (HR-186), are decided through the local connection's `/hook` face (`shellConnection`, the `pc.shell` mapping), as Claude Code's own hook decides them: the command and its working directory, resolved to its final path. A `Monitor` command is decided as a `bash` command, and a `Monitor` without one (a WebSocket watch) is denied. A held command is denied with the transaction to approve; an identical later command runs once it is approved. Without a local connection the integration refuses to start, unless you set `shell: "observe"`: then shell calls go to `/sdk` as built-ins, are recorded `OBSERVE_ONLY`, and run under your own permissions.
3. **Every other tool** goes to the gateway's `/sdk/{connection}` face with its name, MCP server, input as the agent produced it and `tool_use_id`. A connection governs the one MCP server named after it, so name each governed MCP server after its connection: an MCP tool goes to the connection named after its server, and a built-in to `connection`, which records it. A server whose name no connection can have (lowercase letters, digits and hyphens, at most 63 characters), and a tool whose name two configured servers' names fit, are denied without a request.
   - On PantherClaw's allow the hook answers `allow`. An allow does not override your own deny or ask rules. On a target-enforced connection the allow carries the exact request the target accepts; the tool must send it, so pass `onDispatch` to receive it, or such an allow is denied.
   - A built-in tool (`BUILTIN_TOOLS`, exactly the face's list in `sdk/conformance/sdk_face.json`) is recorded `OBSERVE_ONLY` and gets no decision, so your own permission mode applies. The SDK's other built-ins (`UNDECIDED_TOOLS`) can be neither decided nor recorded: `options()` adds them to the disallowed tools, so the model is never offered them.
   - A tool that is neither an MCP tool of a configured server nor built in is denied, and so is an MCP tool the package does not map, unless you set `observeUnmapped: true`.

A deny, an unreachable gateway, a timeout, an error, or an answer it cannot read or check is `deny` (fail closed). The hook's own deadline (`deadlineMs`, 10 s) is shorter than the timeout it registers with the SDK, and the hook body never throws.

**A hold** (an approval or step-up in PantherClaw) never runs without PantherClaw's later allow:

- The hook answers `ask` only when this integration's `canUseTool` is installed, the call's permission mode is `default` (`ASK_MODES`: the only mode where the SDK documents that `canUseTool` follows an `ask`), no allow rule names the tool (the tool with any specifier, its server, `mcp__<server>__*`, or any wildcard that matches it) and no settings files are loaded (`settingSources`), whose rules the integration cannot see.
- `canUseTool` then waits on the hold (`waitMs`, 5 minutes), resubmits the identical call and allows only on PantherClaw's allow, with the original input. It denies at its deadline.
- Otherwise the hook denies with the transaction to approve, and an identical later call resubmits the same action.
- It never asks the local user to approve a PantherClaw hold, and never hands a held call to your own `canUseTool`, even one without its `tool_use_id`. Calls PantherClaw did not hold go to your own `canUseTool`, if you pass one; without one they are denied.

**Pass `permissionMode` explicitly** (`options()` refuses to run without it): a session that starts without one may start in a mode the application did not choose, such as `auto`.

A client you build yourself must know the built-ins: `new Client({ …, builtins: BUILTIN_TOOLS })` (`fromKeyFile` does).

## Status

- The npm names are not reserved yet (Day-0 item 4), so the package is `private`. Until the core client is published, it imports `@pantherclaw/sdk` by its path in this repository.
- The tests (`task sdk:check`, or `pnpm install --frozen-lockfile` then `node --test "test/**/*.test.ts"`) run the hook and the callback against a fake PantherClaw that serves the `/sdk` and `/hook` contracts, and `test/real-sdk.test.ts` runs them inside the real Agent SDK: version 0.3.289, a dev-only install pinned in `pnpm-lock.yaml`, whose own Claude Code process talks to a fake Messages API and a stdio MCP server on 127.0.0.1, offline, in an isolated home and configuration directory. They prove, for that version, that PantherClaw's deny stops a tool in every permission mode, that a hold in `default` mode reaches `canUseTool` and runs only after PantherClaw's allow, that a hook's `ask` never runs a tool without `canUseTool`'s allow, that the application's own hook never overrides PantherClaw's deny, that a PantherClaw that does not answer is denied at the integration's deadline, that a subagent's calls reach the hook, that `Bash` goes to `/hook`, and that every built-in the SDK offers is in `BUILTIN_TOOLS`. Moving to a later SDK version means changing the pin and running them.
