<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the Vercel AI SDK, TypeScript (Apache-2.0)

`@pantherclaw/vercel-ai` makes every tool call of an agent built on the Vercel AI SDK (`ai` 7.0.137 or later, below 8) go through PantherClaw before it runs (PN-016.3). It is built on the core client [`@pantherclaw/sdk`](../../../sdk/typescript). Every decision is **PARTIAL**: the application runs the tool with its own access, so PantherClaw decides and records but cannot stop code that calls the service without the tool (HR-024). For enforced routes, put the service behind PantherClaw's gateway or a target verifier.

```ts
import { generateText, stepCountIs } from "ai";
import { Client, readKeyFile } from "@pantherclaw/sdk";
import { guardTools } from "@pantherclaw/vercel-ai";

const client = new Client({ keyFile: await readKeyFile("agent.key.json"), gateway: "https://gateway.example.com" });
const tools = guardTools({ create_refund: refundTool }, { client, connection: "payments" });
await generateText({ model, tools, prompt, stopWhen: stepCountIs(5) });
```

## How it decides

`guardTools(tools, options)` returns a new ToolSet whose every `execute` asks the gateway's `/sdk/{connection}` face first, as the MCP tool `mcp__<connection>__<tool name>` with the input the AI SDK validated against the tool's schema (what `execute` receives) and the AI SDK's `toolCallId`. The tool then runs on a copy of exactly that decided input, so changing the object during a hold changes nothing: the connection's package maps each tool by its name. The original `execute` functions are reachable only through the guard, and the ToolSet you pass is not changed.

- **allow** runs the tool. On a target-enforced connection the allow carries the exact request the target accepts: pass `onDispatch: (toolCallId, send) => output` to send it: its return value is the tool's output, and the tool's own `execute` does not run (it would send a second request the action token does not bind). Without it such an allow is refused.
- **hold**: the guard waits in PantherClaw (`onHold: "wait"`, the default and only choice; `wait` seconds, default 300) and runs the tool only on PantherClaw's later allow, resubmitting the identical call with the same action id. When the wait ends first (or the AI SDK aborts the call) the call is refused; an identical later call (same tool, same input in any member order, same guard) resubmits the same action, so it runs once approved. An action id is reused only while the identical call is unresolved (in flight or held, D68): an identical call while the first is held shares its id, and one approval runs the tool once. After a final outcome (ran, denied, declined, could not decide) an identical call is a new decision, and so is changed input.
- **deny**, a call PantherClaw cannot decide, an unreachable gateway, a wait that ends or any error return `PantherClaw refused this call: <code> (transaction <id>)` to the model as the tool's output, without running it (fail closed). With `raiseOnRefusal: true`, `execute` throws a `PantherClawRefusal` instead, which the AI SDK reports to the model as a tool error. A tool's own `toModelOutput` never reads a refusal: the model gets it as text. Codes (D47): the deny answer's own code (for example `GRANT_AMOUNT_EXCEEDED`, `unknown_tool`, `use_gateway_face`), else `denied`; `hold_declined` (a hold that ended without an allow); `hold_timeout` (a hold not allowed within the wait); `cannot_decide` (any other answer PantherClaw's client cannot read or check, or an unreachable gateway); `dispatch_required` (an allow carrying a request to send, without `onDispatch`); `wrapper_error` (an error inside the wrapper).
- A tool the package does not map is refused, unless `observeUnmapped: true`.
- A streaming tool (an `async function*` execute) stays a stream: the guard decides first, then yields the tool's own values; a refusal is its only value.

`guardTools` refuses, when it wraps them, the tools PantherClaw cannot govern: a provider-executed tool (it runs at the model provider) and a tool without `execute` (your application would run it outside the AI SDK).

## Status

- The npm name is not reserved yet (Day-0 item 4), so the package is `private`. Until the core client is published, it imports `@pantherclaw/sdk` by its path in this repository.
- The tests (`task sdk:check`, or `pnpm install --frozen-lockfile` then `node --test "test/**/*.test.ts"`) run the guarded tools inside the real AI SDK, version 7.0.137 (a dev-only install pinned in `pnpm-lock.yaml`), with `ai/test` mock language models calling them and a fake PantherClaw serving the `/sdk` face and the wait stream, offline. Moving to a later version means changing the pin and running them.
