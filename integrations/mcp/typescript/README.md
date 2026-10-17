<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw for the MCP TypeScript SDK (Apache-2.0)

`@pantherclaw/mcp` connects an agent built on `@modelcontextprotocol/sdk` (1.32.1 or later, below 2) to PantherClaw (PN-016.3). It is built on the core client [`@pantherclaw/sdk`](../../../sdk/typescript).

## Through the gateway (enforced)

`gatewayFetch(client, connection)` is a `fetch` for the SDK's Streamable HTTP client transport. It signs every request to the gateway's `/mcp/{connection}` face with PAP/1 (workload token, proof over method, URL and body, `PAP-Run-Id`, the gateway's nonce, one token renewal), so the gateway decides every call and sends it with credentials the agent never holds. It refuses to send anywhere but that face, a body that is not a string, and redirects.

```ts
import { Client as McpClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { gatewayFetch } from "@pantherclaw/mcp";

const url = new URL(`${client.gateway}/mcp/github`);
await mcp.connect(new StreamableHTTPClientTransport(url, { fetch: gatewayFetch(client, "github") }));
```

## An agent-held server (cooperative, PARTIAL)

`guardClient(mcpClient, { client, connection })` is for an MCP server the agent reaches itself (agent_held, or target-enforced with `onDispatch`). Every `callTool` goes to the gateway's `/sdk/{connection}` face first, as `mcp__<connection>__<tool>`, and reaches the server only on PantherClaw's allow. The connection governs the MCP server named after it (`server`, default the connection's name). Only arguments the tool's input schema declares (from the server's tool list, read again after a minute) are decided: any other argument is refused with `undecided_args`, and a tool the server does not list with `cannot_decide` (D69). The tool is then called with a copy of exactly the decided arguments. The guarded client offers only `callTool`, `listTools` and `close`, so no request reaches the server's tools without a decision; keep the raw client to yourself.

- A hold waits in PantherClaw (`onHold: "wait"`, the default and only choice; `wait` seconds, default 300) and calls the tool only on the later allow, resubmitting the same action. When the wait ends first (or the call's signal aborts) the call is refused, and an identical later call resubmits the same action. An action id is reused only while the identical call is unresolved (in flight or held, D68); after a final outcome an identical call is a new decision.
- A deny, a call PantherClaw cannot decide, an unmapped tool (unless `observeUnmapped: true`), a wait that ends and any error return an error result `PantherClaw refused this call: <code> (transaction <id>)` without calling the server, or throw a `PantherClawRefusal` with `raiseOnRefusal: true`. Codes (D47): the deny answer's own code (for example `GRANT_AMOUNT_EXCEEDED`, `unknown_tool`, `use_gateway_face`), else `denied`; `hold_declined` (a hold that ended without an allow); `hold_timeout` (a hold not allowed within the wait); `cannot_decide` (any other answer PantherClaw's client cannot read or check, or an unreachable gateway); `dispatch_required` (an allow carrying a request to send, without `onDispatch`); `undecided_args` (an argument the tool's schema does not declare, D69); `duplicate_action` (an identical concurrent call was approved and ran); `wrapper_error` (an error inside the wrapper).
- An allow carrying a request to send (a target-enforced connection) goes to `onDispatch: (callId, send) => result`, whose return value is the call's result; the client's own `callTool` is not used. Without it the call is refused with `dispatch_required`; `gatewayFetch` is the simpler route there.

## Status

- The npm name is not reserved yet (Day-0 item 4), so the package is `private`. Until the core client is published, it imports `@pantherclaw/sdk` by its path in this repository.
- The tests run inside the real MCP SDK, version 1.32.1 (a dev-only install pinned in `pnpm-lock.yaml`): an `McpServer` behind the SDK's Streamable HTTP server transport stands in for the gateway's face and checks each request's proof, and an in-memory MCP server stands in for an agent-held one, with a fake PantherClaw serving tokens and the `/sdk` face, offline.
