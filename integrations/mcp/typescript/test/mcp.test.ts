// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// gatewayFetch and guardClient inside the real MCP TypeScript SDK (the
// pinned dev install): an McpServer behind the SDK's Streamable HTTP
// transport stands in for the gateway's /mcp face, and an in-memory MCP
// server for an agent_held one; a fake PantherClaw serves tokens and the
// /sdk face, offline.

import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { test } from "node:test";
import { Client as McpSdkClient } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { bodyHash, fromB64url, htu, verifyEd25519 } from "../../../../sdk/typescript/src/index.ts";
import { type FetchLike, gatewayFetch, guardClient, PantherClawRefusal } from "../src/index.ts";
import { allow, decided, deny, type Face, gateway, holdThenAllow, run, unmapped } from "./gateway.ts";

/** An MCP server with one tool, create_refund, that records each call. */
function refundServer(ran: unknown[]) {
  const s = new McpServer({ name: "payments", version: "1.0.0" });
  s.registerTool("create_refund", { inputSchema: { amount: z.string(), charge: z.string() } }, async (args) => {
    ran.push(args);
    return { content: [{ type: "text", text: `refunded ${args.amount}` }] };
  });
  return s;
}

/** An agent_held MCP server, reached in memory. */
async function heldServer(ran: unknown[]) {
  const [a, b] = InMemoryTransport.createLinkedPair();
  await refundServer(ran).connect(b);
  const c = new McpSdkClient({ name: "agent", version: "1.0.0" });
  await c.connect(a);
  return c;
}

const textOf = (r: { content?: { type: string; text?: string }[] }) => r.content?.map((p) => p.text).join("") ?? "";
const refund = { name: "create_refund", arguments: { amount: "30.00", charge: "ch_1" } };

/** Checks a PAP/1 proof as the gateway would (signature, method, URL, body) and returns its claims. */
async function checkProof(proof: string, method: string, url: string, body: string) {
  const [h, p, sig] = proof.split(".");
  const header = JSON.parse(new TextDecoder().decode(fromB64url(h ?? "")));
  const claims = JSON.parse(new TextDecoder().decode(fromB64url(p ?? "")));
  assert.ok(await verifyEd25519(fromB64url(header.jwk.x), fromB64url(sig ?? ""), new TextEncoder().encode(`${h}.${p}`)), "the proof's signature");
  assert.equal(claims.htm, method);
  assert.equal(claims.htu, htu(url));
  assert.equal(claims.bh, bodyHash(body));
  return claims;
}

test("TestHR328_gatewayFetch signs every request to the gateway's /mcp face with PAP/1", async (t) => {
  const g = await gateway(t, allow);
  const ran: unknown[] = [];
  const face = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: () => randomUUID(), enableJsonResponse: true });
  await refundServer(ran).connect(face);
  const seen: { method: string; nonce?: string }[] = [];
  let first = true;
  // The gateway: asks for its nonce once, then checks each request's credentials before serving it.
  const gw: FetchLike = async (url, init) => {
    const req = new Request(url, init);
    const body = req.method === "POST" ? await req.clone().text() : "";
    const claims = await checkProof(req.headers.get("PAP-Proof") ?? "", req.method, String(url), body);
    assert.equal(req.headers.get("PAP-Run-Id"), run);
    assert.match(req.headers.get("Authorization") ?? "", /^PAP /);
    seen.push({ method: req.method, nonce: claims.nonce });
    if (first) {
      first = false;
      return new Response("", { status: 401, headers: { "PAP-Error": "use_nonce", "PAP-Nonce": "bm9uY2UtMQ" } });
    }
    assert.equal(claims.nonce, "bm9uY2UtMQ", "the nonce the gateway asked for");
    return face.handleRequest(req);
  };
  const mcp = new McpSdkClient({ name: "agent", version: "1.0.0" });
  await mcp.connect(new StreamableHTTPClientTransport(new URL(`${g.base}/mcp/payments`), { fetch: gatewayFetch(g.client, "payments", gw) }));
  const r = await mcp.callTool(refund);
  assert.equal(textOf(r as never), "refunded 30.00");
  assert.deepEqual(ran, [{ amount: "30.00", charge: "ch_1" }]);
  assert.equal(seen[0]?.nonce, undefined);
  assert.ok(seen.length >= 3, "initialize (twice: the nonce), initialized, tools/call");
  await mcp.close();
});

test("TestHR328_gatewayFetch renews an expired token once and sends nowhere but the connection's face", async (t) => {
  const g = await gateway(t, allow);
  let n = 0;
  const gw: FetchLike = async () => (n++ === 0 ? new Response("", { status: 401, headers: { "PAP-Error": "token_expired" } }) : new Response("{}", { status: 200 }));
  const f = gatewayFetch(g.client, "payments", gw);
  assert.equal((await f(`${g.base}/mcp/payments`, { method: "POST", body: "{}" })).status, 200);
  assert.equal(n, 2);
  // A second refusal is returned, not retried again.
  let m = 0;
  const always: FetchLike = async () => {
    m++;
    return new Response("", { status: 401, headers: { "PAP-Error": "use_nonce", "PAP-Nonce": "x" } });
  };
  assert.equal((await gatewayFetch(g.client, "payments", always)(`${g.base}/mcp/payments`, { method: "POST", body: "{}" })).status, 401);
  assert.equal(m, 2);
  for (const url of [`${g.base}/mcp/other`, `${g.base}/mcp/payments-x`, `${g.base}/sdk/payments`, "https://evil.example/mcp/payments", `${g.base.replace("127.0.0.1", "localhost")}/mcp/payments`]) {
    await assert.rejects(() => f(url, { method: "POST", body: "{}" }), /sends only to/, url);
  }
  await assert.rejects(() => f(`${g.base}/mcp/payments`, { method: "POST", body: new Uint8Array([1]) }), /string body/);
  assert.throws(() => gatewayFetch(g.client, "Not A Connection"), /no connection can be named/);
});

test("TestHR328_guardClient calls the server only on PantherClaw's allow", async (t) => {
  const g = await gateway(t, allow);
  const ran: unknown[] = [];
  const c = guardClient(await heldServer(ran), { client: g.client, connection: "payments" });
  assert.equal(textOf(await c.callTool(refund)), "refunded 30.00");
  assert.deepEqual(ran, [{ amount: "30.00", charge: "ch_1" }]);
  assert.equal(g.paths[0], "/sdk/payments");
  assert.deepEqual({ ...g.calls[0], tool_use_id: undefined }, { tool: "mcp__payments__create_refund", server: "payments", input: refund.arguments, tool_use_id: undefined });
  assert.equal((await c.listTools()).tools[0].name, "create_refund");
  await c.close();
});

test("TestHR328_guardClient refuses on deny, cannot_decide, unmapped and a request to send, without calling the server", async (t) => {
  const bh = createHash("sha256").update("{}").digest("hex");
  const token = `e30.${Buffer.from(JSON.stringify({ pap: { bh } })).toString("base64url")}.c2ln`;
  const send = { method: "POST", url: "https://payments.example/mcp", headers: { "PAP-Action": token }, body: Buffer.from("{}").toString("base64url"), action_token: token };
  const faces: Record<string, [Face, string]> = {
    deny: [(_c, id, res) => res.end(decided(id, "deny", { code: "amount_over_limit", transaction_id: "txn_1" })), "PantherClaw refused this call: amount_over_limit (transaction txn_1)"],
    "a gateway error": [(_c, _id, res) => res.writeHead(502).end(), "PantherClaw refused this call: cannot_decide"],
    unmapped: [unmapped, "PantherClaw refused this call: unknown_tool"],
    "a request to send": [(_c, id, res) => res.end(decided(id, "allow", { dispatch: send })), "PantherClaw refused this call: use_gateway_face"],
  };
  for (const [name, [face, want]] of Object.entries(faces)) {
    const g = await gateway(t, face);
    const ran: unknown[] = [];
    const r = await guardClient(await heldServer(ran), { client: g.client, connection: "payments" }).callTool(refund);
    assert.equal(r.isError, true, name);
    assert.equal(textOf(r), want, name);
    assert.deepEqual(ran, [], name);
  }
  const d = await gateway(t, deny);
  const ran: unknown[] = [];
  const raising = guardClient(await heldServer(ran), { client: d.client, connection: "payments", raiseOnRefusal: true });
  await assert.rejects(() => raising.callTool(refund), (e: unknown) => e instanceof PantherClawRefusal && e.code === "policy_denied");
  const u = await gateway(t, unmapped);
  await guardClient(await heldServer(ran), { client: u.client, connection: "payments", observeUnmapped: true }).callTool(refund);
  assert.equal(ran.length, 1, "observeUnmapped lets only an unmapped tool through");
});

test("TestHR329_guardClient waits on a hold and resubmits the same action; an identical retry reuses it", async (t) => {
  const actionIds: string[] = [];
  const hta = holdThenAllow();
  const g = await gateway(t, (c, id, res) => {
    actionIds.push(id);
    hta(c, id, res);
  });
  const ran: unknown[] = [];
  const c = guardClient(await heldServer(ran), { client: g.client, connection: "payments", wait: 5 });
  assert.equal(textOf(await c.callTool(refund)), "refunded 30.00");
  assert.equal(actionIds.length, 2);
  assert.equal(actionIds[0], actionIds[1], "the resubmission carries the held action's id");

  const held: string[] = [];
  const h = await gateway(t, (_c, id, res) => {
    held.push(id);
    res.end(decided(id, "hold", { wait: { handle: "h", state: "PENDING" } }));
  });
  const r = guardClient(await heldServer(ran), { client: h.client, connection: "payments", onHold: "refuse" });
  assert.equal(textOf(await r.callTool(refund)), "PantherClaw refused this call: held (transaction h)");
  await r.callTool({ name: "create_refund", arguments: { charge: "ch_1", amount: "30.00" } });
  await r.callTool({ name: "create_refund", arguments: { amount: "31.00", charge: "ch_1" } });
  assert.equal(held[0], held[1]);
  assert.notEqual(held[0], held[2]);
  assert.equal(ran.length, 1);
});

test("TestHR329_a hold whose wait ends never calls the server", async (t) => {
  const g = await gateway(t, (_c, id, res) => res.end(decided(id, "hold", { wait: { handle: "h", state: "PENDING" } })), { waitStates: ["PENDING"], block: 5000 });
  const ran: unknown[] = [];
  const c = guardClient(await heldServer(ran), { client: g.client, connection: "payments", wait: 0.3 });
  assert.equal(textOf(await c.callTool(refund)), "PantherClaw refused this call: cannot_decide");
  assert.deepEqual(ran, []);
});

test("TestT150_the guarded client exposes no way to the server's tools but callTool", async (t) => {
  const g = await gateway(t, deny);
  const ran: unknown[] = [];
  const mcp = await heldServer(ran);
  const c = guardClient(mcp, { client: g.client, connection: "payments" }) as unknown as Record<string, unknown>;
  assert.deepEqual(Object.keys(c).sort(), ["callTool", "close", "listTools"]);
  for (const v of Object.values(c)) assert.notEqual(v, mcp.callTool);
  assert.equal(c.request, undefined);
  assert.equal(c.experimental, undefined);
  await (c.callTool as (p: unknown) => Promise<unknown>)(refund);
  assert.deepEqual(ran, []);
  assert.throws(() => guardClient(mcp, { client: g.client, connection: "payments", server: "notes" }), /governs the MCP server named after it/);
});
