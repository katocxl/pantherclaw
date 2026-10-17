// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The wrappers conformance group (sdk/conformance/wrappers.json, M14 D38)
// against guardClient: every case, in one guarded client per case over an
// in-memory MCP server, against the group's fake gateway.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Client as McpSdkClient } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Outbound } from "../../../../sdk/typescript/src/index.ts";
import { guardClient, PantherClawRefusal } from "../src/index.ts";
import { type Case, caseGateway, dispatchOf, type Group, load } from "./conformance.ts";

const g: Group = await load();

/** Held-call cases are HR-329's (resume and action id reuse); the rest HR-328's. */
const id = (c: Case) => (c.answers.includes("hold") ? "TestHR329" : "TestHR328");

/** An agent-held MCP server with the group's tool, recording each call. */
async function server(ran: unknown[]) {
  const s = new McpServer({ name: g.connection, version: "1.0.0" });
  s.registerTool(g.tool, { inputSchema: { amount: z.string(), charge: z.string(), currency: z.string(), reason: z.string() } }, async (args) => {
    ran.push(args);
    return { content: [{ type: "text", text: "ran" }] };
  });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await s.connect(b);
  const c = new McpSdkClient({ name: "agent", version: "1.0.0" });
  await c.connect(a);
  return c;
}

const textOf = (r: unknown) => ((r as { content?: { text?: string }[] }).content ?? []).map((p) => p.text).join("");

for (const c of g.cases) {
  test(`${id(c)}_wrappers conformance: ${c.name}`, async (t) => {
    const gw = await caseGateway(t, g, c);
    const ran: unknown[] = [];
    const dispatched: { id: string; send: Outbound }[] = [];
    const o = c.options ?? {};
    const mcp = await server(ran);
    t.after(() => mcp.close());
    const guarded = guardClient(mcp, {
      client: gw.client,
      connection: g.connection,
      ...(o.wait !== undefined ? { wait: o.wait } : {}),
      raiseOnRefusal: o.raise_on_refusal === true,
      observeUnmapped: o.observe_unmapped === true,
      ...(o.on_dispatch
        ? {
            onDispatch: (callId: string, send: Outbound) => {
              dispatched.push({ id: callId, send });
              return "dispatched";
            },
          }
        : {}),
    });
    let previous = "";
    const seen = new Set<string>();
    for (const [i, call] of c.calls.entries()) {
      const at = `call ${i}`;
      const before = gw.received.length;
      const ranBefore = ran.length;
      let out: unknown;
      let thrown: unknown;
      try {
        out = await guarded.callTool({ name: g.tool, arguments: structuredClone(call.input) });
      } catch (e) {
        thrown = e;
      }
      const reqs = gw.received.slice(before);
      assert.equal(reqs.length, call.requests, `${at}: /sdk requests`);
      for (const r of reqs) {
        assert.equal(r.path, g.path, at);
        assert.deepEqual({ ...r.body, tool_use_id: "" }, { tool: g.sdk_tool, server: g.connection, input: call.input, tool_use_id: "" }, at);
        assert.match(r.body.tool_use_id, /^pc-[0-9a-f]{32}$/, at);
      }
      const ids = new Set(reqs.map((r) => r.actionId));
      assert.equal(ids.size, 1, `${at}: one action id`);
      const [actionId] = ids as Set<string>;
      if (call.action_id === "same") assert.equal(actionId, previous, `${at}: the held call's action id`);
      else assert.ok(!seen.has(actionId as string), `${at}: a new action id`);
      seen.add(actionId as string);
      previous = actionId as string;
      if (call.ran) {
        assert.equal(thrown, undefined, at);
        assert.deepEqual(ran.slice(ranBefore), [call.input], `${at}: ran`);
        assert.equal(textOf(out), "ran", at);
        continue;
      }
      assert.equal(ran.length, ranBefore, `${at}: did not run`);
      if (call.dispatched) {
        assert.equal(thrown, undefined, at);
        assert.equal(out, "dispatched", at);
        assert.equal(dispatched.length, 1, `${at}: the handler is called once`);
        const d = dispatched[0] as { id: string; send: Outbound };
        assert.equal(d.id, reqs[0]?.body.tool_use_id, at);
        assert.deepEqual({ method: d.send.method, url: d.send.url, body: new TextDecoder().decode(d.send.body) }, dispatchOf(g), at);
        continue;
      }
      if (call.raises) {
        assert.ok(thrown instanceof PantherClawRefusal, `${at}: raised`);
        assert.equal(thrown.code, call.code, at);
        assert.equal(thrown.transactionId, call.transaction ?? "", at);
        assert.equal(thrown.message, call.refusal, at);
      } else {
        assert.equal(thrown, undefined, at);
        assert.equal((out as { isError?: boolean }).isError, true, at);
        assert.equal(textOf(out), call.refusal, `${at}: the refusal`);
      }
    }
  });
}
