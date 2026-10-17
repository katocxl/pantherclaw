// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The wrappers conformance group (sdk/conformance/wrappers.json, M14 D38)
// against guardClient: every case, in one guarded client per case over an
// in-memory MCP server, against the group's fake gateway.

import { test } from "node:test";
import { Client as McpSdkClient } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { Outbound } from "../../../../sdk/typescript/src/index.ts";
import { guardClient } from "../src/index.ts";
import { type Case, caseGateway, type Group, load, runCase } from "./conformance.ts";

const g: Group = await load();

/** Held-call cases are HR-329's (resume and action id reuse); the rest HR-328's. */
const id = (c: Case) => (c.answers.includes("hold") ? "TestHR329" : "TestHR328");

/** An agent-held MCP server whose tool declares the group's parameters, recording each call. */
async function server(ran: unknown[]) {
  const s = new McpServer({ name: g.connection, version: "1.0.0" });
  s.registerTool(g.tool, { inputSchema: Object.fromEntries(g.parameters.map((k) => [k, z.string().optional()])) }, async (args) => {
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
    await runCase(
      g,
      c,
      gw.received,
      async (input) => {
        try {
          return { out: await guarded.callTool({ name: g.tool, arguments: input as Record<string, unknown> }) };
        } catch (e) {
          return { thrown: e };
        }
      },
      ran,
      dispatched,
      {
        ranValue: (out) => textOf(out) === "ran",
        refusalText: (out) => ((out as { isError?: boolean }).isError === true ? textOf(out) : undefined),
      },
    );
  });
}
