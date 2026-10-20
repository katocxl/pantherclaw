// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The wrappers conformance group (sdk/conformance/wrappers.json, M14 D38)
// against guardTools: every case, in one guard per case, against the
// group's fake gateway.

import { test } from "node:test";
import { jsonSchema } from "ai";
import type { Outbound } from "../../../../sdk/typescript/src/index.ts";
import { guardTools } from "../src/index.ts";
import { type Case, caseGateway, type Group, load, runCase } from "./conformance.ts";

const g: Group = await load();

/** The tool's input schema declares the group's parameters (string arguments). */
const inputSchema = jsonSchema({ type: "object", properties: Object.fromEntries(g.parameters.map((k) => [k, { type: "string" }])) });

/** Held-call cases are HR-329's (resume and action id reuse); the rest HR-328's. */
const id = (c: Case) => (c.answers.includes("hold") ? "TestHR329" : "TestHR328");

for (const [n, c] of g.cases.entries()) {
  test(`${id(c)}_wrappers conformance: ${c.name}`, async (t) => {
    const gw = await caseGateway(t, g, c);
    const ran: unknown[] = [];
    const dispatched: { id: string; send: Outbound }[] = [];
    const o = c.options ?? {};
    const tools = guardTools(
      {
        [g.tool]: {
          inputSchema,
          execute: async (input: unknown) => {
            ran.push(input);
            return "ran";
          },
        },
      },
      {
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
      },
    );
    const execute = tools[g.tool]?.execute as (input: unknown, options: unknown) => Promise<unknown>;
    await runCase(
      g,
      c,
      gw.received,
      async (input, i) => {
        try {
          return { out: await execute(input, { toolCallId: `call_${n}_${i}`, messages: [] }) };
        } catch (e) {
          return { thrown: e };
        }
      },
      ran,
      dispatched,
      { ranValue: (out) => out === "ran", refusalText: (out) => (typeof out === "string" ? out : undefined) },
    );
  });
}
