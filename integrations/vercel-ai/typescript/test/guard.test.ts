// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// guardTools inside the real AI SDK (the pinned `ai` dev install): a mock
// language model from `ai/test` calls the tools, and a fake PantherClaw
// answers the /sdk face, offline.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { generateText, jsonSchema, stepCountIs, tool } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { guardTools, PantherClawRefusal, type ToolSet } from "../src/index.ts";
import { allow, decided, deny, type Face, gateway, holdThenAllow, unmapped } from "./gateway.ts";

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 1, text: 1, reasoning: 0 },
};

/** A model that calls each tool call in `calls` in its first step, then answers with text. */
function model(calls: { name: string; input: Record<string, unknown>; id?: string }[]) {
  return new MockLanguageModelV4({
    doGenerate: [
      {
        content: calls.map((c, i) => ({ type: "tool-call" as const, toolCallId: c.id ?? `call_${i}`, toolName: c.name, input: JSON.stringify(c.input) })),
        finishReason: { unified: "tool-calls", raw: undefined },
        usage,
        warnings: [],
      },
      { content: [{ type: "text", text: "done" }], finishReason: { unified: "stop", raw: undefined }, usage, warnings: [] },
    ],
  });
}

const refundSchema = jsonSchema<{ amount: string; charge: string }>({
  type: "object",
  properties: { amount: { type: "string" }, charge: { type: "string" } },
  required: ["amount", "charge"],
});

/** The application's tools: create_refund records each run. */
function appTools(ran: unknown[]): ToolSet {
  return {
    create_refund: tool({
      description: "Refund a charge",
      inputSchema: refundSchema,
      execute: async (input) => {
        ran.push(input);
        return { refunded: input.amount };
      },
    }),
  };
}

/** Runs the agent once and returns the tool results the model saw. */
async function runAgent(tools: ToolSet, calls = [{ name: "create_refund", input: { amount: "30.00", charge: "ch_1" } }]) {
  const r = await generateText({ model: model(calls), tools, prompt: "refund", stopWhen: stepCountIs(3) });
  return r.steps.flatMap((s) => s.toolResults.map((x) => x.output));
}

test("TestHR328_a tool runs only on PantherClaw's allow, through the real AI SDK", async (t) => {
  const g = await gateway(t, allow);
  const ran: unknown[] = [];
  const out = await runAgent(guardTools(appTools(ran), { client: g.client, connection: "payments" }));
  assert.deepEqual(ran, [{ amount: "30.00", charge: "ch_1" }]);
  assert.deepEqual(out, [{ refunded: "30.00" }]);
  assert.equal(g.calls.length, 1);
  assert.deepEqual(g.calls[0], { tool: "mcp__payments__create_refund", server: "payments", input: { amount: "30.00", charge: "ch_1" }, tool_use_id: "call_0" });
  assert.equal(g.paths[0], "/sdk/payments");
});

test("TestHR328_deny, cannot_decide and unmapped return a refusal to the model without running the tool", async (t) => {
  const faces: Record<string, [Face, string]> = {
    deny: [(_c, id, res) => res.end(decided(id, "deny", { error_class: "policy_denied", code: "amount_over_limit", transaction_id: "txn_1" })), "PantherClaw refused this call: amount_over_limit (transaction txn_1)"],
    "a denial without a code": [deny, "PantherClaw refused this call: denied"],
    "a gateway error": [(_c, _id, res) => res.writeHead(502).end(), "PantherClaw refused this call: cannot_decide"],
    "an unreadable answer": [(_c, _id, res) => res.end("{"), "PantherClaw refused this call: cannot_decide"],
    "an observe answer for a decided tool": [
      (_c, _id, res) => res.end(JSON.stringify({ decision: "allow", coverage: "OBSERVE_ONLY", mode: "monitor" })),
      "PantherClaw refused this call: cannot_decide",
    ],
    unmapped: [unmapped, "PantherClaw refused this call: unknown_tool"],
  };
  for (const [name, [face, want]] of Object.entries(faces)) {
    const g = await gateway(t, face);
    const ran: unknown[] = [];
    const out = await runAgent(guardTools(appTools(ran), { client: g.client, connection: "payments" }));
    assert.deepEqual(ran, [], name);
    assert.deepEqual(out, [want], name);
  }
});

test("TestHR328_an unreachable PantherClaw and a thrown error refuse", async (t) => {
  const g = await gateway(t, allow);
  const ran: unknown[] = [];
  // biome-ignore lint/suspicious/noExplicitAny: a client that throws instead of answering
  const broken = { authorize: () => Promise.reject(new Error("boom")) } as any;
  assert.deepEqual(await runAgent(guardTools(appTools(ran), { client: broken, connection: "payments" })), ["PantherClaw refused this call: wrapper_error"]);
  const { Client, newKeyFile } = await import("../../../../sdk/typescript/src/index.ts");
  const { identifier, run } = await import("./gateway.ts");
  const down = new Client({ keyFile: { ...newKeyFile(), identifier, server: "http://127.0.0.1:9" }, gateway: "http://127.0.0.1:9", runId: run, timeoutMs: 500 });
  assert.deepEqual(await runAgent(guardTools(appTools(ran), { client: down, connection: "payments" })), ["PantherClaw refused this call: cannot_decide"]);
  assert.deepEqual(ran, []);
  assert.equal(g.calls.length, 0);
});

test("TestHR328_observeUnmapped lets only an unmapped tool run", async (t) => {
  const g = await gateway(t, unmapped);
  const ran: unknown[] = [];
  await runAgent(guardTools(appTools(ran), { client: g.client, connection: "payments", observeUnmapped: true }));
  assert.equal(ran.length, 1);
  const d = await gateway(t, deny);
  await runAgent(guardTools(appTools(ran), { client: d.client, connection: "payments", observeUnmapped: true }));
  assert.equal(ran.length, 1, "a deny still refuses");
});

test("TestHR328_raiseOnRefusal throws a PantherClawRefusal from execute", async (t) => {
  const g = await gateway(t, (_c, id, res) => res.end(decided(id, "deny", { code: "amount_over_limit", transaction_id: "txn_9" })));
  const ran: unknown[] = [];
  const tools = guardTools(appTools(ran), { client: g.client, connection: "payments", raiseOnRefusal: true });
  await assert.rejects(
    async () => (tools.create_refund?.execute as (i: unknown, o: unknown) => Promise<unknown>)({ amount: "1", charge: "ch_1" }, { toolCallId: "c1", messages: [] }),
    (e: unknown) => e instanceof PantherClawRefusal && e.code === "amount_over_limit" && e.transactionId === "txn_9",
  );
  // Inside the AI SDK a thrown refusal is a tool error the model sees, never a run.
  const r = await generateText({ model: model([{ name: "create_refund", input: { amount: "1", charge: "ch_1" } }]), tools, prompt: "refund", stopWhen: stepCountIs(3) });
  const errors = r.steps.flatMap((s) => s.content.filter((p) => p.type === "tool-error"));
  assert.equal(errors.length, 1);
  assert.deepEqual(ran, []);
});

/** A dispatch the client accepts: its action token binds the body. */
function dispatch(body: string) {
  const bh = createHash("sha256").update(body).digest("hex");
  const token = `e30.${Buffer.from(JSON.stringify({ pap: { bh } })).toString("base64url")}.c2ln`;
  return { method: "POST", url: "https://payments.example/v1/refunds", headers: { "PAP-Action": token }, body: Buffer.from(body).toString("base64url"), action_token: token };
}

test("TestHR328_an allow carrying the request to send runs only its dispatch handler", async (t) => {
  const g = await gateway(t, (_c, id, res) => res.end(decided(id, "allow", { dispatch: dispatch('{"amount":"30.00"}') })));
  const ran: unknown[] = [];
  assert.deepEqual(await runAgent(guardTools(appTools(ran), { client: g.client, connection: "payments" })), ["PantherClaw refused this call: dispatch_required"]);
  assert.deepEqual(ran, []);
  const sent: string[] = [];
  const out = await runAgent(
    guardTools(appTools(ran), {
      client: g.client,
      connection: "payments",
      onDispatch: (id, send) => {
        sent.push(`${id} ${new TextDecoder().decode(send.body)}`);
        return { sent: send.url };
      },
    }),
  );
  assert.deepEqual(sent, ['call_0 {"amount":"30.00"}']);
  assert.deepEqual(out, [{ sent: "https://payments.example/v1/refunds" }]);
  assert.deepEqual(ran, [], "the tool's own execute never runs");
});

test("TestHR329_a hold waits and runs only on the later allow, resubmitting the same action", async (t) => {
  const actionIds: string[] = [];
  const hta = holdThenAllow();
  const g = await gateway(t, (c, id, res) => {
    actionIds.push(id);
    hta(c, id, res);
  });
  const ran: unknown[] = [];
  const out = await runAgent(guardTools(appTools(ran), { client: g.client, connection: "payments", wait: 5 }));
  assert.deepEqual(out, [{ refunded: "30.00" }]);
  assert.equal(ran.length, 1);
  assert.equal(g.calls.length, 2, "authorize then one resubmission");
  assert.equal(actionIds[0], actionIds[1], "the resubmission carries the held action's id");
  assert.deepEqual(g.calls[0], g.calls[1], "the identical call");
});

test("TestHR329_a hold whose wait ends, or that is denied, never runs", async (t) => {
  const pending: Face = (_c, id, res) => res.end(decided(id, "hold", { wait: { handle: "h", state: "PENDING" } }));
  const g = await gateway(t, pending, { waitStates: ["PENDING"], block: 5000 });
  const ran: unknown[] = [];
  const out = await runAgent(guardTools(appTools(ran), { client: g.client, connection: "payments", wait: 0.3 }));
  assert.deepEqual(out, ["PantherClaw refused this call: hold_timeout"]);
  const d = await gateway(t, pending, { waitStates: ["DENIED"] });
  const out2 = await runAgent(guardTools(appTools(ran), { client: d.client, connection: "payments", wait: 5 }));
  assert.deepEqual(out2, ["PantherClaw refused this call: hold_declined"]);
  assert.deepEqual(ran, []);
});

test("TestHR329_an identical retry after a hold reuses the action id; changed input is a new decision", async (t) => {
  const actionIds: string[] = [];
  const g = await gateway(t, (_c, id, res) => {
    actionIds.push(id);
    res.end(decided(id, "hold", { wait: { handle: "h", state: "PENDING" } }));
  }, { waitStates: ["PENDING"], block: 5000 });
  const ran: unknown[] = [];
  const tools = guardTools(appTools(ran), { client: g.client, connection: "payments", wait: 0.2 });
  const exec = tools.create_refund?.execute as (i: unknown, o: unknown) => Promise<unknown>;
  assert.equal(await exec({ amount: "30.00", charge: "ch_1" }, { toolCallId: "a", messages: [] }), "PantherClaw refused this call: hold_timeout");
  // The same input with its members in another order is the same call.
  await exec({ charge: "ch_1", amount: "30.00" }, { toolCallId: "b", messages: [] });
  await exec({ amount: "31.00", charge: "ch_1" }, { toolCallId: "c", messages: [] });
  assert.equal(actionIds[0], actionIds[1]);
  assert.notEqual(actionIds[0], actionIds[2]);
  assert.deepEqual(ran, []);
  // Another guard is another wrapper instance: its own action ids.
  const other = guardTools(appTools(ran), { client: g.client, connection: "payments", wait: 0.2 });
  await (other.create_refund?.execute as (i: unknown, o: unknown) => Promise<unknown>)({ amount: "30.00", charge: "ch_1" }, { toolCallId: "d", messages: [] });
  assert.notEqual(actionIds[3], actionIds[0]);
});

test("TestHR328_toModelOutput never reads a refusal as the tool's output", async (t) => {
  const g = await gateway(t, deny);
  const tools = guardTools(
    {
      create_refund: tool({
        inputSchema: refundSchema,
        execute: async () => ({ refunded: true }),
        toModelOutput: ({ output }) => ({ type: "json", value: { ok: (output as { refunded: boolean }).refunded } }),
      }),
    },
    { client: g.client, connection: "payments" },
  );
  const m = model([{ name: "create_refund", input: { amount: "1", charge: "ch_1" } }]);
  await generateText({ model: m, tools, prompt: "refund", stopWhen: stepCountIs(3) });
  // What the model is sent in its second step: the refusal as text, not toModelOutput reading it.
  const seen = JSON.stringify(m.doGenerateCalls[1]?.prompt);
  assert.match(seen, /"type":"text","value":"PantherClaw refused this call: denied"/);
});

test("TestT150_the original execute is not reachable through the guarded tools", async (t) => {
  const g = await gateway(t, deny);
  const ran: unknown[] = [];
  const own = appTools(ran);
  const original = own.create_refund?.execute;
  const tools = guardTools(own, { client: g.client, connection: "payments" });
  const guarded = tools.create_refund as Record<string, unknown>;
  assert.notEqual(guarded.execute, original);
  for (const v of Object.values(guarded)) assert.notEqual(v, original);
  assert.notEqual(tools, own, "a new ToolSet");
  assert.equal(own.create_refund?.execute, original, "the application's own object is not changed");
  await runAgent(tools);
  assert.deepEqual(ran, []);
});

test("TestHR328_tools PantherClaw cannot govern are refused when wrapped", async (t) => {
  const g = await gateway(t, allow);
  const opts = { client: g.client, connection: "payments" };
  assert.throws(() => guardTools({ search: { type: "provider", isProviderExecuted: true, id: "openai.web_search" } }, opts), /runs at the model provider/);
  assert.throws(() => guardTools({ ask: tool({ inputSchema: refundSchema }) as never }, opts), /has no execute/);
  assert.throws(() => guardTools(appTools([]), { client: g.client, connection: "Not A Connection" }), /no connection can be named/);
  assert.throws(() => guardTools(appTools([]), { ...opts, onHold: "ask" as "wait" }), /onHold/);
  // A provider-defined tool the application executes is governed like any other.
  const ran: unknown[] = [];
  const pd = guardTools({ create_refund: { type: "provider", isProviderExecuted: false, id: "x.y", inputSchema: refundSchema, execute: async (i: unknown) => ran.push(i) } }, opts);
  await (pd.create_refund?.execute as (i: unknown, o: unknown) => Promise<unknown>)({ amount: "1", charge: "c" }, { toolCallId: "p", messages: [] });
  assert.equal(ran.length, 1);
});

test("TestHR328_a non-object input is refused without a request", async (t) => {
  const g = await gateway(t, allow);
  const ran: unknown[] = [];
  const tools = guardTools(appTools(ran), { client: g.client, connection: "payments" });
  const exec = tools.create_refund?.execute as (i: unknown, o: unknown) => Promise<unknown>;
  assert.equal(await exec("30.00", { toolCallId: "x", messages: [] }), "PantherClaw refused this call: cannot_decide");
  assert.equal(g.calls.length, 0);
  assert.deepEqual(ran, []);
});
