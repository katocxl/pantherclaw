// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { Client, type KeyFile, keyOf, newKeyFile } from "../../../../sdk/typescript/src/index.ts";
import { type HookOutput, PantherClaw, type PantherClawOptions, type PreToolUseInput } from "../src/index.ts";

const identifier =
  "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005";
const run = "01920000-0000-7000-8000-000000000003";

type Face = (call: Record<string, unknown>, actionId: string, res: ServerResponse) => void;

/** A PantherClaw server and gateway in one, serving the /sdk contract, unsigned tokens and the wait stream. */
async function gateway(t: { after: (fn: () => void) => void }, face: Face, waitStates: string[] = ["READY"]) {
  const kf: KeyFile = { ...newKeyFile(), identifier };
  const jkt = (await keyOf(kf)).jkt;
  const calls: Record<string, unknown>[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", () => {
      res.setHeader("PAP-Nonce", "Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ");
      if (req.url === "/pantherclaw.v1.WorkloadService/IssueToken") {
        const now = Math.floor(Date.now() / 1000);
        const claims = { aud: "pantherclaw-gateway", exp: now + 600, cnf: { jkt }, pap: { v: 1 } };
        const token = `eyJhbGciOiJFZERTQSJ9.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c2ln`;
        res.end(JSON.stringify({ workloadToken: token }));
      } else if (req.url === "/sdk/local") {
        const call = JSON.parse(body);
        calls.push(call);
        face(call, String(req.headers["pc-action-id"]), res);
      } else if (req.url?.startsWith("/v1/wait/")) {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        for (const s of waitStates) res.write(`event: state\ndata: ${JSON.stringify({ handle: "h", state: s })}\n\n`);
        res.end();
      } else {
        res.writeHead(404).end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { client: new Client({ keyFile: { ...kf, server: base }, gateway: base, runId: run, timeoutMs: 2000 }), calls };
}

function hash(actionId: string): string {
  return createHash("sha256").update(`{"action_id":"${actionId}"}`).digest("hex");
}

const allow: Face = (_c, id, res) => res.end(JSON.stringify({ decision: "allow", action_id: id, action_hash: hash(id), coverage: "PARTIAL", mode: "enforce" }));
const deny: Face = (_c, id, res) => res.end(JSON.stringify({ decision: "deny", action_id: id, coverage: "PARTIAL", mode: "enforce", reason: "denied" }));
const observe: Face = (_c, _id, res) => res.end(JSON.stringify({ decision: "allow", coverage: "OBSERVE_ONLY", mode: "monitor" }));
const unmapped: Face = (_c, id, res) => res.end(JSON.stringify({ decision: "deny", code: "unknown_tool", action_id: id, coverage: "PARTIAL", mode: "enforce" }));
function holdThenAllow(): Face {
  let n = 0;
  return (c, id, res) => {
    if (n++ === 0) {
      res.end(JSON.stringify({ decision: "hold", action_id: id, action_hash: hash(id), coverage: "PARTIAL", mode: "enforce", wait: { handle: "h", state: "PENDING" } }));
    } else {
      allow(c, id, res);
    }
  };
}

const refund = (mode = "default", id = "toolu_01"): PreToolUseInput => ({
  hook_event_name: "PreToolUse",
  tool_name: "mcp__payments__create_refund",
  tool_input: { amount: "30.00", charge: "ch_1" },
  tool_use_id: id,
  cwd: "/home/dev/repo",
  permission_mode: mode,
});

const decisionOf = (o: HookOutput) => o.hookSpecificOutput?.permissionDecision ?? "none";

function integration(client: Client, extra: Partial<PantherClawOptions> = {}) {
  return new PantherClaw({ client, connection: "local", mcpServers: ["payments"], deadlineMs: 1000, waitMs: 2000, ...extra });
}

test("TestHR200_the hook denies when PantherClaw cannot decide", async (t) => {
  const faces: Record<string, Face> = {
    "a gateway error": (_c, _id, res) => res.writeHead(502).end(),
    "a malformed answer": (_c, _id, res) => res.end("{"),
    "no answer in time": () => {},
  };
  for (const [name, face] of Object.entries(faces)) {
    const g = await gateway(t, face);
    assert.equal(decisionOf(await integration(g.client).preToolUse(refund())), "deny", name);
  }
  const down = new Client({ keyFile: { ...newKeyFile(), identifier, server: "http://127.0.0.1:9" }, gateway: "http://127.0.0.1:9", runId: run });
  assert.equal(decisionOf(await integration(down).preToolUse(refund())), "deny", "unreachable");
  const g = await gateway(t, allow);
  const broken = integration(g.client);
  // biome-ignore lint/suspicious/noExplicitAny: a thrown error inside the hook body
  (broken as any).decide = () => Promise.reject(new Error("boom"));
  assert.equal(decisionOf(await broken.preToolUse(refund())), "deny", "a thrown error");
});

test("TestHR200_PreToolUse decides in every permission mode, bypass included", async (t) => {
  for (const mode of ["default", "acceptEdits", "plan", "bypassPermissions"]) {
    const g = await gateway(t, deny);
    assert.equal(decisionOf(await integration(g.client).preToolUse(refund(mode))), "deny", mode);
    const a = await gateway(t, allow);
    assert.equal(decisionOf(await integration(a.client).preToolUse(refund(mode))), "allow", mode);
  }
});

test("TestHR200_a hold never runs without a later allow", async (t) => {
  // A hold is denied, never asked: without PantherClaw's canUseTool, in bypassPermissions or dontAsk, or under an allow rule.
  const cases: [string, (p: PantherClaw) => void][] = [
    ["no canUseTool", () => {}],
    ["bypassPermissions", (p) => p.options({ permissionMode: "bypassPermissions" })],
    ["dontAsk", (p) => p.options({ permissionMode: "dontAsk" })],
    ["an allow rule", (p) => p.options({ permissionMode: "default", allowedTools: ["mcp__payments__create_refund"] })],
  ];
  for (const [name, setup] of cases) {
    const g = await gateway(t, holdThenAllow());
    const p = integration(g.client);
    setup(p);
    const mode = name === "bypassPermissions" || name === "dontAsk" ? name : "default";
    assert.equal(decisionOf(await p.preToolUse(refund(mode))), "deny", name);
  }
  // Otherwise the hold is asked; canUseTool waits and allows only after PantherClaw's allow, with the original input.
  const g = await gateway(t, holdThenAllow());
  const opts = integration(g.client).options({ permissionMode: "default", mcpServers: { payments: {} } });
  const hook = opts.hooks?.PreToolUse?.at(-1)?.hooks[0];
  assert.ok(hook && opts.canUseTool);
  assert.equal(decisionOf(await hook(refund("default", "toolu_09"))), "ask");
  const r = await opts.canUseTool("mcp__payments__create_refund", { amount: "999.00", charge: "ch_1" }, { signal: new AbortController().signal, toolUseID: "toolu_09" });
  assert.deepEqual(r, { behavior: "allow", updatedInput: { amount: "30.00", charge: "ch_1" } });
  assert.equal(g.calls.length, 2, "the identical call was resubmitted once");
});

test("TestHR200_canUseTool waits only on holds and denies at its deadline", async (t) => {
  const g = await gateway(t, holdThenAllow(), ["PENDING"]);
  const app = async () => ({ behavior: "deny" as const, message: "the application's own answer" });
  const p = integration(g.client, { waitMs: 300 });
  const opts = p.options({ permissionMode: "default", canUseTool: app });
  const can = opts.canUseTool;
  assert.ok(can);
  const other = await can("Write", { file_path: "x" }, { signal: new AbortController().signal, toolUseID: "toolu_other" });
  assert.deepEqual(other, { behavior: "deny", message: "the application's own answer" });
  assert.equal(decisionOf(await p.preToolUse(refund("default", "toolu_10"))), "ask");
  const r = await can("mcp__payments__create_refund", {}, { signal: new AbortController().signal, toolUseID: "toolu_10" });
  assert.equal(r.behavior, "deny");
});

test("callers must pass permissionMode explicitly", async (t) => {
  const g = await gateway(t, allow);
  assert.throws(() => integration(g.client).options({}), /permissionMode/);
});

test("Bash and PowerShell go to the /sdk face with their working directory", async (t) => {
  const g = await gateway(t, allow);
  const input: PreToolUseInput = { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" }, tool_use_id: "toolu_11", cwd: "/repo" };
  assert.equal(decisionOf(await integration(g.client).preToolUse(input)), "allow");
  assert.deepEqual(g.calls[0], { tool: "Bash", input: { command: "ls" }, tool_use_id: "toolu_11", cwd: "/repo" });
});

test("unmapped built-ins are observed, not blocked; unmapped other tools are denied unless observeUnmapped", async (t) => {
  const o = await gateway(t, observe);
  const read: PreToolUseInput = { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/etc/hosts" }, tool_use_id: "toolu_12" };
  assert.equal(decisionOf(await integration(o.client).preToolUse(read)), "none");
  const u = await gateway(t, unmapped);
  assert.equal(decisionOf(await integration(u.client).preToolUse(refund())), "deny");
  assert.equal(decisionOf(await integration(u.client, { observeUnmapped: true }).preToolUse(refund())), "none");
  const other: PreToolUseInput = { hook_event_name: "PreToolUse", tool_name: "mcp__unknown__run", tool_input: {}, tool_use_id: "toolu_13" };
  assert.equal(decisionOf(await integration(u.client).preToolUse(other)), "deny", "an unconfigured MCP server");
});

test("TestT080_a forged answer or a changed resubmission never runs the tool", async (t) => {
  const forged: Face = (_c, id, res) =>
    res.end(JSON.stringify({ decision: "allow", action_id: id, action_hash: hash("another action"), action_ir: Buffer.from("{}").toString("base64url"), coverage: "PARTIAL", mode: "enforce" }));
  const g = await gateway(t, forged);
  assert.equal(decisionOf(await integration(g.client).preToolUse(refund())), "deny");
  const unlabeled: Face = (_c, id, res) => res.end(JSON.stringify({ decision: "allow", action_id: id, action_hash: hash(id), mode: "enforce" }));
  const u = await gateway(t, unlabeled);
  assert.equal(decisionOf(await integration(u.client).preToolUse(refund())), "deny");
});
