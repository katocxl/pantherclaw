// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The fake gateway and the checks of the wrappers conformance group
// (sdk/conformance/wrappers.json, M14 D38): the gateway answers the n-th
// /sdk request with the case's n-th answer, rewritten for the PC-Action-Id
// it received, serves the case's wait on the SSE stream and the long-poll
// (a gated wait only once every call of the case made its first request),
// and issues unsigned workload tokens bound to the client's key.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Client, type KeyFile, keyOf, newKeyFile, type Outbound } from "../../../../sdk/typescript/src/index.ts";

const identifier =
  "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005";
const run = "01920000-0000-7000-8000-000000000003";

export interface Call {
  input: unknown;
  requests: number;
  resumes?: number;
  action_id?: "new" | "same";
  ran: boolean;
  code?: string;
  transaction?: string;
  refusal?: string;
  raises?: boolean;
  dispatched?: boolean;
}

export interface Case {
  name: string;
  options?: { wait?: number; raise_on_refusal?: boolean; observe_unmapped?: boolean; on_dispatch?: boolean };
  answers: string[];
  wait?: string;
  concurrent?: boolean;
  calls: Call[];
}

export interface Group {
  connection: string;
  tool: string;
  sdk_tool: string;
  path: string;
  parameters: string[];
  action_id: string;
  answers: Record<string, { status: number; body: string }>;
  waits: Record<string, { stream: string; long_poll: string }>;
  cases: Case[];
}

/** The members this runner knows: it fails on any other (the group's rule). */
const KNOWN = {
  group: ["format", "group", "description", "source", "connection", "tool", "sdk_tool", "path", "parameters", "action_id", "codes", "answers", "waits", "cases"],
  case: ["name", "options", "answers", "wait", "concurrent", "calls"],
  options: ["wait", "raise_on_refusal", "observe_unmapped", "on_dispatch"],
  call: ["input", "requests", "resumes", "action_id", "ran", "code", "transaction", "refusal", "raises", "dispatched"],
};

function known(what: keyof typeof KNOWN, v: object, at: string): void {
  for (const k of Object.keys(v)) assert.ok(KNOWN[what].includes(k), `${at}: the runner does not know the ${what} member ${k}`);
}

/** The group, read in place from the repository's sdk/conformance, every member checked as known. */
export async function load(): Promise<Group> {
  const g = JSON.parse(await readFile(new URL("../../../../sdk/conformance/wrappers.json", import.meta.url), "utf8")) as Group;
  known("group", g, "wrappers.json");
  for (const c of g.cases) {
    known("case", c, c.name);
    if (c.options) known("options", c.options, c.name);
    for (const call of c.calls) known("call", call, c.name);
  }
  return g;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

/** An answer rewritten for the action id the client sent (the group's rule). */
function rewrite(g: Group, body: string, actionId: string): string {
  if (body === "") return body;
  const a = JSON.parse(body) as Record<string, unknown>;
  if ("action_id" in a) a.action_id = actionId;
  if (typeof a.action_ir === "string") {
    const old = Buffer.from(a.action_ir, "base64url").toString();
    const ir = old.split(g.action_id).join(actionId);
    a.action_ir = Buffer.from(ir).toString("base64url");
    if (a.action_hash === sha256(old)) a.action_hash = sha256(ir);
  }
  return JSON.stringify(a);
}

/** A /sdk request the gateway received. */
export interface Received {
  path: string;
  actionId: string;
  body: { tool: string; server?: string; input: unknown; tool_use_id: string };
}

/** Serves one case; `client` is a core client for it. */
export async function caseGateway(t: { after: (fn: () => void) => void }, g: Group, c: Case) {
  const kf: KeyFile = { ...newKeyFile(), identifier };
  const jkt = (await keyOf(kf)).jkt;
  const received: Received[] = [];
  const wait = c.wait ? g.waits[c.wait] : undefined;
  // A gated wait answers only once every call made its first request.
  const gated = c.wait === "gated";
  const parked: (() => void)[] = [];
  const open = () => new Set(received.map((r) => r.body.tool_use_id)).size >= c.calls.length;
  const whenOpen = (fn: () => void) => {
    if (!gated || open()) fn();
    else parked.push(fn);
  };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    // No kept-alive sockets: a later test's server may get this port, and a pooled socket to a closed server fails the next request.
    res.setHeader("Connection", "close");
    let body = "";
    req.on("data", (d) => {
      body += d;
    });
    req.on("end", () => {
      if (req.url === "/pantherclaw.v1.WorkloadService/IssueToken") {
        const now = Math.floor(Date.now() / 1000);
        const claims = { aud: "pantherclaw-gateway", exp: now + 600, cnf: { jkt }, pap: { v: 1 } };
        const header = Buffer.from('{"alg":"EdDSA"}').toString("base64url");
        res.end(JSON.stringify({ workloadToken: `${header}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c2ln` }));
      } else if (req.url?.startsWith("/sdk/")) {
        const actionId = String(req.headers["pc-action-id"] ?? "");
        received.push({ path: req.url, actionId, body: JSON.parse(body) });
        const name = c.answers[received.length - 1];
        const a = name ? g.answers[name] : undefined;
        if (!a) res.writeHead(500).end();
        else res.writeHead(a.status, { "Content-Type": "application/json" }).end(rewrite(g, a.body, actionId));
        if (gated && open()) for (const fn of parked.splice(0)) fn();
      } else if (req.url?.startsWith("/v1/wait/") && wait) {
        whenOpen(() => res.writeHead(200, { "Content-Type": "text/event-stream" }).end(wait.stream));
      } else if (req.url === "/pantherclaw.v1.WorkloadService/Wait" && wait) {
        // A short pause, or a client waiting on a pending hold spins.
        whenOpen(() => setTimeout(() => res.writeHead(200, { "Content-Type": "application/json" }).end(wait.long_poll), 50));
      } else {
        res.writeHead(404).end();
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { client: new Client({ keyFile: { ...kf, server: base }, gateway: base, runId: run, timeoutMs: 10_000 }), received };
}

/** The send answer's dispatch: method, URL and decoded body. */
export function dispatchOf(g: Group): { method: string; url: string; body: string } {
  const d = (JSON.parse(g.answers.send?.body ?? "{}") as { dispatch: { method: string; url: string; body: string } }).dispatch;
  return { method: d.method, url: d.url, body: Buffer.from(d.body, "base64url").toString() };
}

/** What a wrapper's call returned or threw. */
export interface Result {
  out?: unknown;
  thrown?: unknown;
}

/** How a runner reads a wrapper's result: whether it is the tool's own, and a returned refusal's text. */
export interface Reader {
  ranValue: (out: unknown) => boolean;
  refusalText: (out: unknown) => string | undefined;
}

/** Whether one call's requests and result are what the call expects (the dispatch handler and the run are checked by the caller). */
function expected(g: Group, call: Call, reqs: Received[], r: Result, read: Reader): string {
  if (reqs.length !== call.requests) return `${reqs.length} /sdk requests, want ${call.requests}`;
  if (call.resumes !== undefined && Math.max(0, reqs.length - 1) !== call.resumes) return `${reqs.length - 1} resubmissions, want ${call.resumes}`;
  for (const q of reqs) {
    if (q.path !== g.path) return `request to ${q.path}`;
    try {
      assert.deepEqual({ ...q.body, tool_use_id: "" }, { tool: g.sdk_tool, server: g.connection, input: call.input, tool_use_id: "" });
    } catch {
      return `request body ${JSON.stringify(q.body)}`;
    }
  }
  if (reqs.length > 0 && new Set(reqs.map((q) => q.actionId)).size !== 1) return "more than one action id";
  if (call.ran) return r.thrown === undefined && read.ranValue(r.out) ? "" : `not run: ${JSON.stringify(r.out)} ${String(r.thrown ?? "")}`;
  if (call.dispatched) return r.thrown === undefined && r.out === "dispatched" ? "" : `not dispatched: ${JSON.stringify(r.out)}`;
  if (call.raises) {
    const e = r.thrown as { code?: string; transactionId?: string; message?: string; name?: string } | undefined;
    const ok = e?.name === "PantherClawRefusal" && e.code === call.code && e.transactionId === (call.transaction ?? "") && e.message === call.refusal;
    return ok ? "" : `raised ${String(r.thrown)}`;
  }
  return r.thrown === undefined && read.refusalText(r.out) === call.refusal ? "" : `returned ${JSON.stringify(r.out)} ${String(r.thrown ?? "")}`;
}

/**
 * Runs a case's calls (in order, or all at once when concurrent) through
 * `invoke` and checks every one; `ran` and `dispatched` record the tool's
 * runs and the dispatch handler's calls.
 */
export async function runCase(
  g: Group,
  c: Case,
  received: Received[],
  invoke: (input: unknown, i: number) => Promise<Result>,
  ran: unknown[],
  dispatched: { id: string; send: Outbound }[],
  read: Reader,
): Promise<void> {
  if (!c.concurrent) {
    let previous = "";
    const seen = new Set<string>();
    for (const [i, call] of c.calls.entries()) {
      const at = `call ${i}`;
      const [before, ranBefore, dispatchedBefore] = [received.length, ran.length, dispatched.length];
      const r = await invoke(structuredClone(call.input), i);
      const reqs = received.slice(before);
      assert.equal(expected(g, call, reqs, r, read), "", at);
      assert.deepEqual(ran.slice(ranBefore), call.ran ? [call.input] : [], `${at}: the tool's runs`);
      const d = dispatched.slice(dispatchedBefore);
      if (call.dispatched) {
        assert.equal(d.length, 1, `${at}: the handler is called once`);
        assert.equal(d[0]?.id, reqs[0]?.body.tool_use_id, `${at}: with the call's tool_use_id`);
        const send = d[0]?.send as Outbound;
        assert.deepEqual({ method: send.method, url: send.url, body: new TextDecoder().decode(send.body) }, dispatchOf(g), at);
      } else {
        assert.equal(d.length, 0, `${at}: no dispatch`);
      }
      if (reqs.length === 0) continue;
      const actionId = reqs[0]?.actionId as string;
      if (call.action_id === "same") assert.equal(actionId, previous, `${at}: the earlier unresolved call's action id`);
      else assert.ok(!seen.has(actionId), `${at}: a new action id`);
      seen.add(actionId);
      previous = actionId;
    }
    return;
  }
  // All at once: the outcomes match the expectations in some order; requests are told apart by tool_use_id.
  const results = await Promise.all(c.calls.map((call, i) => invoke(structuredClone(call.input), i)));
  const byCall = new Map<string, Received[]>();
  for (const q of received) byCall.set(q.body.tool_use_id, [...(byCall.get(q.body.tool_use_id) ?? []), q]);
  const groups = [...byCall.values()];
  assert.equal(groups.length, c.calls.length, "one tool_use_id per call");
  if (c.calls.some((x) => x.action_id === "same")) assert.equal(new Set(received.map((q) => q.actionId)).size, 1, "one action id for all");
  assert.equal(ran.length, c.calls.filter((x) => x.ran).length, "the tool ran once per allowed call");
  for (const input of ran) assert.ok(c.calls.some((x) => x.ran && JSON.stringify(x.input) === JSON.stringify(input)), "ran with an allowed call's input");
  assert.equal(dispatched.length, c.calls.filter((x) => x.dispatched).length, "one dispatch per dispatched call");
  const match = (k: number, usedR: Set<number>, usedG: Set<number>): boolean => {
    if (k === c.calls.length) return true;
    const call = c.calls[k] as Call;
    for (const [ri, r] of results.entries()) {
      if (usedR.has(ri)) continue;
      for (const [gi, reqs] of groups.entries()) {
        if (usedG.has(gi) || expected(g, call, reqs, r, read) !== "") continue;
        if (match(k + 1, new Set([...usedR, ri]), new Set([...usedG, gi]))) return true;
      }
    }
    return false;
  };
  assert.ok(match(0, new Set(), new Set()), `the outcomes ${JSON.stringify(results)} match the calls' expectations in no order`);
}
