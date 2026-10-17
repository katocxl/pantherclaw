// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The fake gateway of the wrappers conformance group
// (sdk/conformance/wrappers.json, M14 D38): it answers the n-th /sdk
// request with the case's n-th answer, rewritten for the PC-Action-Id it
// received, serves the case's wait on the SSE stream and the long-poll, and
// issues unsigned workload tokens bound to the client's key.

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Client, type KeyFile, keyOf, newKeyFile } from "../../../../sdk/typescript/src/index.ts";

const identifier =
  "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005";
const run = "01920000-0000-7000-8000-000000000003";

export interface Call {
  input: Record<string, unknown>;
  requests: number;
  action_id: "new" | "same";
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
  calls: Call[];
}

export interface Group {
  connection: string;
  tool: string;
  sdk_tool: string;
  path: string;
  action_id: string;
  answers: Record<string, { status: number; body: string }>;
  waits: Record<string, { stream: string; long_poll: string }>;
  cases: Case[];
}

/** The group, read from the repository's sdk/conformance. */
export async function load(): Promise<Group> {
  return JSON.parse(await readFile(new URL("../../../../sdk/conformance/wrappers.json", import.meta.url), "utf8"));
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
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
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
        if (!a) {
          res.writeHead(500).end();
          return;
        }
        res.writeHead(a.status, { "Content-Type": "application/json" }).end(rewrite(g, a.body, actionId));
      } else if (req.url?.startsWith("/v1/wait/") && wait) {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.end(wait.stream);
      } else if (req.url === "/pantherclaw.v1.WorkloadService/Wait" && wait) {
        // A short pause, or a client waiting on a pending hold spins.
        setTimeout(() => res.writeHead(200, { "Content-Type": "application/json" }).end(wait.long_poll), 50);
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
  return { client: new Client({ keyFile: { ...kf, server: base }, gateway: base, runId: run, timeoutMs: 2000 }), received };
}

/** The send answer's dispatch: method, URL and decoded body. */
export function dispatchOf(g: Group): { method: string; url: string; body: string } {
  const d = (JSON.parse(g.answers.send?.body ?? "{}") as { dispatch: { method: string; url: string; body: string } }).dispatch;
  return { method: d.method, url: d.url, body: Buffer.from(d.body, "base64url").toString() };
}
