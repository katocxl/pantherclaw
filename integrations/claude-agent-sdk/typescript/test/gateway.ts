// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// A fake PantherClaw for the integration's tests: the server and gateway in
// one, with unsigned workload tokens, the /sdk face of connection
// "payments", the /hook face of the local connection "local" and the wait
// stream.

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { Client, type KeyFile, keyOf, newKeyFile } from "../../../../sdk/typescript/src/index.ts";
import { load } from "../../../../sdk/typescript/test/vectors.ts";
import { BUILTIN_TOOLS } from "../src/index.ts";

export const identifier =
  "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005";
export const run = "01920000-0000-7000-8000-000000000003";

export type Face = (call: Record<string, unknown>, actionId: string, res: ServerResponse) => void;
export type HookFace = (body: Record<string, unknown>, res: ServerResponse) => void;

const sdkAction: string = (await load("actionir.json")).cases.find((c: { name: string }) => c.name === "sdk channel through a connection").canonical;

/** The face's answer for an action id: the canonical sdk-channel action and its hash. */
export function decided(id: string, decision: string, extra: Record<string, unknown> = {}): string {
  const act = sdkAction.replace('"action_id":"01920000-0000-7000-8000-000000000004"', `"action_id":"${id}"`);
  const hash = createHash("sha256").update(act).digest("hex");
  return JSON.stringify({ decision, action_id: id, action_hash: hash, action_ir: Buffer.from(act).toString("base64url"), coverage: "PARTIAL", mode: "enforce", ...extra });
}

/** A PantherClaw server and gateway in one: unsigned tokens, the /sdk face of connection "payments", the /hook face of "local" and the wait stream. */
export async function gateway(t: { after: (fn: () => void) => void }, face: Face, opts: { waitStates?: string[]; hook?: HookFace; block?: number; after?: string[] } = {}) {
  const kf: KeyFile = { ...newKeyFile(), identifier };
  const jkt = (await keyOf(kf)).jkt;
  const calls: Record<string, unknown>[] = [];
  /** The /sdk path of each call, in order. */
  const paths: string[] = [];
  /** When the gateway received each /sdk call (ms, Date.now()). */
  const callTimes: number[] = [];
  const hooks: Record<string, unknown>[] = [];
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
        const header = Buffer.from('{"alg":"EdDSA"}').toString("base64url");
        res.end(JSON.stringify({ workloadToken: `${header}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.c2ln` }));
      } else if (req.url?.startsWith("/sdk/")) {
        const call = JSON.parse(body);
        calls.push(call);
        paths.push(req.url);
        callTimes.push(Date.now());
        face(call, String(req.headers["pc-action-id"]), res);
      } else if (req.url === "/hook/local" && opts.hook) {
        const call = JSON.parse(body);
        hooks.push(call);
        opts.hook(call, res);
      } else if (req.url?.startsWith("/v1/wait/")) {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        for (const s of opts.waitStates ?? ["READY"]) res.write(`event: state\ndata: ${JSON.stringify({ handle: "h", state: s })}\n\n`);
        // A hold that stays pending: the stream stays open for `block` ms, then says `after` (e.g. the hold's denial).
        const finish = () => {
          for (const s of opts.after ?? []) res.write(`event: state\ndata: ${JSON.stringify({ handle: "h", state: s })}\n\n`);
          res.end();
        };
        if (opts.block) setTimeout(finish, opts.block);
        else finish();
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
  return { client: new Client({ keyFile: { ...kf, server: base }, gateway: base, runId: run, timeoutMs: 2000, builtins: BUILTIN_TOOLS }), calls, callTimes, paths, hooks, base };
}

export const allow: Face = (_c, id, res) => res.end(decided(id, "allow"));
export const deny: Face = (_c, id, res) => res.end(decided(id, "deny", { error_class: "policy_denied", reason: "denied" }));
export const observe: Face = (_c, _id, res) => res.end(JSON.stringify({ decision: "allow", coverage: "OBSERVE_ONLY", mode: "monitor" }));
export const unmapped: Face = (_c, id, res) => res.end(JSON.stringify({ decision: "deny", code: "unknown_tool", action_id: id, coverage: "PARTIAL", mode: "enforce" }));
export function holdThenAllow(): Face {
  let n = 0;
  return (c, id, res) => {
    if (n++ === 0) res.end(decided(id, "hold", { wait: { handle: "h", state: "PENDING" } }));
    else allow(c, id, res);
  };
}
