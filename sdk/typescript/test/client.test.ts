// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { checkProof } from "../src/check.ts";
import { Client, evaluate, newActionId, retry, type ToolCall } from "../src/client.ts";
import { b64url, type KeyFile, keyOf, newKeyFile } from "../src/pap.ts";
import { load } from "./vectors.ts";

function heldThenAllowed(calls: { n: number }): Handler {
  return (req, _body, res) => {
    calls.n++;
    if (calls.n > 1) return allowed(req, res);
    const id = String(req.headers["pc-action-id"]);
    const hash = createHash("sha256").update(`{"action_id":"${id}"}`).digest("hex");
    res.end(JSON.stringify({ decision: "hold", action_id: id, action_hash: hash, coverage: "PARTIAL", mode: "enforce", wait: { handle: "h", state: "PENDING" } }));
  };
}

const runId = "01920000-0000-7000-8000-000000000003";
const nonce = "Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ";
const identifier =
  "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005";

type Handler = (req: IncomingMessage, body: string, res: ServerResponse) => void;

/** A PantherClaw server and gateway in one: unsigned tokens, every proof checked with the SDK's checker. */
async function fake(
  t: { after: (fn: () => void) => void },
  sdk: Handler,
  opts: { requireNonce?: boolean; expireFirst?: boolean; wait?: (req: IncomingMessage, res: ServerResponse) => void } = {},
) {
  const kf: KeyFile = { ...newKeyFile(), identifier };
  const jkt = (await keyOf(kf)).jkt;
  let issued = 0;
  let expireFirst = opts.expireFirst ?? false;
  const token = () => {
    const now = Math.floor(Date.now() / 1000);
    const claims = { iss: "x", sub: identifier, aud: "pantherclaw-gateway", iat: now, nbf: now, exp: now + 600, jti: "j", cnf: { jkt }, pap: { v: 1, org: "o", env: "e", att_lvl: 1 } };
    return `${b64url(Buffer.from('{"alg":"EdDSA","kid":"k","typ":"pap-wt+jwt"}'))}.${b64url(Buffer.from(JSON.stringify(claims)))}.c2ln`;
  };
  const server: Server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", async () => {
      const auth = String(req.headers.authorization ?? "");
      const tok = auth.startsWith("PAP ") ? auth.slice(4) : "";
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}${req.url}`;
      let answer = await checkProof(String(req.headers["pap-proof"] ?? ""), { method: req.method ?? "", url, body, token: tok }, Math.floor(Date.now() / 1000));
      if (answer === "use_nonce" && !opts.requireNonce) answer = "ok";
      res.setHeader("PAP-Nonce", nonce);
      if (answer !== "ok") {
        res.writeHead(401, { "PAP-Error": answer }).end();
        return;
      }
      if (req.url === "/pantherclaw.v1.WorkloadService/IssueToken") {
        assert.equal(tok, "", "token issuance uses a key-only proof");
        issued++;
        res.end(JSON.stringify({ workloadToken: token(), attestationLevel: 1 }));
      } else if (req.url?.startsWith("/sdk/")) {
        if (expireFirst) {
          expireFirst = false;
          res.writeHead(401, { "PAP-Error": "token_expired" }).end();
          return;
        }
        sdk(req, body, res);
      } else if (opts.wait && (req.url?.startsWith("/v1/wait/") || req.url === "/pantherclaw.v1.WorkloadService/Wait")) {
        opts.wait(req, res);
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
  return { client: new Client({ keyFile: { ...kf, server: base }, gateway: base, runId, timeoutMs: 1000 }), issued: () => issued };
}

const refund: ToolCall = { tool: "mcp__payments__create_refund", server: "payments", input: { amount: "30.00", charge: "ch_1" }, tool_use_id: "toolu_01" };

function allowed(req: IncomingMessage, res: ServerResponse): void {
  const id = String(req.headers["pc-action-id"]);
  const hash = createHash("sha256").update(`{"action_id":"${id}"}`).digest("hex");
  res.end(JSON.stringify({ decision: "allow", action_id: id, action_hash: hash, coverage: "PARTIAL", mode: "enforce" }));
}

test("TestHR200_fails closed when PantherClaw cannot decide", async (t) => {
  const answers: Record<string, Handler> = {
    "a gateway error": (_q, _b, res) => res.writeHead(502).end(),
    "not JSON": (_q, _b, res) => res.end("<html>"),
    "an empty body": (_q, _b, res) => res.end(),
    "too slow": () => {},
  };
  for (const [name, h] of Object.entries(answers)) {
    const f = await fake(t, h);
    const r = await f.client.authorize("local", refund, newActionId());
    assert.equal(r.outcome, "cannot_decide", `${name}: ${r.why}`);
  }
  const unreachable = new Client({ keyFile: { ...newKeyFile(), identifier, server: "http://127.0.0.1:9" }, gateway: "http://127.0.0.1:9", runId });
  assert.equal((await unreachable.authorize("local", refund, newActionId())).outcome, "cannot_decide");
});

test("the client retries once for a nonce and once for an expired token, and sends the raw call", async (t) => {
  let sent = "";
  const f = await fake(
    t,
    (req, body, res) => {
      assert.deepEqual(JSON.parse(body), refund);
      assert.equal(req.url, "/sdk/local");
      assert.equal(req.headers["pap-run-id"], runId);
      sent = String(req.headers["pc-action-id"]);
      allowed(req, res);
    },
    { requireNonce: true, expireFirst: true },
  );
  const id = newActionId();
  const r = await f.client.authorize("local", refund, id);
  assert.equal(r.outcome, "allow", r.why);
  assert.equal(sent, id);
  assert.equal(f.issued(), 2);
});

test("TestHR201_conformance answers of the /sdk contract", async () => {
  const f = await load("sdk_face.json");
  for (const a of f.answers) {
    const headers = new Headers(a.headers ?? {});
    const got = retry(a.status, headers) || evaluate(a.status, a.body, a.action_id, a.first_hash ?? "").outcome;
    assert.equal(got, a.outcome, a.name);
  }
});

test("a held call waits on the stream and is resubmitted with the same action id once ready", async (t) => {
  const calls = { n: 0 };
  const f = await fake(t, heldThenAllowed(calls), {
    wait: (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.end('event: state\ndata: {"handle":"h","state":"PENDING"}\n\n: heartbeat\n\nevent: state\ndata: {"handle":"h","state":"READY"}\n\n');
    },
  });
  const r = await f.client.authorizeAndWait("local", refund, newActionId());
  assert.equal(r.outcome, "allow", r.why);
  assert.equal(calls.n, 2);
});

test("without the stream the client long-polls, and a declined hold denies", async (t) => {
  const calls = { n: 0 };
  let polls = 0;
  const f = await fake(t, heldThenAllowed(calls), {
    wait: (req, res) => {
      if (req.method === "GET") return void res.writeHead(404).end();
      polls++;
      const state = polls > 1 ? "WAIT_STATE_DECLINED" : "WAIT_STATE_PENDING";
      res.end(JSON.stringify({ wait: { handle: "h", state, code: "APPROVAL_DECLINED" }, timedOut: polls === 1 }));
    },
  });
  const r = await f.client.authorizeAndWait("local", refund, newActionId());
  assert.equal(r.outcome, "deny", r.why);
  assert.equal(calls.n, 1);
  assert.equal(polls, 2);
});

test("TestHR200_a wait past its deadline cannot decide", async (t) => {
  const f = await fake(t, heldThenAllowed({ n: 0 }), { wait: () => {} });
  const r = await f.client.authorizeAndWait("local", refund, newActionId(), 300);
  assert.equal(r.outcome, "cannot_decide", r.why);
});
