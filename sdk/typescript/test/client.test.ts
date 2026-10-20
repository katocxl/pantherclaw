// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { checkProof } from "../src/check.ts";
import { type CallClass, Client, classify, evaluate, newActionId, outboundRequest, readStream, retry, type ToolCall } from "../src/client.ts";
import { b64url, type KeyFile, keyOf, newKeyFile } from "../src/pap.ts";
import { load } from "./vectors.ts";

/** The vectors' sdk-channel action, canonical, under the action id `id`. */
async function sdkAction(id: string): Promise<{ ir: string; hash: string }> {
  const c = (await load("actionir.json")).cases.find((x: { name: string }) => x.name === "sdk channel through a connection");
  const canonical = String(c.canonical).replace('"action_id":"01920000-0000-7000-8000-000000000004"', `"action_id":"${id}"`);
  return { ir: b64url(Buffer.from(canonical)), hash: createHash("sha256").update(canonical).digest("hex") };
}

/** Answers `decision` for the request's action id, with the canonical action and its hash, as the face does. */
async function decided(req: IncomingMessage, res: ServerResponse, decision: string, extra: Record<string, unknown> = {}): Promise<void> {
  const id = String(req.headers["pc-action-id"]);
  const { ir, hash } = await sdkAction(id);
  res.end(JSON.stringify({ decision, action_id: id, action_hash: hash, action_ir: ir, coverage: "PARTIAL", mode: "enforce", ...extra }));
}

function heldThenAllowed(calls: { n: number }, deadline = new Date(Date.now() + 3_600_000).toISOString()): Handler {
  return (req, _body, res) => {
    calls.n++;
    if (calls.n > 1) return void allowed(req, res);
    void decided(req, res, "hold", { wait: { handle: "h", state: "PENDING", deadline } });
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
  opts: {
    requireNonce?: boolean;
    expireFirst?: boolean;
    wait?: (req: IncomingMessage, res: ServerResponse) => void;
    hook?: Handler;
    calls?: { n: number };
    builtins?: string[];
  } = {},
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
      } else if (req.url?.startsWith("/hook/") && opts.hook) {
        opts.hook(req, body, res);
      } else if (req.url?.startsWith("/sdk/")) {
        if (opts.calls) opts.calls.n++;
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
  return {
    client: new Client({ keyFile: { ...kf, server: base }, gateway: base, runId, timeoutMs: 1000, builtins: opts.builtins ?? ["Bash", "Read"] }),
    issued: () => issued,
  };
}

const refund: ToolCall = { tool: "mcp__payments__create_refund", server: "payments", input: { amount: "30.00", charge: "ch_1" }, tool_use_id: "toolu_01" };

function allowed(req: IncomingMessage, res: ServerResponse): Promise<void> {
  return decided(req, res, "allow");
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
    const r = await f.client.authorize("payments", refund, newActionId());
    assert.equal(r.outcome, "cannot_decide", `${name}: ${r.why}`);
  }
  const unreachable = new Client({ keyFile: { ...newKeyFile(), identifier, server: "http://127.0.0.1:9" }, gateway: "http://127.0.0.1:9", runId });
  assert.equal((await unreachable.authorize("payments", refund, newActionId())).outcome, "cannot_decide");
});

test("the client retries once for a nonce and once for an expired token, and sends the raw call", async (t) => {
  let sent = "";
  const f = await fake(
    t,
    (req, body, res) => {
      assert.deepEqual(JSON.parse(body), refund);
      assert.equal(req.url, "/sdk/payments");
      assert.equal(req.headers["pap-run-id"], runId);
      sent = String(req.headers["pc-action-id"]);
      void allowed(req, res);
    },
    { requireNonce: true, expireFirst: true },
  );
  const id = newActionId();
  const r = await f.client.authorize("payments", refund, id);
  assert.equal(r.outcome, "allow", r.why);
  assert.equal(sent, id);
  assert.equal(f.issued(), 2);
});

test("TestHR201_conformance answers of the /sdk contract", async () => {
  const f = await load("sdk_face.json");
  for (const a of f.answers) {
    const headers = new Headers(a.headers ?? {});
    const r = evaluate(a.status, a.body, a.class as CallClass, a.action_id, a.first_hash ?? "");
    const got = retry(a.status, headers) || r.outcome;
    assert.equal(got, a.outcome, `${a.name}: ${r.why}`);
    if (!a.send) {
      assert.equal(r.send, undefined, a.name);
      continue;
    }
    assert.ok(r.send, a.name);
    assert.equal(r.send.method, a.send.method, a.name);
    assert.equal(r.send.url, a.send.url, a.name);
    assert.deepEqual(r.send.headers, a.send.headers, a.name);
    assert.equal(Buffer.from(r.send.body).toString("utf8"), a.send.body, a.name);
    const req = outboundRequest(r.send);
    assert.equal(await req.text(), a.send.body, a.name);
    assert.equal(req.headers.get("pap-action"), a.send.headers["PAP-Action"], a.name);
  }
});

test("TestHR200_conformance calls: MCP tools to the connection named after their server, built-ins, and names never sent", async (t) => {
  const f = await load("sdk_face.json");
  let got: { path: string; body: unknown } | undefined;
  const g = await fake(
    t,
    (req, body, res) => {
      got = { path: String(req.url), body: JSON.parse(body) };
      res.end(JSON.stringify({ decision: "deny", reason: "recorded", mode: "enforce", coverage: "PARTIAL" }));
    },
    { builtins: f.builtins },
  );
  for (const c of f.calls) {
    const { cls, server } = classify(c.tool, f.servers, f.builtins);
    assert.equal(cls, c.class, c.name);
    got = undefined;
    const r = await g.client.authorize(f.connection, { tool: c.tool, server, input: c.input, tool_use_id: c.tool_use_id }, newActionId());
    if (cls === "refused") {
      assert.equal(got, undefined, c.name);
      assert.equal(r.outcome, "cannot_decide", c.name);
      continue;
    }
    assert.deepEqual(got, { path: c.path, body: c.body }, c.name);
  }
});

test("TestHR200_a server named like no connection is never sent", async (t) => {
  const calls = { n: 0 };
  const f = await fake(t, (_q, _b, res) => res.end(JSON.stringify({ decision: "allow", mode: "monitor", coverage: "OBSERVE_ONLY" })), { calls });
  for (const server of ["git__hub", "Payments", "-payments", "pay%2fments"]) {
    const call: ToolCall = { tool: `mcp__${server}__create_refund`, server, input: {}, tool_use_id: "toolu_01" };
    assert.equal((await f.client.authorize("payments", call, newActionId())).outcome, "cannot_decide", server);
  }
  const read: ToolCall = { tool: "Read", input: { file_path: "/etc/hosts" }, tool_use_id: "toolu_02" };
  for (const connection of ["Payments", "pay/ments", "", "payments-"]) {
    assert.equal((await f.client.authorize(connection, read, newActionId())).outcome, "cannot_decide", `a built-in recorded at "${connection}"`);
  }
  assert.equal(calls.n, 0);
});

test("TestHR200_an observe answer lets only a configured built-in run, and other names are never sent", async (t) => {
  const calls = { n: 0 };
  const f = await fake(t, (_q, _b, res) => res.end(JSON.stringify({ decision: "allow", mode: "monitor", coverage: "OBSERVE_ONLY" })), { calls });
  const read: ToolCall = { tool: "Read", input: { file_path: "/etc/hosts" }, tool_use_id: "toolu_02" };
  assert.equal((await f.client.authorize("payments", read, newActionId())).outcome, "observe");
  assert.equal((await f.client.authorize("payments", refund, newActionId())).outcome, "cannot_decide");
  const sent = calls.n;
  for (const tool of ["deploy", "bash", "mcp__payments__create_refund"]) {
    assert.equal((await f.client.authorize("payments", { tool, input: {}, tool_use_id: "toolu_03" }, newActionId())).outcome, "cannot_decide", tool);
  }
  assert.equal(calls.n, sent);
});

test("the client refuses plain http outside loopback", () => {
  const keyFile = { ...newKeyFile(), identifier };
  for (const u of ["http://pantherclaw.example.test", "http://10.0.0.1:8443", "https://user@pantherclaw.example.test"]) {
    assert.throws(() => new Client({ keyFile, server: "https://pantherclaw.example.test", gateway: u }), Error, u);
    assert.throws(() => new Client({ keyFile, server: u }), Error, u);
  }
  for (const u of ["https://pantherclaw.example.test", "http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080"]) {
    new Client({ keyFile, server: u, gateway: u });
  }
});

test("a shell command goes to the /hook face, and a hold there is a deny", async (t) => {
  let body = "";
  let held = false;
  const f = await fake(t, () => {}, {
    hook: (req, b, res) => {
      assert.equal(req.url, "/hook/local");
      assert.equal(req.headers["pap-run-id"], runId);
      body = b;
      res.end(JSON.stringify(held ? { decision: "deny", held: true, transaction_id: "t", mode: "enforce" } : { decision: "allow", mode: "enforce" }));
    },
  });
  const shell = { shell: "bash", command: "git push", cwd: "/repo", call: "toolu_04" } as const;
  assert.equal((await f.client.hook("local", shell)).outcome, "allow");
  assert.equal(body, '{"input":{"call":"toolu_04","command":"git push","cwd":"/repo","shell":"bash"},"tool":"shell"}');
  held = true;
  const r = await f.client.hook("local", shell);
  assert.deepEqual([r.outcome, r.held], ["deny", true]);
  const down = await fake(t, () => {}, { hook: (_q, _b, res) => res.writeHead(502).end() });
  assert.equal((await down.client.hook("local", shell)).outcome, "cannot_decide");
});

test("a wait event whose data never ends is refused", async () => {
  const line = `data: ${"x".repeat(1000)}\n`;
  const stream = new Blob(["event: state\n", line.repeat(100)]).stream();
  await assert.rejects(readStream(stream, () => true), /too long/);
});

test("a held call waits on the stream and is resubmitted with the same action id once ready", async (t) => {
  const calls = { n: 0 };
  const f = await fake(t, heldThenAllowed(calls), {
    wait: (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.end('event: state\ndata: {"handle":"h","state":"PENDING"}\n\n: heartbeat\n\nevent: state\ndata: {"handle":"h","state":"READY"}\n\n');
    },
  });
  const r = await f.client.authorizeAndWait("payments", refund, newActionId());
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
  const r = await f.client.authorizeAndWait("payments", refund, newActionId());
  assert.equal(r.outcome, "deny", r.why);
  assert.equal(calls.n, 1);
  assert.equal(polls, 2);
});

test("TestHR200_a wait past its deadline cannot decide", async (t) => {
  const f = await fake(t, heldThenAllowed({ n: 0 }), { wait: () => {} });
  const r = await f.client.authorizeAndWait("payments", refund, newActionId(), 300);
  assert.equal(r.outcome, "cannot_decide", r.why);
});

test("TestHR200_a wait ends at the hold's own deadline", async (t) => {
  const past = new Date(Date.now() - 4_500).toISOString();
  const f = await fake(t, heldThenAllowed({ n: 0 }, past), { wait: () => {} });
  const start = Date.now();
  const r = await f.client.authorizeAndWait("payments", refund, newActionId(), 60_000);
  assert.equal(r.outcome, "cannot_decide", r.why);
  assert.ok(Date.now() - start < 5_000, `waited ${Date.now() - start} ms`);
});

test("TestHR200_resubmissions are bounded", async (t) => {
  const calls = { n: 0 };
  const f = await fake(
    t,
    (req, _b, res) => {
      calls.n++;
      void decided(req, res, "hold", { wait: { handle: "h", state: "PENDING" } });
    },
    {
      wait: (_req, res) => {
        res.writeHead(200, { "Content-Type": "text/event-stream" });
        res.end('event: state\ndata: {"handle":"h","state":"READY"}\n\n');
      },
    },
  );
  const r = await f.client.authorizeAndWait("payments", refund, newActionId());
  assert.equal(r.outcome, "cannot_decide", r.why);
  assert.equal(calls.n, 4);
});

test("TestHR200_an aborted wait ends at once and resubmits nothing", async (t) => {
  const calls = { n: 0 };
  let release: () => void = () => {};
  const f = await fake(t, heldThenAllowed(calls), {
    wait: (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write('event: state\ndata: {"handle":"h","state":"PENDING"}\n\n');
      // The approval arrives after the abort: it must not be used up.
      release = () => res.end('event: state\ndata: {"handle":"h","state":"READY"}\n\n');
    },
  });
  const ac = new AbortController();
  setTimeout(() => ac.abort(), 100);
  const start = Date.now();
  const r = await f.client.authorizeAndWait("payments", refund, newActionId(), 60_000, ac.signal);
  assert.equal(r.outcome, "cannot_decide", r.why);
  assert.ok(Date.now() - start < 2_000, `waited ${Date.now() - start} ms`);
  release();
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(calls.n, 1, "no resubmission after the abort");
});
