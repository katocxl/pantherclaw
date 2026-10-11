// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { type ActionClaims, MemoryStore, middleware, Refusal, type ReplayStore, Verifier } from "../src/verifier.ts";
import { load } from "./vectors.ts";

const failing: ReplayStore = { shared: true, use: async () => Promise.reject(new Error("unreachable")) };

// biome-ignore lint/suspicious/noExplicitAny: vector cases are untyped JSON
const matchOf = (c: any) => (cl: ActionClaims) => cl.pap.op === c.operation && cl.pap.target.type === c.target_type && cl.pap.target.id === c.target_id;

test("TestHR202_ConformanceActionTokens: every refusal code of the shared vectors", async () => {
  const f = await load("action_tokens.json");
  const jwks = async () => new Response(JSON.stringify(f.jwks), { status: 200 });
  const valid = f.cases[0];
  for (const c of f.cases) {
    const v = new Verifier({
      jwksUrl: "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json",
      issuer: c.issuer,
      audience: c.audience,
      // A store that began recording before any vector's token.
      store: c.store === "unavailable" ? failing : new MemoryStore(100, c.now - 3600),
      now: () => c.now,
      fetch: jwks as typeof fetch,
    });
    let got = "ok";
    try {
      await v.verify(c.token, c.body, matchOf(c));
      if (c.twice) await v.verify(c.token, c.body, matchOf(c));
    } catch (e) {
      assert.ok(e instanceof Refusal, `${c.name}: ${e}`);
      got = e.code;
    }
    assert.equal(got, c.expect, c.name);
    // Verify before insert: a refused request leaves the token unspent.
    if (c.then_valid) await v.verify(c.token, valid.body, matchOf(valid));
  }
});

test("TestHR202_the middleware refuses before the handler runs, and runs it once for the token", async (t) => {
  const f = await load("action_tokens.json");
  const c = f.cases[0];
  const v = new Verifier({
    jwksUrl: "http://127.0.0.1:9/jwks.json",
    issuer: c.issuer,
    audience: c.audience,
    store: new MemoryStore(100, c.now - 3600),
    now: () => c.now,
    fetch: (async () => new Response(JSON.stringify(f.jwks), { status: 200 })) as typeof fetch,
  });
  let ran = 0;
  const server = createServer(
    middleware(
      v,
      (_req, cl) => matchOf(c)(cl),
      (_req, res, { body }) => {
        ran++;
        assert.equal(Buffer.from(body).toString(), c.body);
        res.writeHead(201).end();
      },
      1024,
    ),
  );
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1/refunds`;
  const post = (body: string, token?: string) =>
    fetch(url, { method: "POST", body, headers: token ? { "PAP-Action": token } : {} }).then(async (r) => [r.status, await r.text()] as const);
  assert.deepEqual((await post(c.body))[0], 401);
  assert.equal((await post(`${c.body} `, c.token))[0], 401);
  assert.equal((await post("x".repeat(2048), c.token))[0], 413);
  assert.equal((await post(c.body, c.token))[0], 201);
  const [status, problem] = await post(c.body, c.token);
  assert.equal(status, 409);
  assert.match(problem, /"code":"replayed"/);
  assert.equal(ran, 1);
});

test("TestHR024_a memory store declares the verifier single-replica", async () => {
  const v = new Verifier({ jwksUrl: "https://x.test/jwks.json", issuer: "i", audience: "a", store: new MemoryStore() });
  assert.equal(v.singleReplica, true);
  assert.equal(new Verifier({ jwksUrl: "https://x.test/jwks.json", issuer: "i", audience: "a", store: failing }).singleReplica, false);
});

test("TestHR202_a full or restarted memory store refuses instead of forgetting", async () => {
  const full = new MemoryStore(1, 900);
  assert.equal(await full.use({ audience: "a", id: "a", issuedAt: 1000, now: 1000, until: 1065 }), true);
  await assert.rejects(full.use({ audience: "a", id: "b", issuedAt: 1000, now: 1065, until: 1130 }));
  assert.equal(await full.use({ audience: "a", id: "b", issuedAt: 1000, now: 1066, until: 1131 }), true);
  // A token issued before the start plus the skew may have been spent before a restart.
  const restarted = new MemoryStore(10, 2000);
  for (const issuedAt of [1900, 1995, 2000, 2004]) {
    await assert.rejects(restarted.use({ audience: "a", id: `c${issuedAt}`, issuedAt, now: 2010, until: issuedAt + 65 }));
  }
  assert.equal(await restarted.use({ audience: "a", id: "c2005", issuedAt: 2005, now: 2010, until: 2070 }), true);
  const now = Math.floor(Date.now() / 1000);
  await assert.rejects(new MemoryStore().use({ audience: "a", id: "d", issuedAt: now - 1, now, until: now + 60 }));
});

test("TestHR202_the memory store keys by audience and id", async () => {
  const m = new MemoryStore(10, 0);
  const use = (audience: string) => m.use({ audience, id: "jti", issuedAt: 100, now: 100, until: 160 });
  assert.deepEqual([await use("a"), await use("b"), await use("a")], [true, true, false]);
});

test("TestHR202_the JWKS comes over TLS, strictly parsed, one fetch at a time", async () => {
  for (const u of ["http://pantherclaw.example.test/jwks.json", "http://10.0.0.1/jwks.json", "https://u@pantherclaw.example.test/jwks.json"]) {
    assert.throws(() => new Verifier({ jwksUrl: u, issuer: "i", audience: "a", store: failing }), Error, u);
  }
  const f = await load("action_tokens.json");
  const c = f.cases[0];
  let fetches = 0;
  const slow = (body: string) =>
    (async () => {
      fetches++;
      await new Promise((r) => setTimeout(r, 50));
      return new Response(body, { status: 200 });
    }) as typeof fetch;
  const v = new Verifier({
    jwksUrl: "https://pantherclaw.example.test/jwks.json",
    issuer: c.issuer,
    audience: c.audience,
    store: new MemoryStore(100, c.now - 3600),
    now: () => c.now,
    fetch: slow(JSON.stringify(f.jwks)),
  });
  const all = await Promise.allSettled(Array.from({ length: 8 }, () => v.verify(c.token, c.body, () => false)));
  assert.ok(all.every((r) => r.status === "rejected" && r.reason instanceof Refusal && r.reason.code === "operation_mismatch"));
  assert.equal(fetches, 1);
  const keys = JSON.stringify(f.jwks).slice(1);
  const duplicated = new Verifier({
    jwksUrl: "https://pantherclaw.example.test/jwks.json",
    issuer: c.issuer,
    audience: c.audience,
    store: new MemoryStore(100, c.now - 3600),
    now: () => c.now,
    fetch: slow(`{"keys":[],${keys}`),
  });
  await assert.rejects(duplicated.verify(c.token, c.body, matchOf(c)), (e: unknown) => e instanceof Refusal && e.code === "store_unavailable");
});

test("TestHR202_an unknown kid refetches the JWKS at most once a minute; an unreachable JWKS refuses", async () => {
  const f = await load("action_tokens.json");
  const stranger = f.cases.find((c: { name: string }) => c.name.includes("not in the JWKS"));
  let fetches = 0;
  let now = stranger.now;
  const v = new Verifier({
    jwksUrl: "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json",
    issuer: stranger.issuer,
    audience: stranger.audience,
    store: new MemoryStore(100, stranger.now - 3600),
    now: () => now,
    fetch: (async () => {
      fetches++;
      return new Response(JSON.stringify(f.jwks), { status: 200 });
    }) as typeof fetch,
  });
  for (let i = 0; i < 5; i++) await assert.rejects(v.verify(stranger.token, stranger.body, () => true));
  assert.equal(fetches, 1);
  now += 61;
  await assert.rejects(v.verify(stranger.token, stranger.body, () => true));
  assert.equal(fetches, 2);
  const down = new Verifier({
    jwksUrl: "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json",
    issuer: stranger.issuer,
    audience: stranger.audience,
    store: new MemoryStore(100, stranger.now - 3600),
    now: () => stranger.now,
    fetch: (async () => new Response("", { status: 503 })) as typeof fetch,
  });
  await assert.rejects(down.verify(f.cases[0].token, f.cases[0].body, () => true), (e: unknown) => e instanceof Refusal && e.code === "store_unavailable" && e.status === 503);
});
