// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { test } from "node:test";
import { type ActionClaims, MemoryStore, Refusal, type ReplayStore, Verifier } from "../src/verifier.ts";
import { load } from "./vectors.ts";

const failing: ReplayStore = { shared: true, use: async () => Promise.reject(new Error("unreachable")) };

test("TestHR202_ConformanceActionTokens: every refusal code of the shared vectors", async () => {
  const f = await load("action_tokens.json");
  const jwks = async () => new Response(JSON.stringify(f.jwks), { status: 200 });
  for (const c of f.cases) {
    const v = new Verifier({
      jwksUrl: "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json",
      issuer: c.issuer,
      audience: c.audience,
      store: c.store === "unavailable" ? failing : new MemoryStore(),
      now: () => c.now,
      fetch: jwks as typeof fetch,
    });
    const match = (cl: ActionClaims) => cl.pap.op === c.operation && cl.pap.target.type === c.target_type && cl.pap.target.id === c.target_id;
    let got = "ok";
    try {
      await v.verify(c.token, c.body, match);
      if (c.twice) await v.verify(c.token, c.body, match);
    } catch (e) {
      assert.ok(e instanceof Refusal, `${c.name}: ${e}`);
      got = e.code;
    }
    assert.equal(got, c.expect, c.name);
  }
});

test("TestHR024_a memory store declares the verifier single-replica", async () => {
  const v = new Verifier({ jwksUrl: "https://x.test/jwks.json", issuer: "i", audience: "a", store: new MemoryStore() });
  assert.equal(v.singleReplica, true);
  assert.equal(new Verifier({ jwksUrl: "https://x.test/jwks.json", issuer: "i", audience: "a", store: failing }).singleReplica, false);
});

test("TestHR202_a full or restarted memory store refuses instead of forgetting", async () => {
  const full = new MemoryStore(1, 1000);
  assert.equal(await full.use({ id: "a", issuedAt: 1000, now: 1000, until: 1065 }), true);
  await assert.rejects(full.use({ id: "b", issuedAt: 1000, now: 1065, until: 1130 }));
  assert.equal(await full.use({ id: "b", issuedAt: 1000, now: 1066, until: 1131 }), true);
  await assert.rejects(new MemoryStore(10, 2000).use({ id: "c", issuedAt: 1900, now: 2000, until: 1965 }));
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
    store: new MemoryStore(),
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
    store: new MemoryStore(),
    now: () => stranger.now,
    fetch: (async () => new Response("", { status: 503 })) as typeof fetch,
  });
  await assert.rejects(down.verify(f.cases[0].token, f.cases[0].body, () => true), (e: unknown) => e instanceof Refusal && e.code === "store_unavailable" && e.status === 503);
});
