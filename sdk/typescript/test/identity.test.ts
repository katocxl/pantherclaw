// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The conformance runner over sdk/conformance: key files, workload tokens
// and proofs.

import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { checkProof } from "../src/check.ts";
import { ath, b64url, fromB64url, htu, keyOf, marshalKeyFile, parseTokenClaims, readKeyFile, signProof, thumbprint, WorkloadKey, writeKeyFile } from "../src/pap.ts";
import { load } from "./vectors.ts";

test("key_files.json", async () => {
  const tmp = await mkdtemp(join(tmpdir(), "pc-keyfiles-"));
  let i = 0;
  for (const c of (await load("key_files.json")).cases) {
    const path = join(tmp, `key${i++}.json`);
    await writeFile(path, c.file);
    if (c.reject) {
      await assert.rejects(readKeyFile(path), undefined, c.name);
      continue;
    }
    const kf = await readKeyFile(path);
    const key = await keyOf(kf);
    assert.equal(b64url(key.publicKey), c.public_x, c.name);
    assert.equal(key.jkt, c.jkt, c.name);
    assert.equal(marshalKeyFile(kf), c.file, c.name);
    assert.equal(kf.identifier, c.identifier, c.name);
    await assert.rejects(writeKeyFile(path, kf), undefined, `${c.name}: an existing key file was replaced`);
  }
});

test("workload_tokens.json", async () => {
  const f = await load("workload_tokens.json");
  const key = await WorkloadKey.fromSeed(fromB64url(f.workload_key.seed));
  for (const c of f.cases) {
    if (c.reject) {
      assert.throws(() => parseTokenClaims(c.token), undefined, c.name);
      continue;
    }
    const claims = parseTokenClaims(c.token);
    assert.equal(claims.cnf.jkt, key.jkt, c.name);
    assert.equal(claims.cnf.jkt, thumbprint(key.publicKey), c.name);
    assert.equal(ath(c.token), c.ath, c.name);
    assert.ok(claims.exp > c.valid_at, c.name);
  }
});

test("proofs.json", async () => {
  const f = await load("proofs.json");
  const key = await WorkloadKey.fromSeed(fromB64url(f.key.seed));
  for (const c of f.proofs) {
    const got = await signProof(key, { method: c.method, url: c.url, body: c.body, token: c.token, nonce: c.nonce, iat: c.iat, jti: c.jti });
    assert.equal(got, c.proof, c.name);
  }
  for (const c of f.checks) {
    const got = await checkProof(c.proof, { method: c.method, url: c.url, body: c.body, token: c.token }, c.now);
    assert.equal(got, c.answer, c.name);
  }
});

test("proofs.json htus: the htu PantherClaw's client signs for a URL", async () => {
  const f = await load("proofs.json");
  assert.ok(f.htus.length > 0);
  for (const c of f.htus) {
    if (c.reject) {
      assert.throws(() => htu(c.url), Error, c.url);
      continue;
    }
    assert.equal(htu(c.url), c.htu, c.url);
  }
});
