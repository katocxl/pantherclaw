// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { stat } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { inspect } from "node:util";
import { checkProof } from "../src/check.ts";
import { b64url, bodyHash, htu, keyOf, marshalKeyFile, newKeyFile, readKeyFile, signProof, writeKeyFile } from "../src/pap.ts";

test("htu keeps scheme, host and path only", () => {
  assert.equal(htu("https://gateway.example.test/sdk/local?debug=1#x"), "https://gateway.example.test/sdk/local");
  assert.throws(() => htu("https://user:pw@gateway.example.test/"));
  assert.throws(() => htu("ftp://gateway.example.test/"));
});

test("a fresh proof passes PantherClaw's checks for exactly its request, once a nonce is in it", async () => {
  const key = await keyOf(newKeyFile());
  const now = Math.floor(Date.now() / 1000);
  const req = { method: "POST", url: "https://gateway.example.test/sdk/local", body: '{"tool":"Read"}' };
  const proof = await signProof(key, { ...req, url: `${req.url}?q=1`, nonce: "Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ", iat: now });
  assert.equal(await checkProof(proof, req, now), "ok");
  assert.equal(await checkProof(proof, { ...req, body: "{}" }, now), "body_hash_mismatch");
  assert.equal(await checkProof(await signProof(key, { ...req, iat: now }), req, now), "use_nonce");
});

test("a new key file is written owner-only and read back", async () => {
  const path = join(await mkdtemp(join(tmpdir(), "pc-key-")), "key.json");
  const kf = { ...newKeyFile(), identifier: "pc:org/x/agent/y/inst/z" };
  await writeKeyFile(path, kf);
  assert.deepEqual(await readKeyFile(path), kf);
  if (process.platform !== "win32") assert.equal((await stat(path)).mode & 0o777, 0o600);
});

test("a key file never prints its seed", () => {
  const kf = newKeyFile();
  kf.identifier = "pc:org/o/agent/a/inst/i";
  for (const out of [inspect(kf), JSON.stringify(kf), JSON.stringify({ key: kf })]) {
    assert.ok(!out.includes(kf.private_key) && out.includes("pc:org/o/agent/a/inst/i"), out);
  }
  assert.ok(marshalKeyFile(kf).includes(kf.private_key));
});

test("a proof whose payload is not an object, or whose iat is not an integer, is invalid", async () => {
  const kf = newKeyFile();
  const key = await keyOf(kf);
  const header = `{"alg":"EdDSA","jwk":{"crv":"Ed25519","kty":"OKP","x":"${b64url(key.publicKey)}"},"typ":"pap-proof+jwt"}`;
  const url = "https://gateway.example.test/sdk/payments";
  const signed = async (claims: string) => {
    const input = `${b64url(new TextEncoder().encode(header))}.${b64url(new TextEncoder().encode(claims))}`;
    return `${input}.${b64url(await key.sign(new TextEncoder().encode(input)))}`;
  };
  const claims = (iat: string) =>
    `{"htm":"POST","htu":"${url}","iat":${iat},"jti":"abcdefghijklmnopqrstuvwx","bh":"${bodyHash("")}","nonce":"abcdefghijklmnopqrstuvwx"}`;
  assert.equal(await checkProof(await signed(claims("1791201600")), { method: "POST", url, body: "" }, 1791201600), "ok");
  for (const payload of ["null", "7", "[]", '"x"', claims("1791201600.5"), claims("9007199254740993")]) {
    assert.equal(await checkProof(await signed(payload), { method: "POST", url, body: "" }, 1791201600), "invalid_proof", payload);
  }
});
