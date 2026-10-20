// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import { PEER_OPERATION, PeerRunMissing, peerRun } from "../src/a2a.ts";
import { b64url } from "../src/pap.ts";
import { actionTokenKid, MemoryStore, Refusal, Verifier } from "../src/verifier.ts";

const ISSUER = "https://pc.example.test";
const AUDIENCE = "https://gw.example.test/a2a/peer";
const RUN = "0190f3b4-7c2e-7aaa-8bbb-000000000042";

function minter() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const raw = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(-32));
  const kid = actionTokenKid(raw);
  const jwks = JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", x: b64url(raw), kid, alg: "EdDSA" }] });
  let n = 0;
  const enc = (o: unknown) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  return {
    token(body: string, op = PEER_OPERATION, run: string | null = RUN): string {
      n++;
      const now = Math.floor(Date.now() / 1000);
      const claims: Record<string, unknown> = {
        iss: ISSUER,
        aud: AUDIENCE,
        jti: `jti-${n}`,
        iat: now,
        exp: now + 30,
        pap: { v: 1, txn: "t", act: "a", bh: createHash("sha256").update(body).digest("hex"), op, target: { type: "a2a.agent", id: "peer" } },
      };
      if (run !== null) claims.pc_peer_run = run;
      const input = `${enc({ alg: "EdDSA", kid, typ: "pap-action+jwt" })}.${enc(claims)}`;
      return `${input}.${b64url(new Uint8Array(sign(null, Buffer.from(input), privateKey)))}`;
    },
    verifier(): Verifier {
      return new Verifier({
        jwksUrl: "https://pc.example.test/.well-known/pantherclaw/jwks.json",
        issuer: ISSUER,
        audience: AUDIENCE,
        store: new MemoryStore(100, Math.floor(Date.now() / 1000) - 3600),
        fetch: (async () => new Response(jwks, { status: 200 })) as typeof fetch,
      });
    },
  };
}

test("TestHR325_PeerRunFromTheGatewaysToken", async () => {
  const m = minter();
  const v = m.verifier();
  const body = '{"jsonrpc":"2.0","id":"t","method":"SendMessage","params":{}}';
  const headers = { "pap-action": m.token(body) };
  assert.equal(await peerRun(headers, body, v), RUN);
  const refused = async (h: Record<string, string>, b: string, code: string) => {
    await assert.rejects(peerRun(h, b, v), (e: unknown) => (e instanceof Refusal || e instanceof PeerRunMissing) && e.code === code, code);
  };
  await refused(headers, body, "replayed");
  await refused({}, body, "missing");
  await refused({ "PAP-Action": m.token(body) }, `${body} `, "body_mismatch");
  await refused({ "PAP-Action": m.token(body, "payments.refund.create") }, body, "operation_mismatch");
  await refused({ "PAP-Action": m.token("{}", PEER_OPERATION, null) }, "{}", "peer_run_missing");
  assert.equal(await peerRun(new Headers({ "PAP-Action": m.token(body) }), body, v), RUN);
});
