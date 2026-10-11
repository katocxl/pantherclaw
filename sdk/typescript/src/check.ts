// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Proof checks as PantherClaw makes them (PAP/1 §4, steps 2–5), for fake
// gateways in tests and for services that verify PAP/1 themselves.

import { type JSONValue, parseJSON } from "./jcs.ts";
import { ath, bodyHash, fromB64url, parseTokenClaims, splitURL, thumbprint, TYPE_PROOF, verifyEd25519 } from "./pap.ts";

/** What a verifier knows about the request a proof came with. */
export interface ProofRequest {
  method: string;
  /** The verifier's own URL for the request, never one from the Host header. */
  url: string;
  body: Uint8Array | string;
  token?: string;
}

const noncePattern = /^[A-Za-z0-9_-]{22,64}$/;

/** Parses strictly (duplicate members refused, as PantherClaw does) into plain values. */
function json(bytes: Uint8Array): unknown {
  const plain = (v: JSONValue): unknown =>
    v instanceof Map ? Object.fromEntries([...v].map(([k, x]) => [k, plain(x)])) : Array.isArray(v) ? v.map(plain) : v;
  return plain(parseJSON(bytes));
}

/** htu matches when scheme and host are equal without case and the escaped paths exactly, as PantherClaw compares them. */
function sameHTU(claimed: string, want: string): boolean {
  if (claimed.includes("?") || claimed.includes("#") || want.includes("?") || want.includes("#")) return false;
  try {
    const a = splitURL(claimed);
    const b = splitURL(want);
    return a.scheme === b.scheme && a.host.toLowerCase() === b.host.toLowerCase() && a.path === b.path;
  } catch {
    return false;
  }
}

/**
 * Checks a PAP-Proof against its request at `now` (Unix seconds) and
 * returns "ok" or the PAP-Error code PantherClaw answers: the header (alg
 * EdDSA, typ, a public Ed25519 jwk and nothing else) and signature, the key
 * binding to the token's cnf.jkt, htm, htu, ath, bh, iat, jti and the
 * nonce's shape. The token itself is not verified here, and neither is
 * whether the nonce is current or the jti new: "ok" is not the whole
 * check. The caller checks the nonce against the ones it issued and spends
 * the jti once, or it accepts replays.
 */
export async function checkProof(proof: string, r: ProofRequest, now: number): Promise<string> {
  const parts = proof.split(".");
  if (proof.length > 8 << 10 || /\s/.test(proof) || parts.length !== 3) return "invalid_proof";
  // biome-ignore lint/suspicious/noExplicitAny: parsed and checked member by member
  let h: any;
  // biome-ignore lint/suspicious/noExplicitAny: parsed and checked member by member
  let c: any;
  let sig: Uint8Array;
  let x: Uint8Array;
  try {
    h = json(fromB64url(parts[0] ?? ""));
    c = json(fromB64url(parts[1] ?? ""));
    if (typeof c !== "object" || c === null || Array.isArray(c)) return "invalid_proof";
    sig = fromB64url(parts[2] ?? "");
    const keys = Object.keys(h ?? {}).sort().join(",");
    const jwk = Object.keys(h?.jwk ?? {}).sort().join(",");
    if (keys !== "alg,jwk,typ" || jwk !== "crv,kty,x" || h.alg !== "EdDSA" || h.typ !== TYPE_PROOF || h.jwk.kty !== "OKP" || h.jwk.crv !== "Ed25519") {
      return "invalid_proof";
    }
    x = fromB64url(String(h.jwk.x));
  } catch {
    return "invalid_proof";
  }
  if (!(await verifyEd25519(x, sig, new TextEncoder().encode(`${parts[0]}.${parts[1]}`)))) return "invalid_proof";
  if (r.token) {
    try {
      if (thumbprint(x) !== parseTokenClaims(r.token).cnf.jkt) return "key_mismatch";
    } catch {
      return "invalid_token";
    }
  }
  if (!r.method || c.htm !== r.method || typeof c.htu !== "string" || !sameHTU(c.htu, r.url)) return "invalid_proof";
  if (r.token ? c.ath !== ath(r.token) : c.ath !== undefined && c.ath !== "") return "invalid_proof";
  if (c.bh !== bodyHash(r.body)) return "body_hash_mismatch";
  if (!Number.isSafeInteger(c.iat) || c.iat > now + 60 || c.iat < now - 360) return "invalid_proof";
  if (typeof c.jti !== "string" || c.jti.length < 22 || c.jti.length > 128 || !/^[\x21-\x7e]+$/.test(c.jti)) return "invalid_proof";
  if (typeof c.nonce !== "string" || !noncePattern.test(c.nonce)) return "use_nonce";
  return "ok";
}
