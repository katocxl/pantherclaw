// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// PAP/1 primitives: the workload key file, request proofs, key thumbprints,
// workload token claims and action hashes (docs/protocol/PAP-1.md §3–§4,
// §6), checked against sdk/conformance.

import { createHash, randomBytes } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import { parseAction } from "./action.ts";
import { parseJSON } from "./jcs.ts";

export const VERSION = 1;
export const HEADER_PROOF = "PAP-Proof";
export const HEADER_NONCE = "PAP-Nonce";
export const HEADER_ERROR = "PAP-Error";
export const HEADER_ACTION = "PAP-Action";
export const TYPE_PROOF = "pap-proof+jwt";
export const TOKEN_AUDIENCE = "pantherclaw-gateway";

/** base64url without padding. */
export function b64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Strict base64url decoding: the alphabet only, no padding. */
export function fromB64url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error("not base64url without padding");
  return new Uint8Array(Buffer.from(s, "base64url"));
}

export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

const encoder = new TextEncoder();

/** bh: base64url(SHA-256(body)). */
export function bodyHash(body: Uint8Array | string): string {
  return b64url(sha256(typeof body === "string" ? encoder.encode(body) : body));
}

/** ath: base64url(SHA-256(token)). */
export function ath(token: string): string {
  return b64url(sha256(token));
}

/** The RFC 7638 thumbprint (jkt) of an Ed25519 public key. */
export function thumbprint(publicKey: Uint8Array): string {
  return b64url(sha256(`{"crv":"Ed25519","kty":"OKP","x":"${b64url(publicKey)}"}`));
}

// PKCS #8 prefix of an Ed25519 private key (RFC 8410).
const pkcs8Prefix = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);

/** An Ed25519 workload key (WebCrypto), derived from its 32-byte seed. */
export class WorkloadKey {
  readonly publicKey: Uint8Array;
  readonly jkt: string;
  private readonly key: CryptoKey;

  private constructor(key: CryptoKey, publicKey: Uint8Array) {
    this.key = key;
    this.publicKey = publicKey;
    this.jkt = thumbprint(publicKey);
  }

  /** The key of a seed; the private key is not extractable. */
  static async fromSeed(seed: Uint8Array): Promise<WorkloadKey> {
    if (seed.length !== 32) throw new Error("an Ed25519 seed is 32 bytes");
    const der = new Uint8Array([...pkcs8Prefix, ...seed]);
    const exportable = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", exportable);
    const key = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, false, ["sign"]);
    return new WorkloadKey(key, fromB64url(String(jwk.x)));
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this.key, data));
  }
}

/** Verifies an Ed25519 signature with a raw 32-byte public key. */
export async function verifyEd25519(publicKey: Uint8Array, signature: Uint8Array, data: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32 || signature.length !== 64) return false;
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
}

/** The workload key file (PAP/1 §3.1). Keep it owner-only; never log it. */
export interface KeyFile {
  /** The Ed25519 seed, base64url without padding. */
  private_key: string;
  identifier?: string;
  server?: string;
  run_id?: string;
}

const keyFileMembers = ["private_key", "identifier", "server", "run_id"] as const;

/** Parses a key file strictly: unknown or duplicate members are refused. */
export function parseKeyFile(text: string | Uint8Array): KeyFile {
  const v = parseJSON(text);
  if (!(v instanceof Map)) throw new Error("a key file is a JSON object");
  const out: Record<string, string> = {};
  for (const [k, x] of v) {
    if (!(keyFileMembers as readonly string[]).includes(k) || typeof x !== "string") throw new Error(`key file: unexpected member ${k}`);
    out[k] = x;
  }
  const kf = out as unknown as KeyFile;
  seedOf(kf);
  return kf;
}

/** Returns the key a key file holds. */
export function seedOf(kf: KeyFile): Uint8Array {
  const s = kf.private_key ?? "";
  if (s.length !== 43) throw new Error("key file: private_key must be a base64url Ed25519 seed");
  const seed = fromB64url(s);
  if (seed.length !== 32) throw new Error("key file: private_key must be a base64url Ed25519 seed");
  return seed;
}

/** Returns the key a key file holds. */
export function keyOf(kf: KeyFile): Promise<WorkloadKey> {
  return WorkloadKey.fromSeed(seedOf(kf));
}

/** The key file's bytes as PantherClaw writes them. */
export function marshalKeyFile(kf: KeyFile): string {
  const parts = keyFileMembers.filter((k) => kf[k]).map((k) => `${JSON.stringify(k)}:${JSON.stringify(kf[k])}`);
  return `{${parts.join(",")}}\n`;
}

export async function readKeyFile(path: string): Promise<KeyFile> {
  return parseKeyFile(new Uint8Array(await readFile(path)));
}

/** Writes a new owner-only key file; an existing file is never replaced. */
export async function writeKeyFile(path: string, kf: KeyFile): Promise<void> {
  seedOf(kf);
  const f = await open(path, "wx", 0o600);
  try {
    await f.writeFile(marshalKeyFile(kf));
  } finally {
    await f.close();
  }
}

/** A key file with a fresh key. */
export function newKeyFile(): KeyFile {
  return { private_key: b64url(randomBytes(32)) };
}

export interface ProofParams {
  method: string;
  url: string;
  body?: Uint8Array | string;
  /** The workload token sent with the request; absent for a key-only proof. */
  token?: string;
  /** The server's latest PAP-Nonce. */
  nonce?: string;
  /** iat in Unix seconds (now when absent). */
  iat?: number;
  /** The proof id (128 random bits when absent). */
  jti?: string;
}

/** htu: scheme, host and path of a request URL. */
export function htu(raw: string): string {
  const u = new URL(raw);
  if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username || u.password) {
    throw new Error("the request URL must be an absolute http(s) URL without user information");
  }
  return `${u.protocol}//${u.host}${u.pathname}`;
}

/** Signs a PAP-Proof JWS (PAP/1 §4) byte for byte as PantherClaw does. */
export async function signProof(key: WorkloadKey, p: ProofParams): Promise<string> {
  const header = `{"alg":"EdDSA","jwk":{"crv":"Ed25519","kty":"OKP","x":"${b64url(key.publicKey)}"},"typ":"${TYPE_PROOF}"}`;
  const claims: Record<string, string | number> = {
    htm: p.method,
    htu: htu(p.url),
    iat: p.iat ?? Math.floor(Date.now() / 1000),
    jti: p.jti ?? b64url(randomBytes(16)),
  };
  if (p.token) claims.ath = ath(p.token);
  claims.bh = bodyHash(p.body ?? "");
  if (p.nonce) claims.nonce = p.nonce;
  const input = `${b64url(encoder.encode(header))}.${b64url(encoder.encode(JSON.stringify(claims)))}`;
  return `${input}.${b64url(await key.sign(encoder.encode(input)))}`;
}

export interface TokenClaims {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  cnf: { jkt: string };
  pap: { v: number; org: string; env: string; att_lvl: number };
}

/**
 * Reads a workload token's claims without verifying it, to know when to
 * renew it and which key it is bound to. PantherClaw verifies the token.
 */
export function parseTokenClaims(token: string): TokenClaims {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("not a compact JWS");
  const c = JSON.parse(new TextDecoder().decode(fromB64url(parts[1] ?? ""))) as TokenClaims;
  if (c?.pap?.v !== VERSION || c.aud !== TOKEN_AUDIENCE || typeof c.exp !== "number" || typeof c.cnf?.jkt !== "string" || !c.cnf.jkt) {
    throw new Error("not a PAP/1 workload token");
  }
  return c;
}

/** The action hash of ActionIR, checked as strictly as PantherClaw does (PAP/1 §6). */
export function actionHash(action: string | Uint8Array): string {
  return parseAction(action).hash;
}
