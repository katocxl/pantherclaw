// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Target-side verification of PantherClaw action tokens (PAP/1 §10,
// HR-202): a service PantherClaw reaches through a target-enforced
// connection runs a request only when its PAP-Action token was minted for
// exactly that request, is unexpired and was never used before by any
// replica that shares the replay store.

import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { type JSONValue, parseJSON } from "./jcs.ts";
import { fromB64url, thumbprint, verifyEd25519 } from "./pap.ts";

export const TYPE_ACTION_TOKEN = "pap-action+jwt";
export const MAX_LIFETIME = 60;
export const SKEW = 5;

/** Why a request was refused; every refusal means it must not run. */
export type RefusalCode =
  | "missing"
  | "bad_signature"
  | "wrong_issuer"
  | "wrong_audience"
  | "expired"
  | "body_mismatch"
  | "operation_mismatch"
  | "replayed"
  | "store_unavailable";

export class Refusal extends Error {
  readonly code: RefusalCode;
  constructor(code: RefusalCode, detail: string) {
    super(`action token refused: ${code}: ${detail}`);
    this.name = "Refusal";
    this.code = code;
  }

  /** The HTTP status to answer: 409 for a replay, 503 when keys or store are unreachable, 401 otherwise. */
  get status(): number {
    return this.code === "replayed" ? 409 : this.code === "store_unavailable" ? 503 : 401;
  }
}

export interface ActionClaims {
  iss: string;
  aud: string;
  jti: string;
  iat: number;
  exp: number;
  pap: { v: number; txn: string; act: string; bh: string; op: string; target: { type: string; id: string } };
}

/** One token to record as used until `until` (Unix seconds): its audience and id. */
export interface Spend {
  /** The token's aud, the target's connection id: a store keys by (audience, id). */
  audience: string;
  id: string;
  issuedAt: number;
  now: number;
  until: number;
}

/**
 * Spends action token ids. `use` resolves true on the first use and false
 * on a replay; it must reject, never resolve true, when it cannot record.
 * `shared` says whether every replica of the target uses the same store.
 */
export interface ReplayStore {
  use(spend: Spend): Promise<boolean>;
  readonly shared: boolean;
}

/**
 * A replay store for one replica. It never evicts an id early; when full it
 * refuses. A process that restarted has lost the ids it recorded, so tokens
 * issued before it started plus the skew are refused: one issued up to SKEW
 * after the start, by the Authority's clock, may have been spent before.
 * The store fails closed for those few seconds.
 */
export class MemoryStore implements ReplayStore {
  readonly shared = false;
  private readonly seen = new Map<string, number>();
  private readonly capacity: number;
  private readonly started: number;

  /** `started` (Unix seconds, default now) is when it began recording. */
  constructor(capacity = 100_000, started = Math.floor(Date.now() / 1000)) {
    this.capacity = capacity;
    this.started = started;
  }

  async use(s: Spend): Promise<boolean> {
    if (s.issuedAt < this.started + SKEW) throw new Error("the store began recording after the token was issued");
    const id = `${s.audience}\u0000${s.id}`;
    if (this.seen.has(id)) return false;
    if (this.seen.size >= this.capacity) {
      for (const [k, until] of this.seen) if (s.now > until) this.seen.delete(k);
      if (this.seen.size >= this.capacity) throw new Error("the replay store is full");
    }
    this.seen.set(id, s.until);
    return true;
  }
}

export interface VerifierConfig {
  /** PantherClaw's /.well-known/pantherclaw/jwks.json: https, or http only to a loopback address. */
  jwksUrl: string;
  issuer: string;
  /** The connection id this target is registered as. */
  audience: string;
  store: ReplayStore;
  /** The clock in Unix seconds (default: now). */
  now?: () => number;
  fetch?: typeof fetch;
}

/** The kid of an action-tokens key: "action-tokens-" and 22 characters of its thumbprint. */
export function actionTokenKid(publicKey: Uint8Array): string {
  return `action-tokens-${thumbprint(publicKey).slice(0, 22)}`;
}

const encoder = new TextEncoder();

/** Whether a URL is https, or http to a loopback address, without user information. */
function secure(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.username || u.password) return false;
  if (u.protocol === "https:") return true;
  return u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "[::1]" || /^127(\.[0-9]{1,3}){3}$/.test(u.hostname));
}

const plain = (x: JSONValue): unknown =>
  x instanceof Map ? Object.fromEntries([...x].map(([k, y]) => [k, plain(y)])) : Array.isArray(x) ? x.map(plain) : x;

/** Whether parsed claims have the shape of an action token's; anything else is bad_signature, as a decode failure is. */
function wellFormed(c: unknown): c is ActionClaims {
  // biome-ignore lint/suspicious/noExplicitAny: checked member by member
  const x = c as any;
  return (
    typeof x === "object" &&
    x !== null &&
    typeof x.iss === "string" &&
    typeof x.aud === "string" &&
    typeof x.jti === "string" &&
    Number.isSafeInteger(x.iat) &&
    Number.isSafeInteger(x.exp) &&
    typeof x.pap === "object" &&
    x.pap !== null &&
    typeof x.pap.bh === "string" &&
    typeof x.pap.op === "string" &&
    typeof x.pap.target === "object" &&
    x.pap.target !== null
  );
}

export class Verifier {
  private readonly cfg: VerifierConfig;
  private keys: Map<string, Uint8Array> | null = null;
  private fetched = 0;
  private tried = Number.NEGATIVE_INFINITY;
  /** The JWKS fetch in flight: verifications that need it share it. */
  private inflight: Promise<void> | null = null;
  private fetchError: unknown = null;

  constructor(cfg: VerifierConfig) {
    if (!cfg.jwksUrl || !cfg.issuer || !cfg.audience || !cfg.store) throw new Error("jwksUrl, issuer, audience and store are required");
    if (!secure(cfg.jwksUrl)) throw new Error("the JWKS URL must use https (http only on a loopback address)");
    this.cfg = cfg;
  }

  /** Whether the store serves one replica only: such a verifier cannot back an enforced claim for more (HR-024). */
  get singleReplica(): boolean {
    return !this.cfg.store.shared;
  }

  private now(): number {
    return this.cfg.now ? this.cfg.now() : Math.floor(Date.now() / 1000);
  }

  /**
   * Verifies the token of a request whose exact body is `body` and spends
   * it; `match` says whether the claims' operation and target are what the
   * request does. Throws a Refusal.
   */
  async verify(token: string | null | undefined, body: Uint8Array | string, match: (c: ActionClaims) => boolean): Promise<ActionClaims> {
    if (!token) throw new Refusal("missing", "no PAP-Action header");
    const c = await this.signed(token);
    const now = this.now();
    const bytes = typeof body === "string" ? encoder.encode(body) : body;
    if (c.iss !== this.cfg.issuer) throw new Refusal("wrong_issuer", String(c.iss));
    if (c.aud !== this.cfg.audience) throw new Refusal("wrong_audience", String(c.aud));
    if (!Number.isInteger(c.iat) || !Number.isInteger(c.exp) || c.exp <= c.iat || c.exp - c.iat > MAX_LIFETIME || now >= c.exp + SKEW || c.iat > now + SKEW) {
      throw new Refusal("expired", `iat ${c.iat} exp ${c.exp}`);
    }
    if (c.pap?.v !== 1 || typeof c.jti !== "string" || !c.jti || c.jti.length > 128) throw new Refusal("bad_signature", "not a version 1 action token");
    if (c.pap.bh !== createHash("sha256").update(bytes).digest("hex")) throw new Refusal("body_mismatch", "the body is not the one the token binds");
    if (!match(c)) throw new Refusal("operation_mismatch", `${c.pap.op} on ${c.pap.target?.type} ${c.pap.target?.id}`);
    let first: boolean;
    try {
      first = await this.cfg.store.use({ audience: c.aud, id: c.jti, issuedAt: c.iat, now, until: c.exp + SKEW });
    } catch (e) {
      throw new Refusal("store_unavailable", String(e));
    }
    if (!first) throw new Refusal("replayed", c.jti);
    return c;
  }

  private async signed(token: string): Promise<ActionClaims> {
    const parts = token.split(".");
    if (token.length > 8 << 10 || parts.length !== 3) throw new Refusal("bad_signature", "malformed");
    let h: Map<string, unknown>;
    let payload: Uint8Array;
    let sig: Uint8Array;
    try {
      const v = parseJSON(fromB64url(parts[0] ?? ""));
      if (!(v instanceof Map) || [...v.keys()].sort().join(",") !== "alg,kid,typ") throw new Error("header members");
      h = v;
      payload = fromB64url(parts[1] ?? "");
      sig = fromB64url(parts[2] ?? "");
    } catch {
      throw new Refusal("bad_signature", "malformed");
    }
    const alg = h.get("alg");
    if ((alg !== "EdDSA" && alg !== "Ed25519") || h.get("typ") !== TYPE_ACTION_TOKEN || typeof h.get("kid") !== "string") {
      throw new Refusal("bad_signature", "header");
    }
    const key = await this.key(String(h.get("kid")));
    if (!(await verifyEd25519(key, sig, encoder.encode(`${parts[0]}.${parts[1]}`)))) throw new Refusal("bad_signature", "signature");
    let c: unknown;
    try {
      c = plain(parseJSON(payload));
    } catch {
      throw new Refusal("bad_signature", "claims");
    }
    if (!wellFormed(c)) throw new Refusal("bad_signature", "claims");
    return c;
  }

  /**
   * The JWKS is cached at most 15 minutes and refetched at most once a
   * minute for an unknown kid, one fetch at a time: verifications that need
   * it wait for the one in flight.
   */
  private async key(kid: string): Promise<Uint8Array> {
    const now = this.now();
    const stale = this.keys === null || now - this.fetched >= 900;
    if ((stale || !this.keys?.has(kid)) && (stale || now - this.tried >= 60 || this.inflight)) {
      if (!this.inflight) {
        this.tried = now;
        this.inflight = this.fetchKeys().then(
          (keys) => {
            this.keys = keys;
            this.fetched = now;
            this.fetchError = null;
          },
          (e) => {
            this.fetchError = e;
            if (stale) this.keys = null;
          },
        );
        void this.inflight.finally(() => {
          this.inflight = null;
        });
      }
      await this.inflight;
    }
    if (this.keys === null || this.now() - this.fetched >= 900) throw new Refusal("store_unavailable", `JWKS: ${this.fetchError}`);
    const k = this.keys.get(kid);
    if (!k) throw new Refusal("bad_signature", `unknown key ${kid}`);
    return k;
  }

  private async fetchKeys(): Promise<Map<string, Uint8Array>> {
    const res = await (this.cfg.fetch ?? fetch)(this.cfg.jwksUrl, { redirect: "error", signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const raw = new Uint8Array(await res.arrayBuffer());
    if (raw.length > 64 << 10) throw new Error("the JWKS is too large");
    const set = plain(parseJSON(raw)) as { keys?: { kty?: string; crv?: string; x?: string; kid?: string; alg?: string }[] };
    const keys = new Map<string, Uint8Array>();
    for (const k of set.keys ?? []) {
      try {
        const x = fromB64url(String(k.x));
        if (k.kty !== "OKP" || k.crv !== "Ed25519" || (k.alg && k.alg !== "EdDSA" && k.alg !== "Ed25519") || x.length !== 32) continue;
        if (k.kid === actionTokenKid(x)) keys.set(k.kid, x);
      } catch {
        // not a usable key
      }
    }
    return keys;
  }
}

/** The largest body the middleware reads (1 MiB). */
export const DEFAULT_MAX_BODY = 1 << 20;

/** Answers an RFC 9457 problem document naming the refusal code. */
function problem(res: ServerResponse, status: number, code: string): void {
  res.writeHead(status, { "Content-Type": "application/problem+json", "Cache-Control": "no-store" });
  res.end(`${JSON.stringify({ type: `urn:pantherclaw:action-token:${code}`, title: "action token refused", status, code })}\n`);
}

/**
 * node:http middleware: before `handler` runs, it reads the exact body (at
 * most `maxBody` bytes; 413 beyond), verifies and spends the request's
 * PAP-Action token, and refuses with the Refusal's status and a problem
 * document. `match` says whether the token's operation and target are what
 * the request does. The handler gets the claims and the body bytes, since
 * the request stream has been read.
 */
export function middleware(
  v: Verifier,
  match: (req: IncomingMessage, c: ActionClaims) => boolean,
  handler: (req: IncomingMessage, res: ServerResponse, verified: { claims: ActionClaims; body: Uint8Array }) => void | Promise<void>,
  maxBody = DEFAULT_MAX_BODY,
): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  return async (req, res) => {
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for await (const chunk of req) {
        size += (chunk as Uint8Array).length;
        if (size > maxBody) return problem(res, 413, "request_too_large");
        chunks.push(chunk as Uint8Array);
      }
    } catch {
      return problem(res, 400, "request_unreadable");
    }
    const body = new Uint8Array(Buffer.concat(chunks));
    let claims: ActionClaims;
    try {
      const token = req.headers["pap-action"];
      claims = await v.verify(Array.isArray(token) ? undefined : token, body, (c) => match(req, c));
    } catch (e) {
      const r = e instanceof Refusal ? e : new Refusal("store_unavailable", String(e));
      return problem(res, r.status, r.code);
    }
    await handler(req, res, { claims, body });
  };
}
