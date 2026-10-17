// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// PantherClaw for the MCP TypeScript SDK (PN-016.3, HR-328, HR-329).
//
// gatewayFetch is a fetch for the SDK's Streamable HTTP client transport:
// it signs every request to the gateway's /mcp/{connection} face with
// PAP/1, so the gateway decides and sends every call (an enforced route).
// It refuses to send anywhere else, so the workload's identity reaches only
// that face.
//
// guardClient is for an MCP server the agent reaches with its own access
// (agent_held): every callTool goes to the gateway's /sdk face first and
// reaches the server only on PantherClaw's allow. A hold waits in
// PantherClaw; a deny, a call PantherClaw cannot decide, a wait that ends
// and any error return a refusal (fail closed, HR-200). These decisions are
// cooperative and labeled PARTIAL (HR-024): prefer gatewayFetch.

import { randomBytes } from "node:crypto";
// The core client; once @pantherclaw/sdk is published, a build step imports it by name.
import {
  canonicalize,
  type Client,
  HEADER_NONCE,
  HEADER_PROOF,
  newActionId,
  type Outbound,
  type Result,
  retry,
  signProof,
  type ToolCall,
  type WorkloadKey,
} from "../../../../sdk/typescript/src/index.ts";

/** The rule for a connection's name (migration 00041); a connection governs the one MCP server named after it. */
const CONNECTION_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** How many held calls' action ids one guard remembers for an identical retry. */
const MAX_RETRIES = 1024;

/** The MCP SDK's FetchLike. */
export type FetchLike = (url: string | URL, init?: RequestInit) => Promise<Response>;

/** The workload key the core client signs with. */
function keyOf(client: Client): Promise<WorkloadKey> {
  // The core client keeps its key to itself; the integration signs with the same key the client was built with.
  const key = (client as unknown as { key?: Promise<WorkloadKey> }).key;
  if (!key) throw new Error("PantherClaw: the client has no workload key");
  return key;
}

/** The run the client acts in. */
function runOf(client: Client): string {
  return (client as unknown as { cfg?: { runId?: string } }).cfg?.runId ?? "";
}

/**
 * A fetch that signs every request to the gateway's /mcp/{connection} face
 * with PAP/1: the workload token, a proof over the method, URL and body,
 * the run (PAP-Run-Id), the gateway's nonce (one retry on use_nonce) and
 * one token renewal on token_expired or invalid_token. A request to any
 * other URL, a body that is not a string and a redirect are refused.
 */
export function gatewayFetch(client: Client, connection: string, base: FetchLike = fetch): FetchLike {
  if (!client?.gateway) throw new Error("PantherClaw: a client with a gateway URL is required");
  if (!CONNECTION_NAME.test(connection)) throw new Error(`PantherClaw: no connection can be named ${connection}`);
  const face = new URL(`${client.gateway}/mcp/${connection}`);
  let nonce: string | undefined;
  return async (url, init = {}) => {
    const u = new URL(String(url));
    if (u.origin !== face.origin || (u.pathname !== face.pathname && !u.pathname.startsWith(`${face.pathname}/`)) || u.username || u.password) {
      throw new Error(`PantherClaw: gatewayFetch sends only to ${face.href}`);
    }
    const body = init.body ?? "";
    if (typeof body !== "string") throw new Error("PantherClaw: gatewayFetch signs only a string body");
    const method = (init.method ?? "GET").toUpperCase();
    const run = runOf(client);
    if (!run) throw new Error("PantherClaw: the client has no run id");
    const key = await keyOf(client);
    let force = false;
    for (let attempt = 0; ; attempt++) {
      const token = await client.workloadToken(force);
      const headers = new Headers(init.headers);
      headers.set("PAP-Run-Id", run);
      headers.set("Authorization", `PAP ${token}`);
      headers.set(HEADER_PROOF, await signProof(key, { method, url: u.href, body, token, nonce }));
      const res = await base(u.href, { ...init, method, headers, body: method === "GET" || method === "HEAD" ? undefined : body, redirect: "error" });
      const n = res.headers.get(HEADER_NONCE);
      if (n) nonce = n;
      const again = attempt === 0 ? retry(res.status, res.headers) : "";
      if (!again) return res;
      await res.body?.cancel().catch(() => {});
      force = again === "refresh_token";
    }
  };
}

/** The members of the MCP SDK's Client this integration uses. */
export interface McpClient {
  // biome-ignore lint/suspicious/noExplicitAny: the MCP SDK's own parameter and result types
  callTool(params: { name: string; arguments?: Record<string, unknown>; [k: string]: unknown }, resultSchema?: any, options?: any): Promise<any>;
  // biome-ignore lint/suspicious/noExplicitAny: the MCP SDK's own parameter and result types
  listTools(params?: any, options?: any): Promise<any>;
  close(): Promise<void>;
}

export interface GuardOptions {
  /** The PantherClaw client: key file, gateway and run. */
  client: Client;
  /** The connection that governs the MCP server; its package maps the server's tools. */
  connection: string;
  /** The MCP server's name; a connection governs the one server named after it, so it is the connection's name (the default). */
  server?: string;
  /**
   * A hold: "wait" (the only choice, and the default) waits in PantherClaw
   * for up to `wait` seconds and calls the tool only on its later allow.
   * When the wait ends first, the call is refused, and an identical later
   * call resubmits the same action.
   */
  onHold?: "wait";
  /** How long a hold is waited on, in seconds (default 300, HR-174). */
  wait?: number;
  /** Let a tool the connection's package does not map be called (default false: refused). */
  observeUnmapped?: boolean;
  /** Throw a PantherClawRefusal from callTool instead of returning the refusal as an error result (default false). */
  raiseOnRefusal?: boolean;
  /**
   * Sends an allowed call's request on a target-enforced connection, whose
   * server accepts only that exact request with its action token (HR-201),
   * and returns the call's result (D53). It runs instead of the client's
   * own callTool, which would send a request the token does not bind.
   * Without it such an allow is refused.
   */
  onDispatch?: (callId: string, send: Outbound) => unknown;
}

/** Why PantherClaw refused a call: its code and transaction. */
export class PantherClawRefusal extends Error {
  readonly code: string;
  readonly transactionId: string;
  constructor(code: string, transactionId = "") {
    super(`PantherClaw refused this call: ${code}${transactionId ? ` (transaction ${transactionId})` : ""}`);
    this.name = "PantherClawRefusal";
    this.code = code;
    this.transactionId = transactionId;
  }
}

/**
 * The guarded client: callTool decided by PantherClaw, listTools and close.
 * Nothing else of the MCP client is reachable through it, so no request
 * reaches the server's tools without a decision.
 */
export interface GuardedClient {
  // biome-ignore lint/suspicious/noExplicitAny: the MCP SDK's own parameter and result types
  callTool(params: { name: string; arguments?: Record<string, unknown>; [k: string]: unknown }, resultSchema?: any, options?: any): Promise<any>;
  // biome-ignore lint/suspicious/noExplicitAny: the MCP SDK's own parameter and result types
  listTools(params?: any, options?: any): Promise<any>;
  close(): Promise<void>;
}

/**
 * The refusal a call's final result is (D47), or null when the tool is
 * called: `first` is the first answer, `res` the final one, `resumed`
 * whether a hold was waited on.
 */
function refusal(first: Result, res: Result, resumed: boolean, observeUnmapped: boolean): PantherClawRefusal | null {
  const txn = res.answer?.transaction_id || first.answer?.transaction_id || "";
  if (res.outcome === "allow") return null;
  if (resumed) return new PantherClawRefusal(res.outcome === "deny" ? "hold_declined" : "hold_timeout", txn);
  if (res.outcome === "deny") {
    if (res.answer?.code === "unknown_tool" && observeUnmapped) return null;
    return new PantherClawRefusal(res.answer?.code || "denied", txn);
  }
  return new PantherClawRefusal("cannot_decide", txn);
}

/**
 * Wraps an MCP client of an agent_held or target-enforced server so that
 * PantherClaw decides every callTool before the server sees it. An allow
 * carrying a request to send (a target-enforced connection) goes to
 * onDispatch, never to the client's own callTool.
 */
export function guardClient(mcp: McpClient, options: GuardOptions): GuardedClient {
  if (!mcp || typeof mcp.callTool !== "function") throw new Error("PantherClaw: an MCP client is required");
  if (!options?.client || !options.connection) throw new Error("PantherClaw: a client and a connection are required");
  const o = { onHold: "wait" as const, wait: 300, observeUnmapped: false, raiseOnRefusal: false, server: options.connection, ...options };
  if (!CONNECTION_NAME.test(o.connection)) throw new Error(`PantherClaw: no connection can be named ${o.connection}`);
  if (o.server !== o.connection) throw new Error(`PantherClaw: the connection ${o.connection} governs the MCP server named after it, not ${o.server}`);
  if (o.onHold !== "wait") throw new Error('PantherClaw: onHold is "wait"');
  if (!(o.wait > 0)) throw new Error("PantherClaw: wait is a number of seconds above 0");
  const callTool = mcp.callTool.bind(mcp);
  const listTools = mcp.listTools.bind(mcp);
  const close = mcp.close.bind(mcp);
  /** Action ids of held calls by their content, so an identical later call resubmits the same action (PAP/1 §8). */
  const retries = new Map<string, { actionId: string; expires: number }>();

  const decide = async (name: unknown, args: unknown, signal?: AbortSignal): Promise<{ refusal: PantherClawRefusal | null; send?: Outbound; id: string; txn: string }> => {
    // The client refuses a call without a tool name or with an input that is not an object (cannot_decide).
    if (typeof name !== "string" || name === "" || typeof args !== "object" || args === null || Array.isArray(args)) {
      return { refusal: new PantherClawRefusal("cannot_decide"), id: "", txn: "" };
    }
    const call: ToolCall = { tool: `mcp__${o.server}__${name}`, server: o.server, input: args as Record<string, unknown>, tool_use_id: `pc-${randomBytes(16).toString("hex")}` };
    const key = JSON.stringify([name, canonicalize(JSON.stringify(args))]);
    const now = Date.now();
    for (const [k, r] of retries) if (r.expires < now) retries.delete(k);
    const actionId = retries.get(key)?.actionId ?? newActionId();
    const first = await o.client.authorize(o.connection, call, actionId);
    let res = first;
    if (first.outcome === "hold") {
      retries.set(key, { actionId, expires: now + o.wait * 1000 });
      if (retries.size > MAX_RETRIES) retries.delete(retries.keys().next().value as string);
      res = await withSignal(o.client.resume(o.connection, call, actionId, first, o.wait * 1000), signal);
      // The wait has used up its time: an identical later call may still resubmit the held action.
      if (res.outcome !== "allow") retries.set(key, { actionId, expires: Date.now() + o.wait * 1000 });
    }
    if (res.outcome === "allow") retries.delete(key);
    const r = refusal(first, res, first.outcome === "hold", o.observeUnmapped);
    return { refusal: r, send: r ? undefined : res.send, id: call.tool_use_id, txn: res.answer?.transaction_id ?? "" };
  };

  return {
    async callTool(params, resultSchema, opts) {
      let r: PantherClawRefusal | null;
      let send: Outbound | undefined;
      let id = "";
      let txn = "";
      try {
        ({ refusal: r, send, id, txn } = await decide(params?.name, params?.arguments ?? {}, opts?.signal));
      } catch {
        r = new PantherClawRefusal("wrapper_error");
      }
      if (!r && send && !o.onDispatch) r = new PantherClawRefusal("dispatch_required", txn);
      if (r) {
        if (o.raiseOnRefusal) throw r;
        return { content: [{ type: "text", text: r.message }], isError: true };
      }
      if (send && o.onDispatch) return o.onDispatch(id, send);
      return callTool(params, resultSchema, opts);
    },
    listTools: (params, opts) => listTools(params, opts),
    close: () => close(),
  };
}

/** Ends a wait when the caller aborts the call. */
function withSignal<T>(p: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(new Error("aborted"));
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(new Error("aborted"));
    signal.addEventListener("abort", abort, { once: true });
    p.then(
      (v) => {
        signal.removeEventListener("abort", abort);
        resolve(v);
      },
      (e) => {
        signal.removeEventListener("abort", abort);
        reject(e);
      },
    );
  });
}
