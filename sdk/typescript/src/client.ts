// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The PantherClaw workload client (PAP/1): a proof over every request,
// the servers' nonces, workload token renewal, the gateway's /sdk face and
// waits on held calls. It fails closed (HR-200): when PantherClaw cannot
// decide, the outcome is "cannot_decide", never "allow".

import { randomBytes } from "node:crypto";
import { parseAction } from "./action.ts";
import { fromB64url, HEADER_ERROR, HEADER_NONCE, HEADER_PROOF, type KeyFile, keyOf, parseTokenClaims, signProof, type WorkloadKey } from "./pap.ts";

/** A raw tool call as the agent made it; the gateway maps it (HR-201). */
export interface ToolCall {
  /** The agent's name for the tool: a built-in such as Bash, or mcp__<server>__<tool>. */
  tool: string;
  /** The MCP server's name, for an MCP tool only. */
  server?: string;
  input: Record<string, unknown>;
  /** The agent's id of the call. */
  tool_use_id: string;
  /** A shell tool's working directory (Bash, PowerShell) only. */
  cwd?: string;
}

/** What the agent may do with a call: only allow, and observe for an unmapped built-in, let it run. */
export type Outcome = "allow" | "observe" | "hold" | "deny" | "cannot_decide";

export interface WaitState {
  handle: string;
  state?: string;
  code?: string;
  deadline?: string;
  consume_by?: string;
  approval_request_id?: string;
  retry_after_seconds?: number;
}

export interface Answer {
  decision?: string;
  reason?: string;
  error_class?: string;
  code?: string;
  reasons?: string[];
  action_id?: string;
  action_hash?: string;
  action_ir?: string;
  transaction_id?: string;
  receipt?: string;
  mode?: string;
  coverage?: string;
  wait?: WaitState;
}

export interface Result {
  outcome: Outcome;
  answer?: Answer;
  why: string;
}

const cannot = (why: string): Result => ({ outcome: "cannot_decide", why });

/** The one retry a 401 allows: with its fresh nonce, or with a renewed token. "" otherwise. */
export function retry(status: number, headers: Headers): "retry_nonce" | "refresh_token" | "" {
  if (status !== 401) return "";
  const code = headers.get(HEADER_ERROR);
  if (code === "use_nonce" && headers.get(HEADER_NONCE)) return "retry_nonce";
  if (code === "token_expired" || code === "invalid_token") return "refresh_token";
  return "";
}

/**
 * Reads a /sdk answer for the action id the SDK sent. `firstHash`, when
 * set, is the hash of an earlier answer for the same action. Anything it
 * cannot read or check is cannot_decide (HR-200, HR-201).
 */
export function evaluate(status: number, body: string, actionId: string, firstHash = ""): Result {
  if (status !== 200) return cannot(`the gateway answered HTTP ${status}`);
  let a: Answer;
  try {
    a = JSON.parse(body) as Answer;
    if (typeof a !== "object" || a === null) throw new Error("not an object");
  } catch {
    return cannot("the gateway's answer is not readable");
  }
  const r: Result = { outcome: "deny", answer: a, why: a.reason ?? "" };
  switch (a.decision) {
    case "deny":
      return r;
    case "allow":
      if (a.coverage === "OBSERVE_ONLY") {
        return a.mode === "monitor" && !a.action_hash ? { ...r, outcome: "observe" } : cannot("an observed call that is not only recorded");
      }
      r.outcome = "allow";
      break;
    case "hold":
      if (!a.wait?.handle) return cannot("a hold without a wait handle");
      r.outcome = "hold";
      break;
    default:
      return cannot(`unknown decision ${a.decision}`);
  }
  const problem = checkAction(a, actionId, firstHash);
  return problem ? cannot(problem) : r;
}

function checkAction(a: Answer, actionId: string, firstHash: string): string {
  if (a.coverage !== "PARTIAL") return "a decided call that is not labeled PARTIAL";
  if (a.action_id !== actionId) return "the answer is for another action";
  if (!/^[0-9a-f]{64}$/.test(a.action_hash ?? "")) return "the answer has no action hash";
  if (firstHash && a.action_hash !== firstHash) return "the resubmitted call mapped to another action";
  if (!a.action_ir) return "";
  try {
    const p = parseAction(fromB64url(a.action_ir));
    if (p.hash !== a.action_hash) return "the action hash does not match the action";
    if (p.action.get("action_id") !== actionId) return "the mapped action is for another action id";
  } catch {
    return "the canonical action is not valid ActionIR";
  }
  return "";
}

/** A fresh UUIDv7 for one logical tool call; send it for every retry and resubmission. */
export function newActionId(): string {
  const b = randomBytes(16);
  const ms = BigInt(Date.now());
  for (let i = 0; i < 6; i++) b[i] = Number((ms >> BigInt(40 - 8 * i)) & 0xffn);
  b[6] = ((b[6] ?? 0) & 0x0f) | 0x70;
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80;
  const h = b.toString("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export interface ClientConfig {
  /** The workload key file: its identifier is required; its server and run are defaults. */
  keyFile: KeyFile;
  server?: string;
  /** The base URL of the gateway whose /sdk face decides calls. */
  gateway?: string;
  runId?: string;
  /** Milliseconds for one decision or token request (default 15 s); past it PantherClaw cannot decide. */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

interface Sent {
  status: number;
  headers: Headers;
  body: string;
  stream?: ReadableStream<Uint8Array> | null;
}

export class Client {
  private readonly cfg: Required<Pick<ClientConfig, "server" | "gateway" | "runId" | "timeoutMs">> & ClientConfig;
  private readonly key: Promise<WorkloadKey>;
  private token = "";
  private expiry = 0;
  private readonly nonces = new Map<string, string>();

  constructor(cfg: ClientConfig) {
    if (!cfg.keyFile.identifier) throw new Error("the key file has no identifier: enroll the workload first");
    const server = (cfg.server ?? cfg.keyFile.server ?? "").replace(/\/$/, "");
    if (!server) throw new Error("the PantherClaw server URL is required");
    this.cfg = {
      ...cfg,
      server,
      gateway: (cfg.gateway ?? "").replace(/\/$/, ""),
      runId: cfg.runId ?? cfg.keyFile.run_id ?? "",
      timeoutMs: cfg.timeoutMs ?? 15_000,
    };
    this.key = keyOf(cfg.keyFile);
  }

  /** A workload token valid for at least another minute, renewed at the server when needed. */
  async workloadToken(force = false): Promise<string> {
    if (!force && this.token && Date.now() / 1000 + 60 < this.expiry) return this.token;
    const body = JSON.stringify({ identifier: this.cfg.keyFile.identifier });
    const res = await this.send("POST", `${this.cfg.server}/pantherclaw.v1.WorkloadService/IssueToken`, body, connect, true, 0);
    if (res.status !== 200) throw new Error(`token issuance: HTTP ${res.status} ${res.headers.get(HEADER_ERROR) ?? ""}`);
    const token = String((JSON.parse(res.body) as { workloadToken?: string }).workloadToken ?? "");
    const claims = parseTokenClaims(token);
    if (claims.cnf.jkt !== (await this.key).jkt) throw new Error("the server issued a token for another key");
    this.token = token;
    this.expiry = claims.exp;
    return token;
  }

  /** Sends with the workload token; a token_expired or invalid_token refusal renews it once. */
  protected async do(method: string, url: string, body: string, headers: Record<string, string>, extraMs = 0, signal?: AbortSignal): Promise<Sent> {
    const res = await this.send(method, url, body, headers, false, extraMs, signal);
    if (retry(res.status, res.headers) !== "refresh_token") return res;
    await this.workloadToken(true);
    return this.send(method, url, body, headers, false, extraMs, signal);
  }

  /** Signs and sends one request, retrying once with a fresh nonce (use_nonce). */
  private async send(
    method: string,
    url: string,
    body: string,
    headers: Record<string, string>,
    keyOnly: boolean,
    extraMs: number,
    signal?: AbortSignal,
  ): Promise<Sent> {
    const stream = headers.Accept === "text/event-stream";
    const timeout = stream ? undefined : AbortSignal.timeout(this.cfg.timeoutMs + extraMs);
    const signals = [timeout, signal].filter((x): x is AbortSignal => x !== undefined);
    for (let attempt = 0; ; attempt++) {
      const origin = new URL(url).origin;
      const token = keyOnly ? "" : await this.workloadToken();
      const proof = await signProof(await this.key, { method, url, body, token, nonce: this.nonces.get(origin) });
      const res = await (this.cfg.fetch ?? fetch)(url, {
        method,
        body: method === "GET" ? undefined : body,
        redirect: "error",
        signal: signals.length > 0 ? AbortSignal.any(signals) : undefined,
        headers: { ...headers, [HEADER_PROOF]: proof, ...(token ? { Authorization: `PAP ${token}` } : {}) },
      });
      const nonce = res.headers.get(HEADER_NONCE);
      if (nonce) this.nonces.set(origin, nonce);
      if (stream && res.status === 200) return { status: 200, headers: res.headers, body: "", stream: res.body };
      const text = await res.text();
      if (attempt === 0 && retry(res.status, res.headers) === "retry_nonce") continue;
      return { status: res.status, headers: res.headers, body: text };
    }
  }

  /** Asks the gateway's /sdk face about one call through the named connection. Never throws. */
  async authorize(connection: string, call: ToolCall, actionId: string, firstHash = ""): Promise<Result> {
    if (!this.cfg.gateway || !this.cfg.runId) return cannot("the gateway URL and the run id are required");
    if (!call.tool || !call.tool_use_id || typeof call.input !== "object" || call.input === null || Array.isArray(call.input)) {
      return cannot("a tool call needs a tool name, its id and an input object");
    }
    try {
      const res = await this.do("POST", `${this.cfg.gateway}/sdk/${encodeURIComponent(connection)}`, JSON.stringify(call), {
        "Content-Type": "application/json",
        "PAP-Run-Id": this.cfg.runId,
        "PC-Action-Id": actionId,
      });
      return evaluate(res.status, res.body, actionId, firstHash);
    } catch (e) {
      return cannot(`PantherClaw cannot decide: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** Long-polls a held call at the server: answers when the state differs from `known` or after `timeoutS` (at most 30). */
  async wait(handle: string, known = "", timeoutS = 30, signal?: AbortSignal): Promise<{ state: WaitState; timedOut: boolean }> {
    const req: Record<string, unknown> = { runId: this.cfg.runId, handle, timeoutSeconds: Math.min(timeoutS, 30) };
    if (known) req.knownState = `WAIT_STATE_${known}`;
    const res = await this.do("POST", `${this.cfg.server}/pantherclaw.v1.WorkloadService/Wait`, JSON.stringify(req), connect, timeoutS * 1000, signal);
    if (res.status !== 200) throw new Error(`wait: HTTP ${res.status}`);
    return parseWaitResponse(res.body);
  }

  /** Follows the server's SSE stream for a held call until `fn` returns false, the state is final or the stream ends. */
  async stream(handle: string, fn: (w: WaitState) => boolean, signal?: AbortSignal): Promise<void> {
    const res = await this.do("GET", `${this.cfg.server}/v1/wait/${encodeURIComponent(handle)}`, "", { Accept: "text/event-stream" }, 0, signal);
    if (res.status !== 200 || !res.stream) throw new Error(`wait stream: HTTP ${res.status}`);
    await readStream(res.stream, (w) => fn(w) && next(w) === "wait");
  }

  /**
   * Asks about a call and, while it is held, waits in PantherClaw (the SSE
   * stream, else long-polls) and resubmits the identical call with the same
   * action id once it is ready (PAP/1 §8). Never throws; past `deadlineMs`
   * the call cannot be decided.
   */
  async authorizeAndWait(connection: string, call: ToolCall, actionId: string, deadlineMs = 300_000): Promise<Result> {
    const until = Date.now() + deadlineMs;
    return this.resume(connection, call, actionId, await this.authorize(connection, call, actionId), Math.max(0, until - Date.now()));
  }

  /**
   * Continues from an answer: while it is a hold, waits in PantherClaw and
   * resubmits the identical call with the same action id, checking that it
   * maps to the same action. Never throws; past `deadlineMs` the call
   * cannot be decided.
   */
  async resume(connection: string, call: ToolCall, actionId: string, first: Result, deadlineMs = 300_000): Promise<Result> {
    const until = Date.now() + deadlineMs;
    let res = first;
    while (res.outcome === "hold") {
      const hash = res.answer?.action_hash ?? "";
      let w: WaitState;
      const stop = new AbortController();
      try {
        w = await withDeadline(this.waitReady(res.answer?.wait as WaitState, stop.signal), until);
      } catch (e) {
        return cannot(`the wait for PantherClaw's decision ended: ${e instanceof Error ? e.message : String(e)}`);
      } finally {
        // Ends a stream or long-poll still in flight at the deadline.
        stop.abort();
      }
      if (next(w) === "deny") return { outcome: "deny", answer: res.answer, why: `the hold ended: ${w.state} ${w.code ?? ""}` };
      res = await this.authorize(connection, call, actionId, hash);
    }
    return res;
  }

  private async waitReady(held: WaitState, signal: AbortSignal): Promise<WaitState> {
    let last: WaitState | undefined;
    try {
      await this.stream(
        held.handle,
        (w) => {
          last = w;
          return true;
        },
        signal,
      );
    } catch {
      // the stream is not available: long-poll instead
    }
    if (last && next(last) !== "wait") return last;
    let known = held.state ?? "";
    for (;;) {
      signal.throwIfAborted();
      const { state } = await this.wait(held.handle, known, 30, signal);
      if (next(state) !== "wait") return state;
      known = state.state ?? "";
    }
  }
}

/** What a wait state asks of the agent: keep waiting, resubmit the identical call, or stop. */
export function next(w: WaitState): "wait" | "resubmit" | "deny" {
  if (w.state === "PENDING" || w.state === "EVIDENCE_REQUESTED") return "wait";
  if (w.state === "READY" || w.state === "CONSUMED") return "resubmit";
  return "deny";
}

/** Reads a WorkloadService.Wait answer (Connect JSON). */
export function parseWaitResponse(body: string): { state: WaitState; timedOut: boolean } {
  const r = JSON.parse(body) as { wait?: Record<string, unknown>; timedOut?: boolean };
  if (!r.wait) throw new Error("no wait state");
  const w = r.wait;
  return {
    timedOut: r.timedOut === true,
    state: {
      handle: String(w.handle ?? ""),
      state: String(w.state ?? "").replace(/^WAIT_STATE_/, ""),
      code: w.code as string | undefined,
      deadline: w.deadlineTime as string | undefined,
      consume_by: w.consumeByTime as string | undefined,
      approval_request_id: w.approvalRequestId as string | undefined,
      retry_after_seconds: w.retryAfterSeconds as number | undefined,
    },
  };
}

const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);

/** Reads an SSE wait stream, calling `fn` for every state event until it returns false or the stream ends. */
export async function readStream(stream: ReadableStream<Uint8Array>, fn: (w: WaitState) => boolean): Promise<void> {
  const decoder = new TextDecoder();
  let buf = "";
  let event = "";
  let data = "";
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      buf += decoder.decode(value, { stream: true });
      if (buf.length > 64 << 10) throw new Error("wait event too long");
      let nl = buf.indexOf(LF);
      while (nl >= 0) {
        const line = buf.slice(0, nl).endsWith(CR) ? buf.slice(0, nl - 1) : buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line === "") {
          if (event === "state" && data && !fn(JSON.parse(data) as WaitState)) return;
          event = "";
          data = "";
        } else if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          data += line.slice(5).replace(/^ /, "");
        }
        nl = buf.indexOf(LF);
      }
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

function withDeadline<T>(p: Promise<T>, until: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("deadline")), Math.max(0, until - Date.now()));
    p.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

const connect = { "Content-Type": "application/json", "Connect-Protocol-Version": "1" };
