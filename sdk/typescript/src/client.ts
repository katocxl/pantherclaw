// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The PantherClaw workload client (PAP/1): a proof over every request,
// the servers' nonces, workload token renewal, the gateway's /sdk and /hook
// faces and waits on held calls. It fails closed (HR-200): when PantherClaw
// cannot decide, the outcome is "cannot_decide", never "allow".

import { createHash, randomBytes } from "node:crypto";
import { parseAction } from "./action.ts";
import { type JSONValue, parseJSON } from "./jcs.ts";
import { fromB64url, HEADER_ERROR, HEADER_NONCE, HEADER_PROOF, type KeyFile, keyOf, parseTokenClaims, signProof, type WorkloadKey } from "./pap.ts";

/** A raw tool call as the agent made it; the gateway maps it (HR-201). */
export interface ToolCall {
  /** The agent's name for the tool: mcp__<server>__<tool>, or a tool the agent SDK has built in. */
  tool: string;
  /** The MCP server's name, for an MCP tool only. */
  server?: string;
  input: Record<string, unknown>;
  /** The agent's id of the call. */
  tool_use_id: string;
}

/**
 * How a call goes to the /sdk face: an MCP tool PantherClaw decides
 * ("mapped"), a built-in tool sent so PantherClaw records it ("builtin",
 * the only kind an observe answer lets run), or neither ("refused": never
 * sent, never run, HR-200).
 */
export type CallClass = "mapped" | "builtin" | "refused";

/**
 * The rule for a connection's name (migration 00041). A connection governs
 * the one MCP server named after it, so no other server name is routed.
 */
const connectionName = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Sorts an agent's tool name: mcp__<server>__<tool> is mapped with that
 * server when exactly one of `servers` fits it with a tool name after it
 * and that server's name is a connection's name (the call goes to the
 * connection named after it). A tool whose name two servers' names fit
 * ("notes" and "notes__v2" both fit mcp__notes__v2__search) is refused,
 * since either server might run it. A name in `builtins` (exactly) is a
 * built-in; anything else is refused.
 */
export function classify(tool: string, servers: readonly string[], builtins: readonly string[]): { cls: CallClass; server?: string } {
  if (tool.startsWith("mcp__")) {
    const rest = tool.slice(5);
    const fits = new Set(servers.filter((s) => rest.length > s.length + 2 && rest.startsWith(`${s}__`)));
    const [server] = fits;
    return fits.size === 1 && connectionName.test(server) ? { cls: "mapped", server } : { cls: "refused" };
  }
  return builtins.includes(tool) ? { cls: "builtin" } : { cls: "refused" };
}

/** What the agent may do with a call: only allow, and observe for a built-in, let it run. */
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

/** The gateway's re-serialization of an allowed action for a target-enforced connection (HR-201). */
export interface Dispatch {
  method: string;
  url: string;
  headers: Record<string, string>;
  /** The exact body, base64url. */
  body: string;
  action_token: string;
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
  dispatch?: Dispatch;
}

/** The request to send a target-enforced connection's target: exactly the gateway's. */
export interface Outbound {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

export interface Result {
  outcome: Outcome;
  answer?: Answer;
  /** For an allow on a target-enforced connection: the request to send instead of building one. */
  send?: Outbound;
  why: string;
}

const cannot = (why: string): Result => ({ outcome: "cannot_decide", why });

/**
 * The outbound request as a fetch Request. Add the application's own
 * credential for the target, when it has one, and change nothing else: the
 * target refuses any other body (HR-202). Redirects are refused.
 */
export function outboundRequest(o: Outbound): Request {
  return new Request(o.url, { method: o.method, headers: o.headers, body: o.body.length > 0 ? o.body : undefined, redirect: "error" });
}

/** The one retry a 401 allows: with its fresh nonce, or with a renewed token. "" otherwise. */
export function retry(status: number, headers: Headers): "retry_nonce" | "refresh_token" | "" {
  if (status !== 401) return "";
  const code = headers.get(HEADER_ERROR);
  if (code === "use_nonce" && headers.get(HEADER_NONCE)) return "retry_nonce";
  if (code === "token_expired" || code === "invalid_token") return "refresh_token";
  return "";
}

/** Strict JSON (duplicate members refused) as plain values. */
function plain(v: JSONValue): unknown {
  if (v instanceof Map) return Object.fromEntries([...v].map(([k, x]) => [k, plain(x)]));
  return Array.isArray(v) ? v.map(plain) : v;
}

/**
 * Reads a /sdk answer to a call of class `cls`, for the action id the SDK
 * sent. `firstHash`, when set, is the hash of an earlier answer for the
 * same action. Anything it cannot read or check is cannot_decide (HR-200,
 * HR-201).
 */
export function evaluate(status: number, body: string, cls: CallClass, actionId: string, firstHash = ""): Result {
  if (status !== 200) return cannot(`the gateway answered HTTP ${status}`);
  let a: Answer;
  try {
    const v = plain(parseJSON(body));
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
    a = v as Answer;
  } catch {
    return cannot("the gateway's answer is not readable");
  }
  const r: Result = { outcome: "deny", answer: a, why: a.reason ?? "" };
  switch (a.decision) {
    case "deny":
      return r;
    case "allow":
      if (a.coverage === "OBSERVE_ONLY") {
        if (cls !== "builtin") return cannot("an observe answer for a call that is not a built-in tool");
        if (a.mode !== "monitor" || a.action_hash || a.action_ir || a.dispatch) return cannot("an observed call that is not only recorded");
        return { ...r, outcome: "observe" };
      }
      r.outcome = "allow";
      break;
    case "hold":
      if (!a.wait?.handle) return cannot("a hold without a wait handle");
      if (a.dispatch) return cannot("a hold with a request to send");
      r.outcome = "hold";
      break;
    default:
      return cannot(`unknown decision ${a.decision}`);
  }
  const problem = checkAction(a, actionId, firstHash);
  if (problem) return cannot(problem);
  if (a.dispatch) {
    const send = checkDispatch(a.dispatch);
    if (typeof send === "string") return cannot(send);
    r.send = send;
  }
  return r;
}

function checkAction(a: Answer, actionId: string, firstHash: string): string {
  if (a.coverage !== "PARTIAL") return "a decided call that is not labeled PARTIAL";
  if (a.action_id !== actionId) return "the answer is for another action";
  if (!/^[0-9a-f]{64}$/.test(a.action_hash ?? "")) return "the answer has no action hash";
  if (firstHash && a.action_hash !== firstHash) return "the resubmitted call mapped to another action";
  if (typeof a.action_ir !== "string" || a.action_ir === "") return "the answer does not carry the action it decided";
  try {
    const p = parseAction(fromB64url(a.action_ir));
    if (p.hash !== a.action_hash) return "the action hash does not match the action";
    if (p.action.get("action_id") !== actionId) return "the mapped action is for another action id";
    const conn = p.action.get("connection");
    if (p.action.get("channel") !== "sdk" || typeof conn !== "string" || conn === "") return "the mapped action did not come through an SDK connection";
  } catch {
    return "the canonical action is not valid ActionIR";
  }
  return "";
}

/** Checks a dispatch: its PAP-Action header is its token, whose pap.bh binds the body. The signature is the target's to verify. */
function checkDispatch(d: Dispatch): Outbound | string {
  try {
    const body = fromB64url(String(d.body ?? ""));
    const u = new URL(String(d.url));
    if ((u.protocol !== "https:" && u.protocol !== "http:") || !d.method) return "the request to send has no method or absolute URL";
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(d.headers ?? {})) headers[k] = String(v);
    const action = Object.entries(headers).find(([k]) => k.toLowerCase() === "pap-action")?.[1];
    if (!d.action_token || action !== d.action_token) return "the request to send does not carry its action token";
    const parts = d.action_token.split(".");
    if (parts.length !== 3) return "the action token is not a compact JWS";
    const claims = plain(parseJSON(fromB64url(parts[1] ?? ""))) as { pap?: { bh?: unknown } };
    if (claims?.pap?.bh !== createHash("sha256").update(body).digest("hex")) return "the action token does not bind the body to send";
    return { method: d.method, url: d.url, headers, body };
  } catch {
    return "the request to send is not readable";
  }
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

/** A shell command for the local connection's /hook face (pc.shell), as `pclaw hook claude-code` sends it. */
export interface ShellCall {
  shell: "bash" | "powershell";
  command: string;
  /** The absolute, final working directory (links resolved). */
  cwd: string;
  /** The agent's id of the call. */
  call: string;
}

/** The /hook face's answer: allow, or deny (held: an eligible person may approve it in PantherClaw). */
export interface HookAnswer {
  decision?: string;
  reason?: string;
  error_class?: string;
  code?: string;
  transaction_id?: string;
  held?: boolean;
  mode?: string;
}

export interface HookResult {
  outcome: "allow" | "deny" | "cannot_decide";
  /** The deny is a hold: once approved in PantherClaw, the same command runs. */
  held: boolean;
  answer?: HookAnswer;
  why: string;
}

/** The largest request the /sdk and /hook faces read. */
export const MAX_CALL_BODY = 64 << 10;

const toolUseId = /^[A-Za-z0-9_-]{1,128}$/;
const encoder = new TextEncoder();

/** Whether a base URL may carry workload tokens and proofs: https, or http to a loopback address. */
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

export interface ClientConfig {
  /** The workload key file: its identifier is required; its server and run are defaults. */
  keyFile: KeyFile;
  server?: string;
  /** The base URL of the gateway whose /sdk face decides calls. */
  gateway?: string;
  runId?: string;
  /**
   * The names of the tools the agent SDK has built in. Only these are
   * sent without a server, and only for them does an observe answer let
   * the call run. Empty: no call is a built-in.
   */
  builtins?: readonly string[];
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

/** How long past a hold's deadline the client still waits to hear how it ended. */
const WAIT_GRACE_MS = 5_000;
/** How often one call is resubmitted and held again before the client gives up. */
const MAX_RESUBMITS = 3;

export class Client {
  private readonly cfg: Required<Pick<ClientConfig, "server" | "gateway" | "runId" | "timeoutMs" | "builtins">> & ClientConfig;
  private readonly key: Promise<WorkloadKey>;
  private token = "";
  private expiry = 0;
  private readonly nonces = new Map<string, string>();

  constructor(cfg: ClientConfig) {
    if (!cfg.keyFile.identifier) throw new Error("the key file has no identifier: enroll the workload first");
    const server = (cfg.server ?? cfg.keyFile.server ?? "").replace(/\/$/, "");
    if (!server) throw new Error("the PantherClaw server URL is required");
    const gateway = (cfg.gateway ?? "").replace(/\/$/, "");
    if (!secure(server) || (gateway && !secure(gateway))) {
      throw new Error("the server and gateway URLs must use https (http only on a loopback address) and carry no user information");
    }
    this.cfg = {
      ...cfg,
      server,
      gateway,
      runId: cfg.runId ?? cfg.keyFile.run_id ?? "",
      timeoutMs: cfg.timeoutMs ?? 15_000,
      builtins: cfg.builtins ?? [],
    };
    this.key = keyOf(cfg.keyFile);
  }

  /** A workload token valid for at least another minute, renewed at the server when needed. */
  async workloadToken(force = false): Promise<string> {
    if (!force && this.token && Date.now() / 1000 + 60 < this.expiry) return this.token;
    const body = JSON.stringify({ identifier: this.cfg.keyFile.identifier });
    const res = await this.send("POST", `${this.cfg.server}/pantherclaw.v1.WorkloadService/IssueToken`, body, connect, true, 0);
    if (res.status !== 200) throw new Error(`token issuance: HTTP ${res.status} ${res.headers.get(HEADER_ERROR) ?? ""}`);
    const token = String((plain(parseJSON(res.body)) as { workloadToken?: string }).workloadToken ?? "");
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

  /**
   * The class of a call as the client sends it: an MCP tool names its
   * server, whose name is a connection's; a built-in names none and is
   * configured.
   */
  private classOf(call: ToolCall): CallClass {
    if (call.server) {
      const fits = call.tool.startsWith(`mcp__${call.server}__`) && call.tool.length > call.server.length + 7;
      return fits && connectionName.test(call.server) ? "mapped" : "refused";
    }
    return !call.tool.startsWith("mcp__") && this.cfg.builtins.includes(call.tool) ? "builtin" : "refused";
  }

  /**
   * Asks the gateway's /sdk face about one call. An MCP tool's call goes to
   * the connection named after its server, the one connection that governs
   * it; a built-in tool's call goes to `connection`, which records it.
   * Never throws.
   */
  async authorize(connection: string, call: ToolCall, actionId: string, firstHash = ""): Promise<Result> {
    if (!this.cfg.gateway || !this.cfg.runId) return cannot("the gateway URL and the run id are required");
    if (!call.tool || !toolUseId.test(call.tool_use_id) || typeof call.input !== "object" || call.input === null || Array.isArray(call.input)) {
      return cannot("a tool call needs a tool name, its id and an input object");
    }
    const cls = this.classOf(call);
    if (cls === "refused") return cannot(`PantherClaw neither maps ${call.tool} as an MCP tool nor knows it as a built-in tool`);
    const target = cls === "mapped" ? (call.server as string) : connection;
    if (!connectionName.test(target)) return cannot(`no connection is named ${target}`);
    const body = JSON.stringify({ tool: call.tool, server: call.server, input: call.input, tool_use_id: call.tool_use_id });
    if (encoder.encode(body).length > MAX_CALL_BODY) return cannot("the tool call is larger than the /sdk face takes");
    try {
      const res = await this.do("POST", `${this.cfg.gateway}/sdk/${target}`, body, {
        "Content-Type": "application/json",
        "PAP-Run-Id": this.cfg.runId,
        "PC-Action-Id": actionId,
      });
      return evaluate(res.status, res.body, cls, actionId, firstHash);
    } catch (e) {
      return cannot(`PantherClaw cannot decide: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /**
   * Asks the local connection's /hook face (pc.shell) about a shell
   * command, as Claude Code's hook does. Allow only on an allow; a hold is
   * a deny with `held`, approved in PantherClaw and never by the local user
   * (HR-186). Never throws.
   */
  async hook(connection: string, call: ShellCall): Promise<HookResult> {
    const no = (why: string): HookResult => ({ outcome: "cannot_decide", held: false, why });
    if (!this.cfg.gateway || !this.cfg.runId) return no("the gateway URL and the run id are required");
    if ((call.shell !== "bash" && call.shell !== "powershell") || !call.command || !call.cwd || !toolUseId.test(call.call)) {
      return no("a shell call needs its shell, a command, a working directory and its id");
    }
    const body = JSON.stringify({ input: { call: call.call, command: call.command, cwd: call.cwd, shell: call.shell }, tool: "shell" });
    if (encoder.encode(body).length > MAX_CALL_BODY) return no("the command is larger than the /hook face takes");
    let res: Sent;
    try {
      res = await this.do("POST", `${this.cfg.gateway}/hook/${encodeURIComponent(connection)}`, body, {
        "Content-Type": "application/json",
        "PAP-Run-Id": this.cfg.runId,
      });
    } catch (e) {
      return no(`PantherClaw cannot decide: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (res.status !== 200) return no(`the gateway answered HTTP ${res.status}`);
    let a: HookAnswer;
    try {
      const v = plain(parseJSON(res.body));
      if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
      a = v as HookAnswer;
    } catch {
      return no("the gateway's answer is not readable");
    }
    if (a.decision === "allow") return { outcome: "allow", held: false, answer: a, why: a.reason ?? "" };
    if (a.decision === "deny") return { outcome: "deny", held: a.held === true, answer: a, why: a.reason ?? "" };
    return no(`unknown decision ${a.decision}`);
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
   * maps to the same action. A wait ends at `deadlineMs` or at the hold's
   * own deadline (plus a few seconds' grace), and a call held again after
   * three resubmissions is not resubmitted; each is cannot_decide. Never
   * throws.
   */
  async resume(connection: string, call: ToolCall, actionId: string, first: Result, deadlineMs = 300_000): Promise<Result> {
    const until = Date.now() + deadlineMs;
    let res = first;
    for (let resubmits = 0; res.outcome === "hold"; resubmits++) {
      if (resubmits === MAX_RESUBMITS) return cannot(`the call was held again after ${MAX_RESUBMITS} resubmissions`);
      const hash = res.answer?.action_hash ?? "";
      const held = res.answer?.wait as WaitState;
      const deadline = Date.parse(held.deadline ?? "");
      const end = Number.isFinite(deadline) ? Math.min(until, deadline + WAIT_GRACE_MS) : until;
      let w: WaitState;
      const stop = new AbortController();
      try {
        w = await withDeadline(this.waitReady(held, stop.signal), end);
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
  const r = plain(parseJSON(body)) as { wait?: Record<string, unknown>; timedOut?: boolean };
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
/** The longest line or event an SSE wait stream may send. */
const MAX_EVENT = 64 << 10;

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
      if (buf.length > MAX_EVENT) throw new Error("wait event too long");
      let nl = buf.indexOf(LF);
      while (nl >= 0) {
        const line = buf.slice(0, nl).endsWith(CR) ? buf.slice(0, nl - 1) : buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line === "") {
          if (event === "state" && data && !fn(plain(parseJSON(data)) as WaitState)) return;
          event = "";
          data = "";
        } else if (line.startsWith("event:")) {
          event = line.slice(6).trim();
        } else if (line.startsWith("data:")) {
          data += line.slice(5).replace(/^ /, "");
          if (data.length > MAX_EVENT) throw new Error("wait event too long");
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
