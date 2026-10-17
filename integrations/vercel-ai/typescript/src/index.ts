// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// PantherClaw for the Vercel AI SDK (PN-016.3, HR-328, HR-329). guardTools
// wraps each tool's execute: every call goes to the gateway's /sdk face of
// the connection that governs the tools before it runs, as the MCP tool
// mcp__<connection>__<tool name> (the face decides a call only as an MCP
// tool of the server named after its connection). Only PantherClaw's allow
// runs the tool. A hold waits in PantherClaw and runs only on its later
// allow; a deny, a call PantherClaw cannot decide, a wait that ends and any
// error return a refusal to the model without running the tool (fail
// closed, HR-200). Every decision is cooperative and labeled PARTIAL: the
// application runs the tool with its own access (HR-024).

import { randomBytes } from "node:crypto";
// The core client; once @pantherclaw/sdk is published, a build step imports it by name.
import { canonicalize, type Client, newActionId, type Outbound, type Result, type ToolCall } from "../../../../sdk/typescript/src/index.ts";

/** The rule for a connection's name (migration 00041): the tools are decided as the MCP server named after it. */
const CONNECTION_NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
/** How many held calls' action ids one guard remembers for an identical retry. */
const MAX_RETRIES = 1024;
/** How many refused tool call ids one guard remembers for toModelOutput. */
const MAX_REFUSED = 1024;

/** The AI SDK's options for one execution (the members this integration reads; `ai` ToolExecutionOptions). */
export interface ToolExecutionOptions {
  toolCallId: string;
  abortSignal?: AbortSignal;
  [k: string]: unknown;
}

/** An AI SDK tool (the members this integration reads and replaces; `ai` Tool). */
export interface Tool {
  type?: string;
  isProviderExecuted?: boolean;
  // biome-ignore lint/suspicious/noExplicitAny: the AI SDK's own tool input and output types
  execute?: (input: any, options: any) => unknown;
  // biome-ignore lint/suspicious/noExplicitAny: the AI SDK's own toModelOutput options
  toModelOutput?: (options: any) => unknown;
  [k: string]: unknown;
}

/** An AI SDK ToolSet: tools by the name the model calls them. */
export type ToolSet = Record<string, Tool>;

/**
 * Sends an allowed call's outbound request on a target-enforced connection,
 * whose target accepts only that exact request with its action token
 * (HR-201), and returns the tool's output (D53). It runs instead of the
 * tool's own execute, which would send a second request the action token
 * does not bind.
 */
export type DispatchHandler = (callId: string, send: Outbound) => unknown;

export interface GuardOptions {
  /** The PantherClaw client: key file, gateway and run. */
  client: Client;
  /** The connection that governs these tools; its package maps each tool by its name. */
  connection: string;
  /**
   * A hold: "wait" (the only choice, and the default) waits in PantherClaw
   * for up to `wait` seconds and runs the tool only on its later allow.
   * When the wait ends first, the call is refused, and an identical later
   * call resubmits the same action.
   */
  onHold?: "wait";
  /** How long a hold is waited on, in seconds (default 300, HR-174). */
  wait?: number;
  /** Let a tool the connection's package does not map run (default false: refused). */
  observeUnmapped?: boolean;
  /** Throw a PantherClawRefusal from execute instead of returning the refusal to the model (default false). */
  raiseOnRefusal?: boolean;
  /** Sends an allowed call's request on a target-enforced connection (see DispatchHandler). Without it such an allow is refused. */
  onDispatch?: DispatchHandler;
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
 * The refusal a call's final result is (D47), or null when the tool runs:
 * `first` is the first answer, `res` the final one, `resumed` whether a
 * hold was waited on.
 */
function refusal(first: Result, res: Result, resumed: boolean, observeUnmapped: boolean): PantherClawRefusal | null {
  const txn = res.answer?.transaction_id || first.answer?.transaction_id || "";
  if (res.outcome === "allow") return null;
  // A resubmission the engine answers duplicate_action was approved and ran in an identical concurrent call (D68, D79).
  if (resumed && res.answer?.code === "duplicate_action") return new PantherClawRefusal("duplicate_action", txn);
  if (resumed) return new PantherClawRefusal(res.outcome === "deny" ? "hold_declined" : "hold_timeout", txn);
  if (res.outcome === "deny") {
    if (res.answer?.code === "unknown_tool" && observeUnmapped) return null;
    return new PantherClawRefusal(res.answer?.code || "denied", txn);
  }
  return new PantherClawRefusal("cannot_decide", txn);
}

/**
 * Wraps every tool of a ToolSet so that PantherClaw decides each call
 * before it runs. It returns a new ToolSet; the original execute functions
 * are reachable only through the guard. A tool PantherClaw cannot govern is
 * refused when the tools are wrapped: a provider-executed tool (it runs at
 * the model provider) and a tool without execute (the application runs it
 * outside the AI SDK).
 */
export function guardTools<T extends ToolSet>(tools: T, options: GuardOptions): T {
  if (!options?.client || !options.connection) throw new Error("PantherClaw: a client and a connection are required");
  if (!CONNECTION_NAME.test(options.connection)) throw new Error(`PantherClaw: no connection can be named ${options.connection}`);
  const guard = new Guard(options);
  const out: ToolSet = {};
  for (const [name, t] of Object.entries(tools)) {
    if (t.type === "provider" && t.isProviderExecuted !== false) {
      throw new Error(`PantherClaw: the tool ${name} runs at the model provider, where PantherClaw cannot decide its calls`);
    }
    if (typeof t.execute !== "function") {
      throw new Error(`PantherClaw: the tool ${name} has no execute, so the application would run it without a decision`);
    }
    out[name] = guard.wrap(name, t);
  }
  return out as T;
}

class Guard {
  private readonly o: Required<Omit<GuardOptions, "onDispatch">> & Pick<GuardOptions, "onDispatch">;
  /**
   * Action ids of unresolved calls by their content (D68): a call in flight
   * (expires never) or held past its wait. An identical call meanwhile
   * resubmits the same action (PAP/1 §8); a final outcome forgets it.
   */
  private readonly retries = new Map<string, { actionId: string; expires: number }>();
  /** Tool call ids refused, so a tool's toModelOutput never reads a refusal as its output. */
  private readonly refused = new Map<string, string>();

  constructor(options: GuardOptions) {
    this.o = { onHold: "wait", wait: 300, observeUnmapped: false, raiseOnRefusal: false, ...options };
    if (this.o.onHold !== "wait") throw new Error('PantherClaw: onHold is "wait"');
    if (!(this.o.wait > 0)) throw new Error("PantherClaw: wait is a number of seconds above 0");
  }

  wrap(name: string, t: Tool): Tool {
    const run = t.execute as NonNullable<Tool["execute"]>;
    const schema = t.inputSchema;
    // A streaming tool (an async generator) stays one: the guard decides, then yields the tool's own values.
    const execute =
      run.constructor?.name === "AsyncGeneratorFunction"
        ? async function* (this: Guard, input: unknown, options: ToolExecutionOptions) {
            const v = await this.guarded(name, schema, input, options);
            if (v.run === undefined) yield v.out;
            else yield* run(v.run, options) as AsyncIterable<unknown>;
          }.bind(this)
        : async (input: unknown, options: ToolExecutionOptions) => {
            const v = await this.guarded(name, schema, input, options);
            return v.run === undefined ? v.out : run(v.run, options);
          };
    const wrapped: Tool = { ...t, execute };
    if (typeof t.toModelOutput === "function") {
      const own = t.toModelOutput;
      wrapped.toModelOutput = (o: { toolCallId?: string }) => {
        const why = o?.toolCallId ? this.refused.get(o.toolCallId) : undefined;
        return why === undefined ? own(o) : { type: "text", value: why };
      };
    }
    return wrapped;
  }

  /**
   * Decides a call: `run` is the decided input to run the tool on (D69: the
   * input parsed through the tool's own schema, copied when it was decided,
   * so what runs is what was decided), or else `out` is the call's output
   * (a refusal, or the dispatch handler's).
   */
  private async guarded(name: string, schema: unknown, input: unknown, options: ToolExecutionOptions): Promise<{ run?: Record<string, unknown>; out?: unknown }> {
    if (options?.toolCallId) this.refused.delete(options.toolCallId);
    let d: Awaited<ReturnType<Guard["decide"]>>;
    try {
      const parsed = await parse(schema, input);
      d = parsed === undefined ? { refusal: new PantherClawRefusal("undecided_args"), id: "", txn: "" } : await this.decide(name, parsed, options);
    } catch {
      d = { refusal: new PantherClawRefusal("wrapper_error"), id: "", txn: "" };
    }
    if (d.refusal) return { out: this.refuse(d.refusal, options) };
    if (d.send) {
      if (!this.o.onDispatch) return { out: this.refuse(new PantherClawRefusal("dispatch_required", d.txn), options) };
      return { out: await this.o.onDispatch(d.id, d.send) };
    }
    return { run: d.input };
  }

  private refuse(r: PantherClawRefusal, options: ToolExecutionOptions): string {
    if (this.o.raiseOnRefusal) throw r;
    if (options?.toolCallId) {
      this.refused.set(options.toolCallId, r.message);
      if (this.refused.size > MAX_REFUSED) this.refused.delete(this.refused.keys().next().value as string);
    }
    return r.message;
  }

  private async decide(
    name: string,
    raw: unknown,
    options: ToolExecutionOptions,
  ): Promise<{ refusal: PantherClawRefusal | null; send?: Outbound; id: string; txn: string; input?: Record<string, unknown> }> {
    // The client refuses a call whose input is not an object (cannot_decide).
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return { refusal: new PantherClawRefusal("cannot_decide"), id: "", txn: "" };
    // The schema-parsed input (D69), copied: the decision and the run use this copy.
    const input = JSON.parse(JSON.stringify(raw)) as Record<string, unknown>;
    const server = this.o.connection;
    const call: ToolCall = { tool: `mcp__${server}__${name}`, server, input, tool_use_id: callId(options?.toolCallId) };
    const key = JSON.stringify([name, canonicalize(JSON.stringify(input))]);
    this.prune();
    const actionId = this.retries.get(key)?.actionId ?? newActionId();
    const waitMs = this.o.wait * 1000;
    this.retries.set(key, { actionId, expires: Number.POSITIVE_INFINITY });
    if (this.retries.size > MAX_RETRIES) this.retries.delete(this.retries.keys().next().value as string);
    let unresolved = false;
    try {
      const first = await this.o.client.authorize(server, call, actionId);
      let res = first;
      if (first.outcome === "hold") {
        try {
          res = await withSignal(this.o.client.resume(server, call, actionId, first, waitMs, options?.abortSignal), options?.abortSignal);
        } catch {
          // The wait was aborted: the hold ran out for this call (D47).
          res = { outcome: "cannot_decide", why: "the wait was aborted" };
        }
        // Held past the wait: the action is still unresolved in PantherClaw, so an identical later call resubmits it.
        unresolved = res.outcome === "cannot_decide";
      }
      const r = refusal(first, res, first.outcome === "hold", this.o.observeUnmapped);
      return { refusal: r, send: r ? undefined : res.send, id: call.tool_use_id, txn: res.answer?.transaction_id ?? "", input };
    } finally {
      const e = this.retries.get(key);
      if (e?.actionId === actionId) {
        if (unresolved) e.expires = Date.now() + waitMs;
        else this.retries.delete(key);
      }
    }
  }

  /** Forgets retry ids past their wait. */
  private prune(): void {
    const now = Date.now();
    for (const [k, r] of this.retries) if (r.expires < now) this.retries.delete(k);
  }
}

/**
 * The input parsed through the tool's own input schema into exactly what
 * execute receives (D69): a Standard Schema (zod and others), an AI SDK
 * schema with its validate, or an AI SDK JSON Schema without one (its
 * declared properties only). undefined when the input fails the schema, the
 * schema drops a key the model sent, or the parsed value is not plain JSON
 * (bigint, Date, Map, a class instance, an undefined member), so the
 * decision would not be on what runs.
 */
async function parse(schema: unknown, input: unknown): Promise<Record<string, unknown> | undefined> {
  let value: unknown;
  for (let lazy = 0; typeof schema === "function" && lazy < 4; lazy++) schema = (schema as () => unknown)();
  const s = schema as Record<PropertyKey, unknown> | null | undefined;
  if (s == null) {
    value = input;
    if (typeof input === "object" && input !== null && Object.keys(input).length > 0) return undefined;
  } else if (typeof s["~standard"] === "object" && s["~standard"] !== null) {
    const r = (await (s["~standard"] as { validate: (v: unknown) => unknown }).validate(input)) as { value?: unknown; issues?: unknown };
    if (r.issues) return undefined;
    value = r.value;
  } else if (s[Symbol.for("vercel.ai.schema")] === true) {
    if (typeof s.validate === "function") {
      const r = (await (s.validate as (v: unknown) => unknown)(input)) as { success: boolean; value?: unknown };
      if (!r?.success) return undefined;
      value = r.value;
    } else {
      // A JSON Schema the AI SDK does not validate: only its declared properties are decided.
      const props = (s.jsonSchema as { properties?: object } | undefined)?.properties ?? {};
      if (typeof input !== "object" || input === null || Object.keys(input).some((k) => !Object.hasOwn(props, k))) return undefined;
      value = input;
    }
  } else {
    return undefined;
  }
  if (typeof value !== "object" || value === null || Array.isArray(value) || !plainJSON(value) || dropsKeys(input, value)) return undefined;
  return value as Record<string, unknown>;
}

/** Whether a value is plain JSON: null, booleans, finite numbers, strings, arrays and plain objects of them. */
function plainJSON(v: unknown): boolean {
  if (v === null || typeof v === "boolean" || typeof v === "string") return true;
  if (typeof v === "number") return Number.isFinite(v);
  if (Array.isArray(v)) return v.every(plainJSON);
  if (typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) return false;
  return Object.values(v as object).every((x) => x !== undefined && plainJSON(x));
}

/** Whether parsing dropped a member the model sent, at any depth. */
function dropsKeys(raw: unknown, parsed: unknown): boolean {
  if (Array.isArray(raw) && Array.isArray(parsed)) return raw.length === parsed.length && raw.some((x, i) => dropsKeys(x, parsed[i]));
  if (typeof raw !== "object" || raw === null || Array.isArray(raw) || typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return false;
  return Object.keys(raw).some((k) => !Object.hasOwn(parsed, k) || dropsKeys((raw as Record<string, unknown>)[k], (parsed as Record<string, unknown>)[k]));
}

/** The AI SDK's id of a call, or a fresh one when it is missing or one the faces refuse. */
function callId(id: string | undefined): string {
  return id && /^[A-Za-z0-9_-]{1,128}$/.test(id) ? id : `pc-${randomBytes(16).toString("hex")}`;
}

/** Ends a wait when the AI SDK aborts the call. */
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
