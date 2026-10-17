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
 * (HR-201), and returns the tool's output. It runs instead of the tool's
 * own execute, whose request the target would refuse.
 */
export type DispatchHandler = (send: Outbound, input: Record<string, unknown>, options: ToolExecutionOptions) => unknown;

export interface GuardOptions {
  /** The PantherClaw client: key file, gateway and run. */
  client: Client;
  /** The connection that governs these tools; its package maps each tool by its name. */
  connection: string;
  /**
   * A hold: "wait" (default) waits in PantherClaw for up to `wait` seconds
   * and runs the tool only on its later allow; "refuse" returns a refusal
   * at once, and an identical later call resubmits the same action.
   */
  onHold?: "wait" | "refuse";
  /** How long a hold is waited on, in seconds (default 300, HR-174). */
  wait?: number;
  /** Let a tool the connection's package does not map run (default false: refused). */
  observeUnmapped?: boolean;
  /** Throw a PantherClawRefusal from execute instead of returning the refusal to the model (default false). */
  raiseOnRefusal?: boolean;
  /** Handlers for tools on a target-enforced connection, by tool name (see DispatchHandler). Without one such an allow is refused. */
  onDispatch?: Record<string, DispatchHandler>;
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

/** The refusal a result is, or null for an allow. */
function refusal(res: Result, observeUnmapped: boolean): PantherClawRefusal | null {
  const a = res.answer;
  const txn = a?.transaction_id ?? a?.wait?.handle ?? "";
  switch (res.outcome) {
    case "allow":
      return null;
    case "hold":
      return new PantherClawRefusal("held", txn);
    case "deny":
      if (a?.code === "unknown_tool" && observeUnmapped) return null;
      return new PantherClawRefusal(a?.code || a?.error_class || "denied", txn);
    default:
      return new PantherClawRefusal(a?.code || "cannot_decide", txn);
  }
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
  /** Action ids of held calls by their content, so an identical later call resubmits the same action (PAP/1 §8). */
  private readonly retries = new Map<string, { actionId: string; expires: number }>();
  /** Tool call ids refused, so a tool's toModelOutput never reads a refusal as its output. */
  private readonly refused = new Map<string, string>();

  constructor(options: GuardOptions) {
    this.o = { onHold: "wait", wait: 300, observeUnmapped: false, raiseOnRefusal: false, ...options };
    if (this.o.onHold !== "wait" && this.o.onHold !== "refuse") throw new Error('PantherClaw: onHold is "wait" or "refuse"');
    if (!(this.o.wait > 0)) throw new Error("PantherClaw: wait is a number of seconds above 0");
  }

  wrap(name: string, t: Tool): Tool {
    const run = t.execute as NonNullable<Tool["execute"]>;
    const handler = this.o.onDispatch?.[name];
    const wrapped: Tool = { ...t, execute: (input: unknown, options: ToolExecutionOptions) => this.execute(name, run, handler, input, options) };
    if (typeof t.toModelOutput === "function") {
      const own = t.toModelOutput;
      wrapped.toModelOutput = (o: { toolCallId?: string }) => {
        const why = o?.toolCallId ? this.refused.get(o.toolCallId) : undefined;
        return why === undefined ? own(o) : { type: "text", value: why };
      };
    }
    return wrapped;
  }

  private async execute(name: string, run: NonNullable<Tool["execute"]>, handler: DispatchHandler | undefined, input: unknown, options: ToolExecutionOptions): Promise<unknown> {
    let r: PantherClawRefusal | null;
    let send: Outbound | undefined;
    try {
      ({ refusal: r, send } = await this.decide(name, input, options));
    } catch (e) {
      r = new PantherClawRefusal("cannot_decide");
    }
    if (r) return this.refuse(r, options);
    if (send) {
      if (!handler) return this.refuse(new PantherClawRefusal("dispatch_handler_required"), options);
      return handler(send, input as Record<string, unknown>, options);
    }
    return run(input, options);
  }

  private refuse(r: PantherClawRefusal, options: ToolExecutionOptions): string {
    if (this.o.raiseOnRefusal) throw r;
    if (options?.toolCallId) {
      this.refused.set(options.toolCallId, r.message);
      if (this.refused.size > MAX_REFUSED) this.refused.delete(this.refused.keys().next().value as string);
    }
    return r.message;
  }

  private async decide(name: string, input: unknown, options: ToolExecutionOptions): Promise<{ refusal: PantherClawRefusal | null; send?: Outbound }> {
    if (typeof input !== "object" || input === null || Array.isArray(input)) return { refusal: new PantherClawRefusal("input_not_object") };
    const server = this.o.connection;
    const call: ToolCall = { tool: `mcp__${server}__${name}`, server, input: input as Record<string, unknown>, tool_use_id: callId(options?.toolCallId) };
    const key = JSON.stringify([name, canonicalize(JSON.stringify(input))]);
    this.prune();
    const actionId = this.retries.get(key)?.actionId ?? newActionId();
    const waitMs = this.o.wait * 1000;
    let res = await this.o.client.authorize(server, call, actionId);
    if (res.outcome === "hold") {
      this.retries.set(key, { actionId, expires: Date.now() + waitMs });
      if (this.retries.size > MAX_RETRIES) this.retries.delete(this.retries.keys().next().value as string);
      if (this.o.onHold === "wait") res = await withSignal(this.o.client.resume(server, call, actionId, res, waitMs), options?.abortSignal);
    }
    const r = refusal(res, this.o.observeUnmapped);
    if (res.outcome === "allow") this.retries.delete(key);
    return { refusal: r, send: r ? undefined : res.send };
  }

  /** Forgets retry ids past their wait. */
  private prune(): void {
    const now = Date.now();
    for (const [k, r] of this.retries) if (r.expires < now) this.retries.delete(k);
  }
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
