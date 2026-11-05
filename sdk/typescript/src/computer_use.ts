// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Computer use decided by PantherClaw (M33 D984; HR-758). ComputerUseGuard
// asks the local connection's /hook face (package pc.computer, hook tool
// `computer`) about each input action a model asks for: an Anthropic
// `computer_*` tool use (decideAnthropic) or an OpenAI computer_call
// (decideOpenAI). Only an allow lets the action run. Screenshots, waits,
// cursor positions and zooms read the screen and are allowed locally,
// never sent. An action the guard does not know is refused locally
// (COMPUTER_ACTION_UNKNOWN), and any failure refuses (fail closed, HR-200).
// Every decision is cooperative and PARTIAL: only actions sent through the
// guard are decided.

import { randomBytes } from "node:crypto";
import type { Client, HookResult } from "./client.ts";

export const CODE_ACTION_UNKNOWN = "COMPUTER_ACTION_UNKNOWN";
export const CODE_CANNOT_DECIDE = "CANNOT_DECIDE";

/** What the agent may do with one computer action: only `allowed` lets it run. */
export interface ComputerDecision {
  allowed: boolean;
  held: boolean;
  code: string;
  reason: string;
  transaction_id: string;
}

/** An Anthropic computer tool use block. */
export interface AnthropicToolUse {
  id?: string;
  name?: string;
  input?: Record<string, unknown>;
}

/** An OpenAI computer_call output item. */
export interface OpenAIComputerCall {
  call_id?: string;
  action?: Record<string, unknown>;
}

const TOOL = "computer";
const callRe = /^[A-Za-z0-9_-]{1,128}$/;
const localAnthropic = new Set(["screenshot", "wait", "cursor_position", "zoom"]);
const localOpenAI = new Set(["screenshot", "wait"]);
const anthropicKinds: Record<string, [string, string]> = {
  left_click: ["click", "left"],
  right_click: ["click", "right"],
  middle_click: ["click", "middle"],
  double_click: ["double_click", ""],
  triple_click: ["triple_click", ""],
  left_click_drag: ["drag", ""],
  left_mouse_down: ["press", ""],
  left_mouse_up: ["release", ""],
  type: ["type", ""],
  key: ["key", ""],
  hold_key: ["key", ""],
  scroll: ["scroll", ""],
  mouse_move: ["move", ""],
};
const openAIKinds: Record<string, string> = {
  click: "click",
  double_click: "double_click",
  drag: "drag",
  keypress: "key",
  type: "type",
  scroll: "scroll",
  move: "move",
};
const openAIButtons: Record<string, string> = { left: "left", right: "right", wheel: "middle", middle: "middle", back: "back", forward: "forward" };
const localReason = "PantherClaw allows reading the screen locally; nothing was sent.";

function refused(code: string, reason: string): ComputerDecision {
  return { allowed: false, held: false, code, reason, transaction_id: "" };
}

function allowedLocally(): ComputerDecision {
  return { allowed: true, held: false, code: "", reason: localReason, transaction_id: "" };
}

function callId(raw: unknown): string {
  return typeof raw === "string" && callRe.test(raw) ? raw : `pc-${randomBytes(16).toString("hex")}`;
}

function int(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : undefined;
}

/** An [x, y] pair or an {x, y} object. */
function point(raw: unknown): [number, number] | undefined {
  let x: number | undefined;
  let y: number | undefined;
  if (Array.isArray(raw)) {
    if (raw.length !== 2) return undefined;
    [x, y] = [int(raw[0]), int(raw[1])];
  } else if (typeof raw === "object" && raw !== null) {
    const o = raw as Record<string, unknown>;
    [x, y] = [int(o.x), int(o.y)];
  }
  return x !== undefined && y !== undefined ? [x, y] : undefined;
}

function at(out: Record<string, unknown>, p: [number, number] | undefined): void {
  if (p) [out.x, out.y] = p;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Decides computer actions through `connection`, a local connection whose package is pc.computer. */
export class ComputerUseGuard {
  readonly #client: Client;
  readonly #connection: string;

  constructor(client: Client, connection: string) {
    if (!client || !connection) throw new Error("PantherClaw: a client and a connection are required");
    this.#client = client;
    this.#connection = connection;
  }

  async #ask(input: Record<string, unknown>): Promise<ComputerDecision> {
    let res: HookResult;
    try {
      res = await this.#client.hookCall(this.#connection, TOOL, input);
    } catch (e) {
      return refused(CODE_CANNOT_DECIDE, `PantherClaw cannot decide: ${e instanceof Error ? e.message : String(e)}`);
    }
    const txn = typeof res.answer?.transaction_id === "string" ? res.answer.transaction_id : "";
    const code = typeof res.answer?.code === "string" ? res.answer.code : "";
    if (res.outcome === "allow") return { allowed: true, held: false, code: "", reason: res.why, transaction_id: txn };
    if (res.outcome === "deny") return { allowed: false, held: res.held, code: code || "denied", reason: res.why, transaction_id: txn };
    return { allowed: false, held: false, code: code || CODE_CANNOT_DECIDE, reason: res.why, transaction_id: txn };
  }

  /** Decides an Anthropic computer tool use (`{id, name, input}`). Never throws. */
  async decideAnthropic(toolUse: AnthropicToolUse): Promise<ComputerDecision> {
    try {
      if (!isObject(toolUse)) return refused(CODE_ACTION_UNKNOWN, "a computer tool use is an object");
      const { name, input } = toolUse;
      if (typeof name !== "string" || !(name === "computer" || name.startsWith("computer_")) || !isObject(input)) {
        return refused(CODE_ACTION_UNKNOWN, "PantherClaw decides computer tool uses only");
      }
      const action = input.action;
      if (typeof action === "string" && localAnthropic.has(action)) return allowedLocally();
      const mapped = typeof action === "string" && Object.hasOwn(anthropicKinds, action) ? anthropicKinds[action] : undefined;
      if (!mapped) return refused(CODE_ACTION_UNKNOWN, `PantherClaw does not know the computer action ${JSON.stringify(action)}`);
      const [kind, button] = mapped;
      const out: Record<string, unknown> = { kind };
      if (button) out.button = button;
      at(out, point(input.coordinate));
      const text = input.text;
      if (typeof text === "string" && text) {
        // key and hold_key name keys; type types text; a click or a scroll names the modifier keys held.
        out[kind === "type" ? "text" : "keys"] = text;
      }
      out.call = callId(toolUse.id);
      return await this.#ask(out);
    } catch (e) {
      return refused(CODE_CANNOT_DECIDE, `PantherClaw cannot decide: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  /** Decides an OpenAI computer_call (`{call_id, action}`). Never throws. */
  async decideOpenAI(computerCall: OpenAIComputerCall): Promise<ComputerDecision> {
    try {
      if (!isObject(computerCall)) return refused(CODE_ACTION_UNKNOWN, "a computer call is an object");
      const action = computerCall.action;
      if (!isObject(action)) return refused(CODE_ACTION_UNKNOWN, "a computer call carries an action object");
      const typ = action.type;
      if (typeof typ === "string" && localOpenAI.has(typ)) return allowedLocally();
      const kind = typeof typ === "string" && Object.hasOwn(openAIKinds, typ) ? openAIKinds[typ] : undefined;
      if (!kind) return refused(CODE_ACTION_UNKNOWN, `PantherClaw does not know the computer action ${JSON.stringify(typ)}`);
      const out: Record<string, unknown> = { kind };
      if (kind === "click") {
        const b = action.button;
        const button = typeof b === "string" && Object.hasOwn(openAIButtons, b) ? openAIButtons[b] : undefined;
        if (!button) return refused(CODE_ACTION_UNKNOWN, `PantherClaw does not know the mouse button ${JSON.stringify(b)}`);
        out.button = button;
      }
      if (kind === "drag") {
        const path = action.path;
        at(out, Array.isArray(path) && path.length > 0 ? point(path[path.length - 1]) : undefined);
      } else {
        at(out, point(action));
      }
      if (kind === "key") {
        const keys = action.keys;
        if (!Array.isArray(keys) || !keys.every((k) => typeof k === "string")) return refused(CODE_ACTION_UNKNOWN, "a keypress names its keys");
        out.keys = keys.join("+");
      }
      if (kind === "type") {
        if (typeof action.text !== "string") return refused(CODE_ACTION_UNKNOWN, "a type action carries its text");
        out.text = action.text;
      }
      out.call = callId(computerCall.call_id);
      return await this.#ask(out);
    } catch (e) {
      return refused(CODE_CANNOT_DECIDE, `PantherClaw cannot decide: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}
