// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// PantherClaw for the Claude Agent SDK (G0 M8 decision 2, HR-200). A
// PreToolUse hook sends every tool call to the gateway's /sdk face before it
// runs, in every permission mode, and denies when PantherClaw cannot decide.
// A canUseTool callback only turns a PantherClaw hold into a wait. Every
// decision is cooperative and labeled PARTIAL: the agent runs the tool with
// its own access (HR-024, HR-186).

// The core client; once @pantherclaw/sdk is published, a build step imports it by name.
import { type Client, newActionId, type Result, type ToolCall, type WaitState } from "../../../../sdk/typescript/src/index.ts";

/** The Agent SDK's built-in tools: run when PantherClaw does not map them, and recorded OBSERVE_ONLY. */
export const BUILTIN_TOOLS: readonly string[] = [
  "Agent",
  "AskUserQuestion",
  "Bash",
  "CronCreate",
  "CronDelete",
  "CronList",
  "Edit",
  "EnterPlanMode",
  "EnterWorktree",
  "ExitPlanMode",
  "ExitWorktree",
  "Glob",
  "Grep",
  "ListMcpResourcesTool",
  "LSP",
  "Monitor",
  "NotebookEdit",
  "PowerShell",
  "Read",
  "ReadMcpResourceTool",
  "Skill",
  "Task",
  "TaskCreate",
  "TaskGet",
  "TaskList",
  "TaskOutput",
  "TaskStop",
  "TaskUpdate",
  "TodoWrite",
  "ToolSearch",
  "WaitForMcpServers",
  "WebFetch",
  "WebSearch",
  "Write",
];

const SHELLS = new Set(["Bash", "PowerShell"]);
/** Permission modes in which a hold is never asked: canUseTool is not called there. */
const NO_ASK_MODES = new Set(["bypassPermissions", "dontAsk"]);

export interface PantherClawOptions {
  /** The PantherClaw client: key file, gateway and run. */
  client: Client;
  /** The cooperative (local) connection whose /sdk face decides the calls. */
  connection: string;
  /** The MCP servers the agent is configured with (the keys of its mcpServers option). */
  mcpServers?: readonly string[];
  /** MCP servers reached through the gateway's /mcp face: already enforced there, so not asked again. */
  gatewayMcpServers?: readonly string[];
  /** Built-in tool names (default BUILTIN_TOOLS). */
  builtinTools?: readonly string[];
  /** Let a non-built-in tool that PantherClaw does not map run (default false: denied). */
  observeUnmapped?: boolean;
  /** How long one decision may take, in ms (default 10 s); the hook's timeout is registered above it. */
  deadlineMs?: number;
  /** How long canUseTool waits on a hold, in ms (default 5 minutes, HR-174). */
  waitMs?: number;
}

/** The Agent SDK's PreToolUse hook input (the members this integration reads). */
export interface PreToolUseInput {
  hook_event_name: string;
  tool_name: string;
  tool_input: unknown;
  tool_use_id?: string;
  cwd?: string;
  permission_mode?: string;
  mcp_server?: { name: string; source?: string };
}

export interface HookOutput {
  hookSpecificOutput?: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason: string;
  };
}

export type PermissionResult =
  | { behavior: "allow"; updatedInput: Record<string, unknown> }
  | { behavior: "deny"; message: string; interrupt?: boolean };

export type CanUseTool = (
  toolName: string,
  input: Record<string, unknown>,
  options: { signal: AbortSignal; toolUseID?: string; [k: string]: unknown },
) => Promise<PermissionResult>;

export type HookCallback = (input: PreToolUseInput, toolUseID?: string, options?: { signal?: AbortSignal }) => Promise<HookOutput>;

/** The query options this integration reads and sets (a subset of the Agent SDK's Options). */
export interface QueryOptions {
  permissionMode?: string;
  allowedTools?: string[];
  mcpServers?: Record<string, unknown>;
  canUseTool?: CanUseTool;
  hooks?: Record<string, { matcher?: string; hooks: HookCallback[]; timeout?: number }[]>;
  [k: string]: unknown;
}

type Route = { kind: "call"; server?: string } | { kind: "skip" } | { kind: "refuse"; why: string };

interface Held {
  call: ToolCall;
  actionId: string;
  hash: string;
  wait: WaitState;
  key: string;
}

const decision = (permissionDecision: "allow" | "deny" | "ask", reason: string): HookOutput => ({
  hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason: `${reason} (PantherClaw, PARTIAL)` },
});

/**
 * The PantherClaw integration. `options()` returns the application's query
 * options with PantherClaw's PreToolUse hook and canUseTool added.
 */
export class PantherClaw {
  private readonly o: Required<PantherClawOptions>;
  private permissionMode = "";
  private allowedTools: readonly string[] = [];
  private appCanUseTool: CanUseTool | undefined;
  private canUseToolInstalled = false;
  /** Held calls by tool_use_id, for canUseTool. */
  private readonly held = new Map<string, Held>();
  /** Action ids of held calls by their content, so an identical later call resubmits (PAP/1 §8). */
  private readonly retries = new Map<string, string>();

  constructor(options: PantherClawOptions) {
    if (!options.client || !options.connection) throw new Error("PantherClaw: a client and a connection are required");
    this.o = { mcpServers: [], gatewayMcpServers: [], builtinTools: BUILTIN_TOOLS, observeUnmapped: false, deadlineMs: 10_000, waitMs: 300_000, ...options };
  }

  /**
   * Adds PantherClaw to the application's query options. permissionMode
   * must be passed explicitly: a session that starts without one may start
   * in a mode the application did not choose.
   */
  options(app: QueryOptions): QueryOptions {
    if (!app.permissionMode) throw new Error("PantherClaw: pass permissionMode explicitly in the query options");
    this.permissionMode = app.permissionMode;
    this.allowedTools = app.allowedTools ?? [];
    this.appCanUseTool = app.canUseTool;
    const servers = Object.keys(app.mcpServers ?? {});
    if (servers.length > 0) this.o.mcpServers = [...new Set([...this.o.mcpServers, ...servers])];
    const pre = [...(app.hooks?.PreToolUse ?? []), { hooks: [this.hook()], timeout: Math.ceil(this.o.deadlineMs / 1000) + 5 }];
    return { ...app, hooks: { ...(app.hooks ?? {}), PreToolUse: pre }, canUseTool: this.canUseTool() };
  }

  /** The PreToolUse hook (no matcher: every tool). */
  hook(): HookCallback {
    return (input) => this.preToolUse(input);
  }

  /** Which kind of call a tool is, and its MCP server. */
  route(input: PreToolUseInput): Route {
    const tool = input.tool_name;
    if (tool.startsWith("mcp__")) {
      const rest = tool.slice(5);
      const named = input.mcp_server?.name;
      const server = named && rest.startsWith(`${named}__`) ? named : [...this.o.mcpServers].sort((a, b) => b.length - a.length).find((s) => rest.startsWith(`${s}__`));
      if (!server || rest.length <= server.length + 2) return { kind: "refuse", why: `the MCP server of ${tool} is not configured` };
      return this.o.gatewayMcpServers.includes(server) ? { kind: "skip" } : { kind: "call", server };
    }
    if (SHELLS.has(tool) && !input.cwd) return { kind: "refuse", why: `${tool} without a working directory` };
    return { kind: "call" };
  }

  /** The PreToolUse hook body. It never throws: any failure denies (HR-200). */
  async preToolUse(input: PreToolUseInput): Promise<HookOutput> {
    try {
      return await this.decide(input);
    } catch (e) {
      return decision("deny", `PantherClaw cannot decide this call: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async decide(input: PreToolUseInput): Promise<HookOutput> {
    const args = input.tool_input;
    if (typeof args !== "object" || args === null || Array.isArray(args)) return decision("deny", "the tool input is not an object");
    const route = this.route(input);
    if (route.kind === "skip") return {};
    if (route.kind === "refuse") return decision("deny", `PantherClaw cannot decide this call: ${route.why}`);
    const call: ToolCall = { tool: input.tool_name, input: args as Record<string, unknown>, tool_use_id: input.tool_use_id || newActionId() };
    if (route.server) call.server = route.server;
    if (SHELLS.has(call.tool)) call.cwd = input.cwd;
    const key = JSON.stringify([call.tool, call.server ?? "", call.cwd ?? "", call.input]);
    const actionId = this.retries.get(key) ?? newActionId();
    const res = await withDeadline(this.o.client.authorize(this.o.connection, call, actionId), this.o.deadlineMs);
    return this.answer(res, input, call, actionId, key);
  }

  private answer(res: Result, input: PreToolUseInput, call: ToolCall, actionId: string, key: string): HookOutput {
    const builtin = this.o.builtinTools.includes(call.tool);
    switch (res.outcome) {
      case "allow":
        this.retries.delete(key);
        return decision("allow", "PantherClaw allowed this call");
      case "observe":
        // An unmapped built-in is recorded, not decided: the application's own permissions apply.
        return builtin ? {} : decision("deny", "PantherClaw does not map this tool");
      case "hold": {
        this.retries.set(key, actionId);
        const w = res.answer?.wait as WaitState;
        const mode = input.permission_mode || this.permissionMode;
        if (this.canUseToolInstalled && !NO_ASK_MODES.has(mode) && !this.allowedTools.some((r) => r === call.tool || r.startsWith(`${call.tool}(`))) {
          this.held.set(call.tool_use_id, { call, actionId, hash: res.answer?.action_hash ?? "", wait: w, key });
          return decision("ask", `PantherClaw holds this call for an approval (transaction ${w.handle})`);
        }
        return decision("deny", `PantherClaw holds this call for an approval by an eligible person (transaction ${w.handle}); once it is approved, make the same call again`);
      }
      default:
        if (res.answer?.code === "unknown_tool" && this.o.observeUnmapped && !builtin) return {};
        return decision("deny", res.why || "PantherClaw denied this call");
    }
  }

  /**
   * The canUseTool callback. It handles only calls PantherClaw holds: it
   * waits on the hold within its own deadline, resubmits the identical call
   * and allows only on PantherClaw's allow, with the original input. Every
   * other call goes to the application's own callback, or is denied when
   * there is none (never asking the local user for a PantherClaw hold).
   */
  canUseTool(): CanUseTool {
    this.canUseToolInstalled = true;
    return async (toolName, input, options) => {
      const h = options.toolUseID ? this.held.get(options.toolUseID) : undefined;
      if (!h || h.call.tool !== toolName) {
        if (this.appCanUseTool) return this.appCanUseTool(toolName, input, options);
        return { behavior: "deny", message: "no permission handler for this call" };
      }
      this.held.delete(options.toolUseID as string);
      try {
        const held: Result = { outcome: "hold", why: "", answer: { decision: "hold", action_hash: h.hash, wait: h.wait } };
        const res = await withDeadline(this.o.client.resume(this.o.connection, h.call, h.actionId, held, this.o.waitMs), this.o.waitMs, options.signal);
        if (res.outcome !== "allow") return { behavior: "deny", message: `${res.why || "PantherClaw did not allow this call"} (PantherClaw, PARTIAL)` };
        this.retries.delete(h.key);
        return { behavior: "allow", updatedInput: h.call.input };
      } catch (e) {
        return { behavior: "deny", message: `the wait for PantherClaw's decision ended: ${e instanceof Error ? e.message : String(e)}` };
      }
    };
  }
}

function withDeadline<T>(p: Promise<T>, ms: number, signal?: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("PantherClaw did not answer in time")), ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new Error("aborted"));
      },
      { once: true },
    );
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
