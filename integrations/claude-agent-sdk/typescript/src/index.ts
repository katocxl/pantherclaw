// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// PantherClaw for the Claude Agent SDK (G0 M8 decision 2 and design
// decision 8, HR-200). A PreToolUse hook sorts every tool call into three
// classes before it runs, in every permission mode, and denies when
// PantherClaw cannot decide: tools of MCP servers served by the gateway's
// /mcp face pass (the gateway enforces them); Bash and PowerShell go to the
// local connection's /hook face (pc.shell); every other tool goes to the
// /sdk face. A canUseTool callback only turns a PantherClaw hold into a
// wait. Every decision is cooperative and labeled PARTIAL: the agent runs
// the tool with its own access (HR-024, HR-186).

import { randomBytes } from "node:crypto";
import { realpath } from "node:fs/promises";
// The core client; once @pantherclaw/sdk is published, a build step imports it by name.
import {
  Client,
  type HookResult,
  newActionId,
  type Outbound,
  type Result,
  readKeyFile,
  type ToolCall,
  type WaitState,
} from "../../../../sdk/typescript/src/index.ts";

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

const SHELLS: Record<string, "bash" | "powershell"> = { Bash: "bash", PowerShell: "powershell" };

/**
 * The permission modes in which a hold is asked: those where the SDK
 * documents, and the pinned tests prove, that canUseTool is called after a
 * hook's `ask` (HR-200). In every other mode a hold is denied.
 */
export const ASK_MODES: readonly string[] = ["default"];

/** How many held calls wait for canUseTool at once; beyond it a hold is denied, never asked. */
const MAX_HELD = 256;
/** How many asked tool_use_ids are remembered, so that canUseTool never hands one to the application. */
const MAX_ASKED = 10_000;

export interface PantherClawOptions {
  /** The PantherClaw client: key file, gateway and run, built with `builtins: BUILTIN_TOOLS` (fromKeyFile does). */
  client: Client;
  /** The http or mcp connection whose /sdk face decides the calls. */
  connection: string;
  /** The local connection whose /hook face decides Bash and PowerShell (pc.shell). Required unless `shell` is "observe". */
  shellConnection?: string;
  /**
   * "observe": there is no local connection, and the application accepts
   * that shell calls are only recorded (OBSERVE_ONLY) and run under its own
   * permissions. Without it or a shellConnection the integration refuses
   * to start (HR-200).
   */
  shell?: "observe";
  /** The MCP servers the agent is configured with (the keys of its mcpServers option). */
  mcpServers?: readonly string[];
  /**
   * MCP servers reached through the gateway's /mcp face: already enforced
   * there, so not asked again. Each must be configured with a URL under the
   * gateway's /mcp/ path; otherwise its calls go to the /sdk face.
   */
  gatewayMcpServers?: readonly string[];
  /** Built-in tool names (default BUILTIN_TOOLS); the client must know them as built-ins. */
  builtinTools?: readonly string[];
  /** Let a tool PantherClaw does not map run (default false: denied). */
  observeUnmapped?: boolean;
  /**
   * Called with an allowed call's outbound request on a target-enforced
   * connection, whose target accepts only that exact request with its
   * action token (HR-201). The tool must send it. Without this callback such
   * an allow is denied, since the tool's own request would be refused.
   */
  onDispatch?: (toolUseId: string, send: Outbound) => void;
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
  /** Set when a subagent made the call; its calls go through the same hook. */
  agent_id?: string;
  agent_type?: string;
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
  settingSources?: string[];
  mcpServers?: Record<string, unknown>;
  canUseTool?: CanUseTool;
  hooks?: Record<string, { matcher?: string; hooks: HookCallback[]; timeout?: number }[]>;
  [k: string]: unknown;
}

type Route = { kind: "call"; server?: string } | { kind: "shell"; shell: "bash" | "powershell" } | { kind: "skip" } | { kind: "refuse"; why: string };

interface Held {
  call: ToolCall;
  actionId: string;
  hash: string;
  wait: WaitState;
  key: string;
  expires: number;
}

const decision = (permissionDecision: "allow" | "deny" | "ask", reason: string): HookOutput => ({
  hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision, permissionDecisionReason: `${reason} (PantherClaw, PARTIAL)` },
});

/** Whether an allow rule names a tool: the tool itself (with any specifier), its MCP server, or a wildcard that matches it. */
export function ruleNames(rule: string, tool: string, server = ""): boolean {
  const base = (rule.split("(")[0] ?? "").trim();
  if (base === "*" || base === tool) return true;
  if (server && (base === `mcp__${server}` || base === `mcp__${server}__*`)) return true;
  if (!base.includes("*")) return false;
  const pattern = base.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
  return new RegExp(`^${pattern}$`).test(tool);
}

/**
 * The PantherClaw integration. `options()` returns the application's query
 * options with PantherClaw's PreToolUse hook and canUseTool added.
 */
export class PantherClaw {
  private readonly o: Required<Omit<PantherClawOptions, "shellConnection" | "shell" | "onDispatch">> &
    Pick<PantherClawOptions, "shellConnection" | "shell" | "onDispatch">;
  private permissionMode = "";
  private allowedTools: readonly string[] = [];
  private settingsLoaded = false;
  private appCanUseTool: CanUseTool | undefined;
  private canUseToolInstalled = false;
  /** Gateway MCP servers whose configured URL is the gateway's /mcp face. */
  private trustedGatewayServers = new Set<string>();
  /** Held calls by tool_use_id, for canUseTool. */
  private readonly held = new Map<string, Held>();
  /** Every tool_use_id answered `ask`: canUseTool never hands one to the application. */
  private readonly asked = new Set<string>();
  /** Action ids of held calls by their content, so an identical later call resubmits (PAP/1 §8). */
  private readonly retries = new Map<string, { actionId: string; expires: number }>();

  constructor(options: PantherClawOptions) {
    if (!options.client || !options.connection) throw new Error("PantherClaw: a client and a connection are required");
    if (!options.shellConnection && options.shell !== "observe") {
      throw new Error('PantherClaw: Bash and PowerShell are decided through a local connection\'s /hook face: set shellConnection, or shell: "observe" to only record them');
    }
    this.o = { mcpServers: [], gatewayMcpServers: [], builtinTools: BUILTIN_TOOLS, observeUnmapped: false, deadlineMs: 10_000, waitMs: 300_000, ...options };
    const known = new Set(this.o.client.builtins);
    const missing = this.o.builtinTools.filter((t) => !known.has(t));
    if (missing.length > 0) throw new Error(`PantherClaw: build the client with builtins: BUILTIN_TOOLS (it does not know ${missing.join(", ")})`);
  }

  /** Builds the client from a key file and the integration on it. */
  static async fromKeyFile(
    path: string,
    options: Omit<PantherClawOptions, "client"> & { gateway: string; server?: string; runId?: string; timeoutMs?: number },
  ): Promise<PantherClaw> {
    const { gateway, server, runId, timeoutMs, ...rest } = options;
    const client = new Client({ keyFile: await readKeyFile(path), gateway, server, runId, timeoutMs, builtins: rest.builtinTools ?? BUILTIN_TOOLS });
    return new PantherClaw({ ...rest, client });
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
    // Settings files can hold allow rules this integration cannot see, so a hold is never asked with them loaded.
    this.settingsLoaded = (app.settingSources ?? []).length > 0;
    this.appCanUseTool = app.canUseTool;
    const servers = Object.keys(app.mcpServers ?? {});
    if (servers.length > 0) this.o.mcpServers = [...new Set([...this.o.mcpServers, ...servers])];
    const face = `${this.o.client.gateway}/mcp/`;
    this.trustedGatewayServers = new Set(
      this.o.gatewayMcpServers.filter((name) => {
        const cfg = app.mcpServers?.[name] as { url?: unknown } | undefined;
        return typeof cfg?.url === "string" && cfg.url.startsWith(face);
      }),
    );
    const pre = [...(app.hooks?.PreToolUse ?? []), { hooks: [this.hook()], timeout: Math.ceil(this.o.deadlineMs / 1000) + 5 }];
    return { ...app, hooks: { ...(app.hooks ?? {}), PreToolUse: pre }, canUseTool: this.canUseTool() };
  }

  /** The PreToolUse hook (no matcher: every tool, a subagent's included). */
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
      return this.trustedGatewayServers.has(server) ? { kind: "skip" } : { kind: "call", server };
    }
    const shell = SHELLS[tool];
    if (shell && this.o.shellConnection) return { kind: "shell", shell };
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
    if (route.kind === "shell") return this.shell(input, route.shell, args as Record<string, unknown>);
    const builtin = !route.server && this.o.builtinTools.includes(input.tool_name);
    if (!route.server && !builtin) {
      return this.o.observeUnmapped ? {} : decision("deny", `PantherClaw does not know the ${input.tool_name} tool`);
    }
    const call: ToolCall = { tool: input.tool_name, input: args as Record<string, unknown>, tool_use_id: callId(input.tool_use_id) };
    if (route.server) call.server = route.server;
    const key = JSON.stringify([call.tool, call.server ?? "", call.input]);
    this.prune();
    const actionId = this.retries.get(key)?.actionId ?? newActionId();
    const res = await withDeadline(this.o.client.authorize(this.o.connection, call, actionId), this.o.deadlineMs);
    return this.answer(res, input, call, actionId, key, builtin);
  }

  /** A shell command, decided through the local connection's /hook face (pc.shell) in its final working directory. */
  private async shell(input: PreToolUseInput, shell: "bash" | "powershell", args: Record<string, unknown>): Promise<HookOutput> {
    const command = args.command;
    if (typeof command !== "string" || command === "") return decision("deny", "PantherClaw cannot decide this call: the command is empty");
    if (!input.cwd) return decision("deny", "PantherClaw cannot decide this call: no working directory");
    const cwd = await realpath(input.cwd);
    const res: HookResult = await withDeadline(
      this.o.client.hook(this.o.shellConnection as string, { shell, command, cwd, call: callId(input.tool_use_id) }),
      this.o.deadlineMs,
    );
    if (res.outcome === "allow") return decision("allow", res.why || "PantherClaw allowed this command");
    if (res.held) {
      const txn = res.answer?.transaction_id ? ` (transaction ${res.answer.transaction_id})` : "";
      return decision("deny", `PantherClaw holds this command for an approval by an eligible person${txn}; once it is approved, run the same command again`);
    }
    return decision("deny", res.why || "PantherClaw denied this command");
  }

  private answer(res: Result, input: PreToolUseInput, call: ToolCall, actionId: string, key: string, builtin: boolean): HookOutput {
    switch (res.outcome) {
      case "allow":
        this.retries.delete(key);
        if (res.send) {
          if (!this.o.onDispatch) return decision("deny", "this connection's target accepts only PantherClaw's own request: pass onDispatch to send it");
          this.o.onDispatch(call.tool_use_id, res.send);
        }
        return decision("allow", "PantherClaw allowed this call");
      case "observe":
        // A built-in is recorded, not decided: the application's own permissions apply.
        return builtin ? {} : decision("deny", "PantherClaw does not map this tool");
      case "hold": {
        const w = res.answer?.wait as WaitState;
        this.retries.set(key, { actionId, expires: Date.now() + this.o.waitMs });
        if (this.mayAsk(input, call)) {
          this.held.set(call.tool_use_id, { call, actionId, hash: res.answer?.action_hash ?? "", wait: w, key, expires: Date.now() + this.o.waitMs });
          this.remember(call.tool_use_id);
          return decision("ask", `PantherClaw holds this call for an approval (transaction ${w.handle})`);
        }
        return decision("deny", `PantherClaw holds this call for an approval by an eligible person (transaction ${w.handle}); once it is approved, make the same call again`);
      }
      default:
        if (res.answer?.code === "unknown_tool" && this.o.observeUnmapped) return {};
        return decision("deny", res.why || "PantherClaw denied this call");
    }
  }

  /**
   * Whether a hold may be asked: this integration's canUseTool is installed,
   * the call's permission mode is on ASK_MODES, no allow rule names the tool
   * (wildcards and server rules included), no settings files are loaded, and
   * there is room to remember the hold. Otherwise it is denied (HR-200).
   */
  private mayAsk(input: PreToolUseInput, call: ToolCall): boolean {
    const mode = input.permission_mode || this.permissionMode;
    return (
      this.canUseToolInstalled &&
      ASK_MODES.includes(mode) &&
      !this.settingsLoaded &&
      !this.allowedTools.some((r) => ruleNames(r, call.tool, call.server)) &&
      this.held.size < MAX_HELD
    );
  }

  private remember(id: string): void {
    this.asked.add(id);
    if (this.asked.size > MAX_ASKED) this.asked.delete(this.asked.values().next().value as string);
  }

  /** Forgets holds and retry ids past their wait. */
  private prune(): void {
    const now = Date.now();
    for (const [k, h] of this.held) if (h.expires < now) this.held.delete(k);
    for (const [k, r] of this.retries) if (r.expires < now) this.retries.delete(k);
  }

  /**
   * The canUseTool callback. It handles only calls PantherClaw holds: it
   * waits on the hold within its own deadline, resubmits the identical call
   * and allows only on PantherClaw's allow, with the original input. A call
   * whose hook answer was `ask`, or one without a tool_use_id while a call
   * of its tool is held, is never handed to the application. Every other
   * call goes to the application's own callback, or is denied when there is
   * none (never asking the local user for a PantherClaw hold).
   */
  canUseTool(): CanUseTool {
    this.canUseToolInstalled = true;
    return async (toolName, input, options) => {
      this.prune();
      const id = options.toolUseID;
      const h = id ? this.held.get(id) : undefined;
      if (!h || h.call.tool !== toolName) {
        if (h || (id && this.asked.has(id))) return { behavior: "deny", message: "PantherClaw holds this call; the wait for it has ended (PantherClaw, PARTIAL)" };
        if (!id && [...this.held.values()].some((x) => x.call.tool === toolName)) {
          return { behavior: "deny", message: "PantherClaw holds a call of this tool; it runs only after PantherClaw allows it (PantherClaw, PARTIAL)" };
        }
        if (this.appCanUseTool) return this.appCanUseTool(toolName, input, options);
        return { behavior: "deny", message: "no permission handler for this call" };
      }
      this.held.delete(id as string);
      try {
        const held: Result = { outcome: "hold", why: "", answer: { decision: "hold", action_hash: h.hash, wait: h.wait } };
        const res = await withDeadline(this.o.client.resume(this.o.connection, h.call, h.actionId, held, this.o.waitMs), this.o.waitMs, options.signal);
        if (res.outcome !== "allow") return { behavior: "deny", message: `${res.why || "PantherClaw did not allow this call"} (PantherClaw, PARTIAL)` };
        if (res.send) {
          if (!this.o.onDispatch) return { behavior: "deny", message: "this connection's target accepts only PantherClaw's own request: pass onDispatch to send it" };
          this.o.onDispatch(h.call.tool_use_id, res.send);
        }
        this.retries.delete(h.key);
        return { behavior: "allow", updatedInput: h.call.input };
      } catch (e) {
        return { behavior: "deny", message: `the wait for PantherClaw's decision ended: ${e instanceof Error ? e.message : String(e)}` };
      }
    };
  }
}

/** The SDK's id of a call, or a fresh one when it is missing or one the faces refuse. */
function callId(id: string | undefined): string {
  return id && /^[A-Za-z0-9_-]{1,128}$/.test(id) ? id : `pc-${randomBytes(16).toString("hex")}`;
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
