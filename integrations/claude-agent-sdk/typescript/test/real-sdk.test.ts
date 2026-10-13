// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The integration inside the real Claude Agent SDK (HR-200, G0 M8 S6). The
// SDK's own Claude Code process runs every scenario offline: a fake
// Messages API scripts the model's tool calls (test/anthropic.ts), a stdio
// MCP server records whether the tool ran (test/fake-mcp.mjs), and a fake
// PantherClaw decides (test/gateway.ts). The SDK is a dev-only install
// (pnpm install --frozen-lockfile; task sdk:check runs it), pinned in
// pnpm-lock.yaml within the peer range package.json supports.

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import type { ServerResponse } from "node:http";
import { BUILTIN_TOOLS, type HookCallback, type HookOutput, PantherClaw, type PantherClawOptions, type PreToolUseInput, type QueryOptions } from "../src/index.ts";
import { fakeAnthropic, type Turn } from "./anthropic.ts";
import { allow, deny, type Face, gateway, holdThenAllow, observe } from "./gateway.ts";

const sdk = await import("@anthropic-ai/claude-agent-sdk").catch(() => null);
const installed = JSON.parse(
  await readFile(fileURLToPath(new URL("../node_modules/@anthropic-ai/claude-agent-sdk/package.json", import.meta.url)), "utf8").catch(() => "{}"),
) as { version?: string };
const supported = JSON.parse(await readFile(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8")).peerDependencies[
  "@anthropic-ai/claude-agent-sdk"
] as string;

const fakeMcp = fileURLToPath(new URL("./fake-mcp.mjs", import.meta.url));
const refundInput = { amount: "30.00", charge: "ch_1" };

/** The scripted model: each scenario's first tool call, named in the prompt (or a subagent's task). */
function model(prompt: string, tools: string[]): Turn {
  if (prompt.includes("PC_SCENARIO=refund")) return { tool: "mcp__payments__create_refund", input: refundInput };
  if (prompt.includes("PC_SCENARIO=bash")) return { tool: "Bash", input: { command: "echo ran > marker.txt", description: "Write a marker" } };
  if (prompt.includes("PC_SCENARIO=monitor")) {
    return { tool: "Monitor", input: { command: "echo ran > marker.txt", description: "Write a marker", timeout_ms: 60000 } };
  }
  if (prompt.includes("PC_SCENARIO=subagent")) {
    const agent = tools.includes("Agent") ? "Agent" : "Task";
    return { tool: agent, input: { description: "Refund the charge", prompt: "PC_SCENARIO=refund", subagent_type: "general-purpose" } };
  }
  return { text: "nothing to do" };
}

interface Run {
  /** What the MCP tool received, one call per entry. */
  refunds: Record<string, unknown>[];
  /** The tools the model was offered. */
  tools: string[];
  dir: string;
}

/** Only the variables a process needs, never this machine's Claude configuration. */
function isolatedEnv(dir: string, api: string): Record<string, string> {
  const keep = /^(PATH|PATHEXT|SYSTEMROOT|SYSTEMDRIVE|WINDIR|COMSPEC|TEMP|TMP|TMPDIR|LANG|OS|NUMBER_OF_PROCESSORS|PROCESSOR_ARCHITECTURE)$/i;
  const env = Object.fromEntries(Object.entries(process.env).filter(([k, v]) => keep.test(k) && v !== undefined)) as Record<string, string>;
  return {
    ...env,
    HOME: dir,
    USERPROFILE: dir,
    APPDATA: join(dir, "appdata"),
    LOCALAPPDATA: join(dir, "localappdata"),
    CLAUDE_CONFIG_DIR: join(dir, "config"),
    ANTHROPIC_BASE_URL: api,
    ANTHROPIC_API_KEY: "sk-ant-test-not-a-key",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_AUTOUPDATER: "1",
  };
}

/**
 * Runs one scenario through the real SDK. `options` gets the SDK options
 * the run needs (cwd, environment, the MCP server) and returns the query
 * options to use, usually through PantherClaw's options().
 */
async function run(
  t: { after: (fn: () => void) => void },
  prompt: string,
  options: (base: QueryOptions) => QueryOptions,
  features: Record<string, unknown> = {},
): Promise<Run> {
  assert.ok(sdk, "the Agent SDK is not installed: run pnpm install --frozen-lockfile here (task sdk:check does)");
  const api = await fakeAnthropic(t, model);
  const dir = await mkdtemp(join(tmpdir(), "pc-agent-sdk-"));
  const log = join(dir, "refunds.log");
  // The CLI's feature flags, from its own cache on disk (it never fetches them here).
  await mkdir(join(dir, "config"), { recursive: true });
  await writeFile(join(dir, "config", ".claude.json"), JSON.stringify({ cachedGrowthBookFeatures: features }));
  const base: QueryOptions = {
    cwd: dir,
    maxTurns: 6,
    env: { ...isolatedEnv(dir, api.url), CLAUDE_CODE_GB_DISK_CACHE_WHEN_TELEMETRY_OFF: "1" },
    mcpServers: { payments: { type: "stdio", command: process.execPath, args: [fakeMcp, log] } },
  };
  let done!: () => void;
  const finished = new Promise<void>((r) => {
    done = r;
  });
  // A streaming prompt, held open until the result, as canUseTool needs.
  async function* input() {
    yield { type: "user" as const, message: { role: "user" as const, content: prompt }, parent_tool_use_id: null, session_id: "" };
    await finished;
  }
  // biome-ignore lint/suspicious/noExplicitAny: the SDK's own option and message types
  const q = sdk.query({ prompt: input() as any, options: options(base) as any });
  try {
    for await (const m of q) {
      if (m.type === "result") break;
    }
  } finally {
    done();
  }
  const refunds = (await readFile(log, "utf8").catch(() => ""))
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
  const tools = [...new Set(api.requests.flatMap((r) => (Array.isArray(r.tools) ? r.tools.map((x: { name: string }) => x.name) : [])))] as string[];
  return { refunds, tools, dir };
}

function integration(client: PantherClawOptions["client"], extra: Partial<PantherClawOptions> = {}) {
  return new PantherClaw({ client, connection: "payments", shell: "observe", deadlineMs: 5000, waitMs: 5000, ...extra });
}

/** A face that observes the SDK's built-ins and answers MCP tools with `mcp`. */
function faceFor(mcp: Face): Face {
  return (call, id, res: ServerResponse) => (String(call.tool).startsWith("mcp__") ? mcp(call, id, res) : observe(call, id, res));
}

const testOptions = { timeout: 120_000 };

test("TestHR200_the supported Agent SDK version is the one installed, and every built-in it offers is known", testOptions, async (t) => {
  const [lo, hi] = supported.match(/>=(\S+) <(\S+)/)?.slice(1) ?? [];
  const cmp = (a: string, b: string) => {
    const x = a.split(".").map(Number);
    const y = b.split(".").map(Number);
    for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
    return 0;
  };
  assert.ok(installed.version && lo && hi && cmp(installed.version, lo) >= 0 && cmp(installed.version, hi) < 0, `${installed.version} within ${supported}`);
  const g = await gateway(t, faceFor(deny));
  const r = await run(t, "PC_SCENARIO=none", (base) => integration(g.client).options({ ...base, permissionMode: "default", settingSources: [] }));
  const unknown = r.tools.filter((tool) => !tool.startsWith("mcp__") && !BUILTIN_TOOLS.includes(tool));
  assert.deepEqual(unknown, [], "a built-in the integration does not know would be denied");
});

test("TestHR200_in the real SDK, PantherClaw's deny stops the tool in every permission mode", testOptions, async (t) => {
  for (const mode of ["default", "acceptEdits", "bypassPermissions", "dontAsk", "auto"]) {
    const g = await gateway(t, faceFor(deny));
    const r = await run(t, "PC_SCENARIO=refund", (base) =>
      integration(g.client).options({ ...base, permissionMode: mode, allowDangerouslySkipPermissions: mode === "bypassPermissions", settingSources: [] }),
    );
    assert.deepEqual(r.refunds, [], `${mode}: the tool ran`);
    assert.ok(g.calls.some((c) => c.tool === "mcp__payments__create_refund"), `${mode}: PantherClaw was not asked`);
  }
  // The harness itself: PantherClaw's allow lets the tool run.
  const g = await gateway(t, faceFor(allow));
  const r = await run(t, "PC_SCENARIO=refund", (base) =>
    integration(g.client).options({ ...base, permissionMode: "bypassPermissions", allowDangerouslySkipPermissions: true, settingSources: [] }),
  );
  assert.deepEqual(r.refunds, [refundInput]);
});

test("TestHR200_in the real SDK, a hold is asked in default mode, waited on, and runs once PantherClaw allows it", testOptions, async (t) => {
  const g = await gateway(t, faceFor(holdThenAllow()));
  const r = await run(t, "PC_SCENARIO=refund", (base) => integration(g.client).options({ ...base, permissionMode: "default", settingSources: [] }));
  assert.deepEqual(r.refunds, [refundInput], "the tool ran once, with its original input");
  assert.equal(g.calls.filter((c) => c.tool === "mcp__payments__create_refund").length, 2, "the identical call was resubmitted once");
  // In any other mode the hold is denied, never asked.
  const d = await gateway(t, faceFor(holdThenAllow()));
  const b = await run(t, "PC_SCENARIO=refund", (base) =>
    integration(d.client).options({ ...base, permissionMode: "bypassPermissions", allowDangerouslySkipPermissions: true, settingSources: [] }),
  );
  assert.deepEqual(b.refunds, []);
});

test("TestHR200_in the real SDK, a tool never runs after a hook's ask without canUseTool's allow", testOptions, async (t) => {
  const ask: HookCallback = async () => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: "test" } });
  const hooks = { PreToolUse: [{ hooks: [ask] }] };
  const none = await run(t, "PC_SCENARIO=refund", (base) => ({ ...base, permissionMode: "default", settingSources: [], hooks }));
  assert.deepEqual(none.refunds, [], "ask without canUseTool");
  let asked = 0;
  const denied = await run(t, "PC_SCENARIO=refund", (base) => ({
    ...base,
    permissionMode: "default",
    settingSources: [],
    hooks,
    canUseTool: async () => {
      asked++;
      return { behavior: "deny", message: "no" };
    },
  }));
  assert.equal(asked, 1, "canUseTool was called after the hook's ask");
  assert.deepEqual(denied.refunds, [], "ask, then canUseTool's deny");
});

test("TestHR200_in the real SDK, the application's own hook never overrides PantherClaw's deny", testOptions, async (t) => {
  const appAllow: HookCallback = async () => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: "app" } });
  const g = await gateway(t, faceFor(deny));
  const r = await run(t, "PC_SCENARIO=refund", (base) =>
    integration(g.client).options({ ...base, permissionMode: "default", settingSources: [], hooks: { PreToolUse: [{ hooks: [appAllow] }] } }),
  );
  assert.deepEqual(r.refunds, [], "an app allow with PantherClaw's deny");
  const appDeny: HookCallback = async () => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: "app" } });
  const a = await gateway(t, faceFor(allow));
  const d = await run(t, "PC_SCENARIO=refund", (base) =>
    integration(a.client).options({ ...base, permissionMode: "default", settingSources: [], hooks: { PreToolUse: [{ hooks: [appDeny] }] } }),
  );
  assert.deepEqual(d.refunds, [], "an app deny with PantherClaw's allow");
});

test("TestHR200_in the real SDK, the application's allow never runs a call PantherClaw holds and asks about", testOptions, async (t) => {
  const appAllow: HookCallback = async () => ({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: "app" } });
  // The hold never becomes ready: only canUseTool's allow could run the tool, and it denies at its deadline.
  const g = await gateway(t, faceFor(holdThenAllow()), { waitStates: ["PENDING"] });
  const start = Date.now();
  const r = await run(t, "PC_SCENARIO=refund", (base) =>
    integration(g.client, { waitMs: 1500 }).options({ ...base, permissionMode: "default", settingSources: [], hooks: { PreToolUse: [{ hooks: [appAllow] }] } }),
  );
  assert.deepEqual(r.refunds, [], "an app allow ran a held call");
  assert.equal(g.calls.filter((c) => c.tool === "mcp__payments__create_refund").length, 1, "a held call was resubmitted without PantherClaw's ready");
  assert.ok(Date.now() - start >= 1400, "the call was not left to canUseTool's wait");
});

test("TestHR200_in the real SDK, a PantherClaw that does not answer is denied at the integration's deadline", testOptions, async (t) => {
  const g = await gateway(t, faceFor(() => {}));
  const start = Date.now();
  const r = await run(t, "PC_SCENARIO=refund", (base) =>
    integration(g.client, { deadlineMs: 1500 }).options({ ...base, permissionMode: "bypassPermissions", allowDangerouslySkipPermissions: true, settingSources: [] }),
  );
  assert.deepEqual(r.refunds, []);
  assert.ok(Date.now() - start < 6500 + 10_000, "denied well before the registered hook timeout");
});

test("TestHR200_in the real SDK, a subagent's tool calls go through PantherClaw's hook", testOptions, async (t) => {
  const seen: PreToolUseInput[] = [];
  const record: HookCallback = async (input) => {
    seen.push(input);
    return {} as HookOutput;
  };
  const g = await gateway(t, faceFor(deny));
  const r = await run(t, "PC_SCENARIO=subagent", (base) =>
    integration(g.client).options({
      ...base,
      permissionMode: "bypassPermissions",
      allowDangerouslySkipPermissions: true,
      settingSources: [],
      hooks: { PreToolUse: [{ hooks: [record] }] },
    }),
  );
  assert.deepEqual(r.refunds, [], "the subagent's refund ran");
  const sub = seen.find((i) => i.tool_name === "mcp__payments__create_refund");
  assert.ok(sub?.agent_id, "the hook saw the subagent's call");
  assert.ok(g.calls.some((c) => c.tool === "mcp__payments__create_refund"), "PantherClaw decided the subagent's call");
});

test("TestHR200_in the real SDK, Bash goes to the local connection's /hook face and its deny stops it", testOptions, async (t) => {
  const g = await gateway(t, faceFor(deny), { hook: (_b, res) => res.end(JSON.stringify({ decision: "deny", reason: "no", mode: "enforce" })) });
  const r = await run(t, "PC_SCENARIO=bash", (base) =>
    integration(g.client, { shell: undefined, shellConnection: "local" }).options({
      ...base,
      permissionMode: "bypassPermissions",
      allowDangerouslySkipPermissions: true,
      settingSources: [],
    }),
  );
  assert.equal(g.hooks.length, 1, "the command went to /hook");
  assert.equal(g.calls.filter((c) => c.tool === "Bash").length, 0, "never to /sdk");
  assert.equal(await readFile(join(r.dir, "marker.txt"), "utf8").catch(() => ""), "", "the command ran");
});

test("TestHR186_in the real SDK, Monitor's command goes to the local connection's /hook face and its deny stops it", testOptions, async (t) => {
  const g = await gateway(t, faceFor(deny), { hook: (_b, res) => res.end(JSON.stringify({ decision: "deny", reason: "no", mode: "enforce" })) });
  const r = await run(t, "PC_SCENARIO=monitor", (base) =>
    integration(g.client, { shell: undefined, shellConnection: "local" }).options({
      ...base,
      permissionMode: "bypassPermissions",
      allowDangerouslySkipPermissions: true,
      settingSources: [],
    }),
    // Monitor is offered only behind this flag.
    { tengu_amber_sentinel: true },
  );
  assert.ok(r.tools.includes("Monitor"), `the model was offered Monitor (${r.tools.join(", ")})`);
  assert.equal(g.hooks.length, 1, "the command went to /hook");
  assert.equal((g.hooks[0] as { input: { shell: string; command: string } }).input.shell, "bash");
  assert.equal(g.calls.filter((c) => c.tool === "Monitor").length, 0, "never to /sdk");
  assert.equal(await readFile(join(r.dir, "marker.txt"), "utf8").catch(() => ""), "", "the command ran");
});
