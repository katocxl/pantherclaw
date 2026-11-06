// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// HR-758: the computer-use guard asks PantherClaw before every input action.

import assert from "node:assert/strict";
import { test } from "node:test";
import { Client, type HookResult } from "../src/client.ts";
import { CODE_ACTION_UNKNOWN, CODE_CANNOT_DECIDE, ComputerUseGuard } from "../src/computer_use.ts";
import { newKeyFile } from "../src/pap.ts";

/** A client whose hookCall records each call and answers `answer`. */
function stub(answer: HookResult | (() => never)) {
  const seen: { connection: string; tool: string; input: Record<string, unknown> }[] = [];
  const client = {
    async hookCall(connection: string, tool: string, input: Record<string, unknown>): Promise<HookResult> {
      seen.push({ connection, tool, input });
      if (typeof answer === "function") return answer();
      return answer;
    },
  } as unknown as Client;
  return { guard: new ComputerUseGuard(client, "desktop"), seen };
}

const allow: HookResult = { outcome: "allow", held: false, why: "ok", answer: { decision: "allow", transaction_id: "t-1" } as never };

test("TestHR758_AnthropicInputActionsAreAskedWithTheirMapping", async () => {
  const { guard, seen } = stub(allow);
  const cases: [Record<string, unknown>, Record<string, unknown>][] = [
    [{ action: "left_click", coordinate: [10, 20] }, { kind: "click", button: "left", x: 10, y: 20 }],
    [{ action: "right_click" }, { kind: "click", button: "right" }],
    [{ action: "middle_click" }, { kind: "click", button: "middle" }],
    [{ action: "double_click" }, { kind: "double_click" }],
    [{ action: "triple_click" }, { kind: "triple_click" }],
    [{ action: "left_click_drag", coordinate: [5, 6] }, { kind: "drag", x: 5, y: 6 }],
    [{ action: "left_mouse_down" }, { kind: "press" }],
    [{ action: "left_mouse_up" }, { kind: "release" }],
    [{ action: "type", text: "hello" }, { kind: "type", text: "hello" }],
    [{ action: "key", text: "ctrl+s" }, { kind: "key", keys: "ctrl+s" }],
    [{ action: "hold_key", text: "shift" }, { kind: "key", keys: "shift" }],
    [{ action: "scroll", coordinate: [3, 4], text: "ctrl" }, { kind: "scroll", x: 3, y: 4, keys: "ctrl" }],
    [{ action: "mouse_move", coordinate: [7, 8] }, { kind: "move", x: 7, y: 8 }],
  ];
  for (const [input, want] of cases) {
    const d = await guard.decideAnthropic({ id: "toolu_01", name: "computer", input });
    assert.equal(d.allowed, true, JSON.stringify(input));
    assert.equal(d.transaction_id, "t-1");
    assert.deepEqual(seen.at(-1), { connection: "desktop", tool: "computer", input: { ...want, call: "toolu_01" } });
  }
  assert.equal(seen.length, cases.length);
});

test("TestHR758_OpenAIInputActionsAreAskedWithTheirMapping", async () => {
  const { guard, seen } = stub(allow);
  const cases: [Record<string, unknown>, Record<string, unknown>][] = [
    [{ type: "click", button: "left", x: 1, y: 2 }, { kind: "click", button: "left", x: 1, y: 2 }],
    [{ type: "click", button: "wheel", x: 1, y: 2 }, { kind: "click", button: "middle", x: 1, y: 2 }],
    [{ type: "double_click", x: 3, y: 4 }, { kind: "double_click", x: 3, y: 4 }],
    [{ type: "drag", path: [{ x: 0, y: 0 }, { x: 9, y: 9 }] }, { kind: "drag", x: 9, y: 9 }],
    [{ type: "keypress", keys: ["CTRL", "S"] }, { kind: "key", keys: "CTRL+S" }],
    [{ type: "type", text: "hi" }, { kind: "type", text: "hi" }],
    [{ type: "scroll", x: 5, y: 6, scroll_y: 3 }, { kind: "scroll", x: 5, y: 6 }],
    [{ type: "move", x: 7, y: 8 }, { kind: "move", x: 7, y: 8 }],
  ];
  for (const [action, want] of cases) {
    const d = await guard.decideOpenAI({ call_id: "call_1", action });
    assert.equal(d.allowed, true, JSON.stringify(action));
    assert.deepEqual(seen.at(-1)?.input, { ...want, call: "call_1" });
  }
});

test("TestHR758_ReadingTheScreenIsAllowedLocallyAndNeverSent", async () => {
  const { guard, seen } = stub({ outcome: "deny", held: false, why: "no" });
  for (const action of ["screenshot", "wait", "cursor_position", "zoom"]) {
    assert.equal((await guard.decideAnthropic({ id: "t", name: "computer_20250124", input: { action } })).allowed, true, action);
  }
  for (const type of ["screenshot", "wait"]) {
    assert.equal((await guard.decideOpenAI({ call_id: "c", action: { type } })).allowed, true, type);
  }
  assert.equal(seen.length, 0);
});

test("TestHR758_ADenyOrAHoldRefusesAndAnUnknownActionIsRefusedLocally", async () => {
  const held = stub({ outcome: "deny", held: true, why: "held", answer: { decision: "deny", code: "APPROVAL_REQUIRED", transaction_id: "t-2" } as never });
  const d = await held.guard.decideAnthropic({ id: "toolu_02", name: "computer", input: { action: "left_click", coordinate: [1, 1] } });
  assert.deepEqual([d.allowed, d.held, d.code, d.transaction_id], [false, true, "APPROVAL_REQUIRED", "t-2"]);
  const { guard, seen } = stub(allow);
  for (const tu of [{ id: "t", name: "computer", input: { action: "teleport" } }, { id: "t", name: "bash", input: { action: "left_click" } }, "x"]) {
    const r = await guard.decideAnthropic(tu as never);
    assert.deepEqual([r.allowed, r.code], [false, CODE_ACTION_UNKNOWN], JSON.stringify(tu));
  }
  for (const call of [
    { call_id: "c", action: { type: "teleport" } },
    { call_id: "c", action: { type: "click", button: "thumb" } },
    { call_id: "c", action: { type: "keypress", keys: "ctrl" } },
    { call_id: "c" },
  ]) {
    const r = await guard.decideOpenAI(call as never);
    assert.deepEqual([r.allowed, r.code], [false, CODE_ACTION_UNKNOWN], JSON.stringify(call));
  }
  assert.equal(seen.length, 0);
});

test("TestHR758_AnyErrorRefuses", async () => {
  const thrown = stub(() => {
    throw new Error("boom");
  });
  const d = await thrown.guard.decideAnthropic({ id: "t", name: "computer", input: { action: "type", text: "x" } });
  assert.deepEqual([d.allowed, d.code], [false, CODE_CANNOT_DECIDE]);
  // A real client whose gateway is unreachable cannot decide, so the guard refuses.
  const down = new Client({ keyFile: { ...newKeyFile(), identifier: "pc:org/o/agent/a/inst/i", server: "http://127.0.0.1:9" }, gateway: "http://127.0.0.1:9", runId: "01920000-0000-7000-8000-000000000003", timeoutMs: 500 });
  const r = await new ComputerUseGuard(down, "desktop").decideOpenAI({ call_id: "c", action: { type: "move", x: 1, y: 1 } });
  assert.deepEqual([r.allowed, r.code], [false, CODE_CANNOT_DECIDE]);
  assert.throws(() => new ComputerUseGuard(undefined as never, "desktop"));
});

test("TestHR758_ACallIdThatIsNotOneGetsARandomCall", async () => {
  const { guard, seen } = stub(allow);
  await guard.decideAnthropic({ id: "bad id!", name: "computer", input: { action: "double_click" } });
  const call = String(seen.at(-1)?.input.call);
  assert.match(call, /^pc-[0-9a-f]{32}$/);
});
