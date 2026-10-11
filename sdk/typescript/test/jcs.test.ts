// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

import assert from "node:assert/strict";
import { test } from "node:test";
import { canonicalize, JCSError, parseJSON, serialize } from "../src/jcs.ts";

test("plain JavaScript values serialize canonically", () => {
  assert.equal(serialize({ b: 1, a: [true, null, -0, "x"] }), '{"a":[true,null,0,"x"],"b":1}');
  assert.throws(() => serialize(Number.NaN), JCSError);
  assert.throws(() => serialize(Number.POSITIVE_INFINITY), JCSError);
  assert.throws(() => serialize(undefined), JCSError);
  assert.throws(() => serialize("\ud800"), JCSError);
});

test("a __proto__ member is an ordinary member", () => {
  const v = parseJSON('{"__proto__":{"admin":true},"a":1}');
  assert.ok(v instanceof Map);
  assert.equal(canonicalize('{"__proto__":{"admin":true},"a":1}'), '{"__proto__":{"admin":true},"a":1}');
  assert.equal(({} as Record<string, unknown>).admin, undefined);
});

test("nesting is bounded and numbers out of range are refused", () => {
  assert.throws(() => parseJSON("[".repeat(600) + "]".repeat(600)), JCSError);
  assert.throws(() => parseJSON("[1e400]"), JCSError);
});

test("only JSON values serialize", () => {
  class Point {
    x = 1;
  }
  // biome-ignore lint/suspicious/noSparseArray: a hole, which is not JSON
  const holey = [, 1];
  for (const v of [new Date(0), /x/, new Point(), new Uint8Array(2), new Map<unknown, unknown>([[1, "one"]]), undefined, () => 0, holey, new Array(2)]) {
    assert.throws(() => serialize(v), JCSError);
  }
  assert.equal(serialize(Object.assign(Object.create(null), { b: 1, a: [true] })), '{"a":[true],"b":1}');
});
