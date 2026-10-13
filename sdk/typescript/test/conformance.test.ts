// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// The conformance runner over sdk/conformance: canonical JSON, ActionIR
// and approval bindings.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ActionError, parseAction } from "../src/action.ts";
import { canonicalize, JCSError, serialize } from "../src/jcs.ts";
import { load } from "./vectors.ts";

const sha256 = (s: string, enc: "hex" | "base64url") => createHash("sha256").update(s).digest(enc);

test("jcs.json", async () => {
  for (const c of (await load("jcs.json")).cases) {
    const input = c.input_hex ? new Uint8Array(Buffer.from(c.input_hex, "hex")) : c.input;
    if (c.reject) {
      assert.throws(() => canonicalize(input), JCSError, c.name);
      continue;
    }
    const got = canonicalize(input);
    assert.equal(got, c.canonical, c.name);
    assert.equal(sha256(got, "hex"), c.sha256, c.name);
  }
});

test("actionir.json", async () => {
  for (const c of (await load("actionir.json")).cases) {
    const input = c.input_hex ? new Uint8Array(Buffer.from(c.input_hex, "hex")) : c.input;
    if (c.reject) {
      assert.throws(() => parseAction(input), ActionError, `${c.name} (${c.reject})`);
      continue;
    }
    const p = parseAction(input);
    assert.equal(p.canonical, c.canonical, c.name);
    assert.equal(p.hash, c.action_hash, c.name);
  }
});

test("approval_bindings.json", async () => {
  for (const c of (await load("approval_bindings.json")).cases) {
    const got = serialize(c.input);
    assert.equal(got, c.canonical, c.name);
    assert.equal(sha256(got, "base64url"), c.binding, c.name);
  }
});
