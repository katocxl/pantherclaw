// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Loads the shared conformance vectors in sdk/conformance
// (PANTHERCLAW_CONFORMANCE_DIR overrides the directory).

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = process.env.PANTHERCLAW_CONFORMANCE_DIR ?? fileURLToPath(new URL("../../conformance/", import.meta.url));

// biome-ignore lint/suspicious/noExplicitAny: vector files are untyped JSON
export async function load(name: string): Promise<any> {
  const f = JSON.parse(await readFile(join(dir, name), "utf8"));
  assert.equal(f.format, "pantherclaw.conformance/v1", name);
  return f;
}
