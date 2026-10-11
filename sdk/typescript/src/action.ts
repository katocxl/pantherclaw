// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// ActionIR v1 (PAP/1 §6), with the structural checks PantherClaw makes
// (HR-100..103, actionir.json); the 8 KiB cap on material parameters
// depends on the definition and is PantherClaw's alone. SDKs never build or
// send ActionIR (HR-201): they parse the action a gateway returns, to check
// it and its hash.

import { createHash } from "node:crypto";
import { type JSONValue, JCSError, parseJSON, serialize } from "./jcs.ts";

/** Raised for ActionIR that PantherClaw would refuse. */
export class ActionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ActionError";
  }
}

export interface ParsedAction {
  /** The action, as parsed. */
  action: Map<string, JSONValue>;
  /** Its canonical form. */
  canonical: string;
  /** The action hash: lowercase hex SHA-256 of the canonical form. */
  hash: string;
}

const encoder = new TextEncoder();
const uuid = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const patterns: Record<string, RegExp> = {
  operation: /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$/,
  route: /^[a-z0-9][a-z0-9._-]{0,63}$/,
  package: /^[a-z0-9][a-z0-9.-]{0,127}$/,
  version: /^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/,
  digest: /^sha256:[0-9a-f]{64}$/,
};
const members: Record<string, string[]> = {
  "": ["v", "org", "env", "run_id", "action_id", "agent_instance", "operation", "definition", "channel", "route", "connection", "target", "params", "destinations", "dedupe_key"],
  definition: ["package", "version", "digest"],
  target: ["type", "id", "account"],
  destination: ["kind", "id"],
};

function fail(why: string): never {
  throw new ActionError(`invalid ActionIR: ${why}`);
}

/** Walks the raw value: depth at most 16, strings and member names at most 64 KiB (UTF-8), a number only as the version. */
function scan(v: JSONValue, depth: number, pointer: string): void {
  if ((Array.isArray(v) || v instanceof Map) && depth > 16) fail("nested deeper than 16");
  if (typeof v === "number" && pointer !== "/v") fail(`a JSON number at ${pointer}`);
  if (typeof v === "string" && encoder.encode(v).length > 64 << 10) fail("a string longer than 64 KiB");
  if (Array.isArray(v)) v.forEach((x, i) => scan(x, depth + 1, `${pointer}/${i}`));
  if (v instanceof Map) {
    for (const [k, x] of v) {
      if (encoder.encode(k).length > 64 << 10) fail("a member name longer than 64 KiB");
      scan(x, depth + 1, `${pointer}/${k}`);
    }
  }
}

function object(v: JSONValue | undefined, name: string, allowed: string[]): Map<string, JSONValue> {
  if (!(v instanceof Map)) fail(`${name} must be an object`);
  for (const k of v.keys()) if (!allowed.includes(k)) fail(`unknown member ${k} in ${name || "the action"}`);
  return v;
}

/** A string member; an optional one may be absent or null, as PantherClaw reads it. */
function str(o: Map<string, JSONValue>, k: string, required = true): string {
  const v = o.get(k);
  if ((v === undefined || v === null) && !required) return "";
  if (typeof v !== "string") fail(`${k} must be a string`);
  return v;
}

/** Identifiers are printable ASCII without spaces, at most 8 KiB (HR-102). */
function identifier(name: string, v: string, required: boolean): void {
  if (v === "") {
    if (required) fail(`${name} is required`);
    return;
  }
  if (v.length > 8 << 10 || !/^[\x21-\x7e]+$/.test(v)) fail(`${name} must be printable ASCII`);
}

/** Parses ActionIR strictly and returns it with its canonical form and hash. */
export function parseAction(raw: string | Uint8Array): ParsedAction {
  const bytes = typeof raw === "string" ? encoder.encode(raw) : raw;
  if (bytes.length === 0 || bytes.length > 1 << 20) fail("size");
  let v: JSONValue;
  const numbers: string[] = [];
  try {
    v = parseJSON(bytes, { numbers });
  } catch (e) {
    fail(e instanceof JCSError ? e.message : String(e));
  }
  scan(v, 1, "");
  const a = object(v, "", members[""] ?? []);
  // The only number is the version, written exactly 1 (not 1.0 or 1e0).
  if (a.get("v") !== 1 || numbers.some((n) => n !== "1")) fail("version");
  for (const k of ["org", "env", "run_id", "action_id", "agent_instance"]) if (!uuid.test(str(a, k))) fail(`${k} is not a UUID`);
  if (!patterns.operation?.test(str(a, "operation"))) fail("operation");
  const d = object(a.get("definition"), "definition", members.definition ?? []);
  if (!patterns.package?.test(str(d, "package")) || !patterns.version?.test(str(d, "version")) || !patterns.digest?.test(str(d, "digest"))) {
    fail("definition");
  }
  if (!["mcp", "http", "sdk", "hook"].includes(str(a, "channel"))) fail("channel");
  if (!patterns.route?.test(str(a, "route"))) fail("route");
  const conn = str(a, "connection", false);
  if (conn !== "" && !uuid.test(conn)) fail("connection");
  const t = object(a.get("target"), "target", members.target ?? []);
  identifier("target.type", str(t, "type", false), true);
  identifier("target.id", str(t, "id", false), true);
  identifier("target.account", str(t, "account", false), false);
  if (!(a.get("params") instanceof Map)) fail("params must be an object");
  const dests = a.get("destinations");
  if (!Array.isArray(dests)) fail("destinations must be present");
  for (const x of dests) {
    const o = object(x, "destination", members.destination ?? []);
    if (!["internal", "external"].includes(str(o, "kind"))) fail("destination kind");
    identifier("destination id", str(o, "id", false), true);
  }
  identifier("dedupe_key", str(a, "dedupe_key", false), false);
  const canonical = serialize(v);
  return { action: a, canonical, hash: createHash("sha256").update(canonical).digest("hex") };
}
