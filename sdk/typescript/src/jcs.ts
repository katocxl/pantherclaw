// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// RFC 8785 JSON Canonicalization Scheme, checked against the shared
// conformance vectors (sdk/conformance/jcs.json). JSON.parse is not used:
// it accepts duplicate member names and lone surrogates, which PantherClaw
// refuses.

/** A parsed JSON value. Objects keep their members in a Map. */
export type JSONValue = null | boolean | number | string | JSONValue[] | Map<string, JSONValue>;

/** Raised for input that is not exactly one strict JSON value. */
export class JCSError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JCSError";
  }
}

const maxDepth = 512;
const numberPattern = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;

/** Options of parseJSON. */
export interface ParseOptions {
  /** Receives the source text of every number, in order. */
  numbers?: string[];
}

class Parser {
  private i = 0;
  private readonly s: string;
  private readonly numbers: string[] | undefined;

  constructor(s: string, numbers?: string[]) {
    this.s = s;
    this.numbers = numbers;
  }

  parse(): JSONValue {
    const v = this.value(0);
    this.ws();
    if (this.i !== this.s.length) throw new JCSError("not one JSON value");
    return v;
  }

  private ws(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return;
      this.i++;
    }
  }

  private value(depth: number): JSONValue {
    if (depth > maxDepth) throw new JCSError("nesting too deep");
    this.ws();
    const c = this.s[this.i];
    if (c === "{") return this.object(depth);
    if (c === "[") return this.array(depth);
    if (c === '"') return this.string();
    for (const [word, v] of [["true", true], ["false", false], ["null", null]] as const) {
      if (this.s.startsWith(word, this.i)) {
        this.i += word.length;
        return v;
      }
    }
    const m = numberPattern.exec(this.s.slice(this.i));
    if (m === null) throw new JCSError(`not JSON at offset ${this.i}`);
    this.i += m[0].length;
    this.numbers?.push(m[0]);
    const n = Number(m[0]);
    if (!Number.isFinite(n)) throw new JCSError("number out of range");
    return n;
  }

  private object(depth: number): Map<string, JSONValue> {
    const out = new Map<string, JSONValue>();
    this.i++;
    this.ws();
    if (this.s[this.i] === "}") {
      this.i++;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') throw new JCSError(`member name expected at offset ${this.i}`);
      const name = this.string();
      if (out.has(name)) throw new JCSError(`duplicate member name ${JSON.stringify(name)}`);
      this.ws();
      if (this.s[this.i++] !== ":") throw new JCSError("':' expected");
      out.set(name, this.value(depth + 1));
      this.ws();
      const c = this.s[this.i++];
      if (c === "}") return out;
      if (c !== ",") throw new JCSError("',' or '}' expected");
    }
  }

  private array(depth: number): JSONValue[] {
    const out: JSONValue[] = [];
    this.i++;
    this.ws();
    if (this.s[this.i] === "]") {
      this.i++;
      return out;
    }
    for (;;) {
      out.push(this.value(depth + 1));
      this.ws();
      const c = this.s[this.i++];
      if (c === "]") return out;
      if (c !== ",") throw new JCSError("',' or ']' expected");
    }
  }

  private string(): string {
    let out = "";
    this.i++;
    for (;;) {
      if (this.i >= this.s.length) throw new JCSError("unterminated string");
      const c = this.s.charCodeAt(this.i++);
      if (c === 0x22) break;
      if (c < 0x20) throw new JCSError("control character in a string");
      if (c !== 0x5c) {
        out += String.fromCharCode(c);
        continue;
      }
      const e = this.s[this.i++];
      const simple: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
      if (e !== undefined && e in simple) {
        out += simple[e];
      } else if (e === "u") {
        const hex = this.s.slice(this.i, this.i + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new JCSError("bad \\u escape");
        out += String.fromCharCode(parseInt(hex, 16));
        this.i += 4;
      } else {
        throw new JCSError("bad escape");
      }
    }
    if (!out.isWellFormed()) throw new JCSError("a lone surrogate is not a Unicode scalar value");
    return out;
  }
}

/** Parses exactly one strict JSON value from text or UTF-8 bytes. */
export function parseJSON(input: string | Uint8Array, opts: ParseOptions = {}): JSONValue {
  let text: string;
  if (typeof input === "string") {
    if (!input.isWellFormed()) throw new JCSError("invalid UTF-16");
    text = input;
  } else {
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      throw new JCSError("invalid UTF-8");
    }
  }
  return new Parser(text, opts.numbers).parse();
}

/**
 * Serializes a value canonically. Accepts JSON values only: parsed values
 * (Maps with string keys), arrays, and plain JavaScript objects (whose
 * prototype is Object.prototype or null). Anything else (a Date, a class
 * instance, a typed array, undefined) is refused rather than written as
 * something it is not. Members are sorted by UTF-16 code units and numbers
 * are written as ECMAScript does.
 */
export function serialize(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new JCSError("numbers must be finite");
    return Object.is(v, -0) ? "0" : String(v);
  }
  if (typeof v === "string") {
    if (!v.isWellFormed()) throw new JCSError("a lone surrogate is not a Unicode scalar value");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    // A hole ([,1]) is not JSON; map would skip it and write "[,1]".
    for (let i = 0; i < v.length; i++) if (!(i in v)) throw new JCSError("an array with a hole is not JSON");
    return `[${v.map(serialize).join(",")}]`;
  }
  if (typeof v !== "object") throw new JCSError(`cannot serialize ${typeof v}`);
  let entries: [string, unknown][];
  if (v instanceof Map) {
    entries = [...v.entries()];
    if (entries.some(([k]) => typeof k !== "string")) throw new JCSError("a Map with keys that are not strings is not JSON");
  } else {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) throw new JCSError(`cannot serialize ${proto?.constructor?.name ?? "this object"}`);
    entries = Object.entries(v);
  }
  entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, x]) => `${serialize(k)}:${serialize(x)}`).join(",")}}`;
}

/** Returns the canonical form of JSON text or UTF-8 bytes. */
export function canonicalize(input: string | Uint8Array): string {
  return serialize(parseJSON(input));
}
