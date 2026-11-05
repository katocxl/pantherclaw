// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check

// The native port to `pclaw browser host` (G0 M33 D979, D980). The
// extension reaches PantherClaw only through it (FQ33-1): it holds no key
// and calls no PantherClaw URL. The port stays open and reconnects with a
// backoff of at most 30 s. Every question that gets no answer, because
// there is no port, it disconnects or it does not answer in time, is a deny
// with code CANNOT_DECIDE (fail closed, HR-751).

/**
 * @typedef {{decision: "allow" | "deny", held: boolean, code: string, reason: string, transaction_id: string}} Answer
 * @typedef {{ok: boolean, connection: string, run: string, reason: string}} Status
 */

export const CANNOT_DECIDE = "CANNOT_DECIDE";
const CANNOT_DECIDE_REASON = "PantherClaw cannot decide this call, so it is blocked.";
/** The host's own deadline is 8 s; this one also covers the port. */
const ANSWER_TIMEOUT_MS = 12_000;
const MAX_BACKOFF_MS = 30_000;

/**
 * @param {string} reason
 * @returns {Answer}
 */
export function cannotDecide(reason = CANNOT_DECIDE_REASON) {
  return { decision: "deny", held: false, code: CANNOT_DECIDE, reason, transaction_id: "" };
}

export class Host {
  /** @param {() => Promise<string>} hostName */
  constructor(hostName) {
    this.hostName = hostName;
    /** @type {chrome.runtime.Port | null} */
    this.port = null;
    /** @type {Map<string, {resolve: (v: any) => void, fallback: any, timer: ReturnType<typeof setTimeout>}>} */
    this.pending = new Map();
    this.backoff = 1000;
    /** @type {ReturnType<typeof setTimeout> | null} */
    this.retry = null;
  }

  /** Opens the port (idempotent). */
  async connect() {
    if (this.port || this.retry) {
      return;
    }
    let port;
    try {
      port = chrome.runtime.connectNative(await this.hostName());
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.port = port;
    port.onMessage.addListener((msg) => this.onMessage(msg));
    port.onDisconnect.addListener(() => {
      void chrome.runtime.lastError;
      this.port = null;
      for (const [id, p] of this.pending) {
        clearTimeout(p.timer);
        p.resolve(p.fallback);
        this.pending.delete(id);
      }
      this.scheduleReconnect();
    });
  }

  scheduleReconnect() {
    if (this.retry) {
      return;
    }
    const wait = this.backoff;
    this.backoff = Math.min(this.backoff * 2, MAX_BACKOFF_MS);
    this.retry = setTimeout(() => {
      this.retry = null;
      void this.connect();
    }, wait);
  }

  /** @param {any} msg */
  onMessage(msg) {
    if (!msg || msg.v !== 1 || typeof msg.id !== "string") {
      return;
    }
    this.backoff = 1000;
    const p = this.pending.get(msg.id);
    if (!p) {
      return;
    }
    clearTimeout(p.timer);
    this.pending.delete(msg.id);
    p.resolve(msg);
  }

  /**
   * Sends one message and waits for its answer, or resolves to fallback.
   * @template T
   * @param {Record<string, unknown>} body
   * @param {T} fallback
   * @returns {Promise<T>}
   */
  ask(body, fallback) {
    const port = this.port;
    if (!port) {
      void this.connect();
      return Promise.resolve(fallback);
    }
    const id = crypto.randomUUID();
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(fallback);
      }, ANSWER_TIMEOUT_MS);
      this.pending.set(id, { resolve, fallback, timer });
      try {
        port.postMessage({ v: 1, id, ...body });
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        resolve(fallback);
      }
    });
  }

  /**
   * Asks PantherClaw about one action. Only the D974 inputs are sent: no
   * page content (HR-754).
   * @param {string} tool
   * @param {Record<string, unknown>} input
   * @param {string} actionId
   * @returns {Promise<Answer>}
   */
  async decide(tool, input, actionId) {
    const fallback = cannotDecide();
    const a = await this.ask({ type: "decide", tool, action_id: actionId, input }, fallback);
    if (a === fallback || (a.decision !== "allow" && a.decision !== "deny")) {
      return fallback;
    }
    return {
      decision: a.decision, held: a.held === true, code: String(a.code || ""), reason: String(a.reason || ""),
      transaction_id: String(a.transaction_id || ""),
    };
  }

  /** @returns {Promise<Status>} */
  async status() {
    const fallback = { ok: false, connection: "", run: "", reason: "The PantherClaw native host is not reachable." };
    const s = await this.ask({ type: "status" }, fallback);
    return {
      ok: s.ok === true, connection: String(s.connection || ""), run: String(s.run || ""), reason: String(s.reason || ""),
    };
  }
}
