// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check
"use strict";

// Runs the signed-in pclaw on this machine (G0 M36 D1067, FQ36-4). The
// extension holds no token: pclaw reads the person's own session. Only the
// two read-only verbs are ever run, `pclaw editor status` and `pclaw editor
// open` (HR-794), always with an argument array and never through a shell.

const { execFile } = require("node:child_process");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TIMEOUT_MS = 30_000;
const MAX_OUTPUT = 4 * 1024 * 1024;

/**
 * @typedef {{ connection_id: string, operation: string, state: string }} Coverage
 * @typedef {{ id: string, operation: string, state: string, run_id?: string, transaction_id?: string,
 *   created_at?: string, deadline_at?: string, url: string }} Approval
 * @typedef {{ id: string, operation: string, decision: string, reason_code?: string, run_id?: string,
 *   created_at?: string, url: string }} Decision
 * @typedef {{ agent_id: string, server: string, generated_at: string, coverage: Coverage[], waiting: number,
 *   approvals: Approval[], decisions: Decision[], approvals_url: string }} Status
 */

/**
 * run executes pclaw with args and resolves to its parsed JSON output.
 * @param {string} program
 * @param {string[]} args
 * @returns {Promise<any>}
 */
function run(program, args) {
  return new Promise((resolve, reject) => {
    execFile(program, args, { shell: false, windowsHide: true, timeout: TIMEOUT_MS, maxBuffer: MAX_OUTPUT, encoding: "utf8" },
      (err, stdout, stderr) => {
        if (err) {
          const detail = String(stderr || "").trim().split("\n").slice(-1)[0] || err.message;
          reject(new Error(`pclaw ${args.slice(0, 2).join(" ")}: ${detail}`));
          return;
        }
        try {
          resolve(JSON.parse(String(stdout)));
        } catch {
          reject(new Error(`pclaw ${args.slice(0, 2).join(" ")}: the output is not JSON`));
        }
      });
  });
}

/**
 * status reads one agent's coverage, waiting approvals and recent decisions.
 * @param {string} program
 * @param {string} agent
 * @returns {Promise<Status>}
 */
async function status(program, agent) {
  if (!UUID.test(agent)) {
    throw new Error("the agent id is not a UUID");
  }
  const s = await run(program, ["editor", "status", "--agent", agent, "--json"]);
  if (!s || typeof s !== "object" || !Array.isArray(s.coverage) || !Array.isArray(s.approvals) || !Array.isArray(s.decisions)) {
    throw new Error("pclaw editor status: unexpected output");
  }
  return /** @type {Status} */ (s);
}

/**
 * consoleLink asks pclaw for the console page of an approval or a
 * transaction. Only an https link, or http on this machine, is returned.
 * @param {string} program
 * @param {"approval" | "transaction"} kind
 * @param {string} id
 * @returns {Promise<string>}
 */
async function consoleLink(program, kind, id) {
  if ((kind !== "approval" && kind !== "transaction") || !UUID.test(id)) {
    throw new Error("not an approval or transaction id");
  }
  const out = await run(program, ["editor", "open", kind, id]);
  const url = new URL(String(out && out.url));
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new Error("pclaw editor open: the console link is not https");
  }
  return url.toString();
}

module.exports = { UUID, status, consoleLink };
