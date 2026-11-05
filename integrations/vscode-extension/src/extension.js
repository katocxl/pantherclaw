// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato
// @ts-check
"use strict";

// The PantherClaw VS Code extension (G0 M36 D1067, FQ36-4). It shows one
// agent's coverage, waiting approvals and recent decisions, read through the
// signed-in pclaw on this machine. It is read only (HR-794): there is no
// approve, decline or edit action anywhere, and no token lives in VS Code.
// "Open in console" opens the console page in the browser, where a person
// decides.

const vscode = require("vscode");
const pclaw = require("./pclaw.js");

const REFRESH_MS = 60_000;
const AGENT_FILE = [".pantherclaw", "agent"];

/** @typedef {import("./pclaw.js").Status} Status */

/**
 * @typedef {{ kind: "section", label: string, children: Node[] }
 *   | { kind: "approval" | "transaction", label: string, description: string, tooltip: string, id: string }
 *   | { kind: "info", label: string, description?: string, tooltip?: string }} Node
 */

class StatusTree {
  constructor() {
    /** @type {vscode.EventEmitter<void>} */
    this.changed = new vscode.EventEmitter();
    this.onDidChangeTreeData = this.changed.event;
    /** @type {Node[]} */
    this.roots = [{ kind: "info", label: "Loading…" }];
  }

  /** @param {Node[]} roots */
  set(roots) {
    this.roots = roots;
    this.changed.fire();
  }

  /** @param {Node} n */
  getTreeItem(n) {
    if (n.kind === "section") {
      const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.Expanded);
      item.contextValue = "pantherclaw.section";
      return item;
    }
    const item = new vscode.TreeItem(n.label, vscode.TreeItemCollapsibleState.None);
    item.description = n.description;
    item.tooltip = n.tooltip;
    if (n.kind === "approval" || n.kind === "transaction") {
      item.contextValue = "pantherclaw." + n.kind;
      item.command = { command: "pantherclaw.openInConsole", title: "Open in console", arguments: [n] };
    }
    return item;
  }

  /** @param {Node} [n] */
  getChildren(n) {
    if (!n) {
      return this.roots;
    }
    return n.kind === "section" ? n.children : [];
  }
}

/**
 * agentId reads the agent from the setting, else from .pantherclaw/agent in
 * the first workspace folder (only in a trusted workspace).
 * @returns {Promise<string>}
 */
async function agentId() {
  const set = String(vscode.workspace.getConfiguration("pantherclaw").get("agent") || "").trim();
  if (set) {
    return set;
  }
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!folder || !vscode.workspace.isTrusted) {
    return "";
  }
  try {
    const raw = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(folder.uri, ...AGENT_FILE));
    return Buffer.from(raw).toString("utf8").trim().slice(0, 64);
  } catch {
    return "";
  }
}

function pclawPath() {
  return String(vscode.workspace.getConfiguration("pantherclaw").get("pclawPath") || "pclaw");
}

/**
 * nodes turns a status into the three sections.
 * @param {Status} s
 * @returns {Node[]}
 */
function nodes(s) {
  /** @type {Node[]} */
  const coverage = s.coverage.map((c) => ({
    kind: "info", label: c.operation, description: c.state, tooltip: `${c.operation} on ${c.connection_id}: ${c.state}`,
  }));
  /** @type {Node[]} */
  const approvals = s.approvals.map((a) => ({
    kind: "approval", id: a.id, label: a.operation, description: a.deadline_at ? `until ${a.deadline_at}` : a.state,
    tooltip: `Waiting for approval (${a.state}). Open in console to review it there.`,
  }));
  /** @type {Node[]} */
  const decisions = s.decisions.map((d) => ({
    kind: "transaction", id: d.id, label: d.operation, description: d.decision,
    tooltip: `${d.decision}${d.reason_code ? " (" + d.reason_code + ")" : ""} at ${d.created_at || "?"}`,
  }));
  return [
    { kind: "section", label: "Coverage", children: coverage.length ? coverage : [{ kind: "info", label: "No coverage records" }] },
    { kind: "section", label: `Waiting approvals (${s.waiting})`, children: approvals.length ? approvals : [{ kind: "info", label: "No approvals waiting" }] },
    { kind: "section", label: "Recent decisions (24 h)", children: decisions.length ? decisions : [{ kind: "info", label: "No decisions in the last 24 hours" }] },
  ];
}

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  const tree = new StatusTree();
  const bar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  bar.command = "pantherclaw.refresh";
  bar.text = "PantherClaw";
  bar.show();
  let busy = false;

  async function refresh() {
    if (busy) {
      return;
    }
    busy = true;
    try {
      const agent = await agentId();
      if (!agent) {
        tree.set([{ kind: "info", label: "Set pantherclaw.agent or .pantherclaw/agent" }]);
        bar.text = "PantherClaw: no agent";
        bar.tooltip = "Set the pantherclaw.agent setting, or write the agent id to .pantherclaw/agent";
        return;
      }
      const s = await pclaw.status(pclawPath(), agent);
      tree.set(nodes(s));
      bar.text = `PantherClaw: ${s.waiting} waiting`;
      bar.tooltip = `Agent ${s.agent_id} on ${s.server}. Click to refresh.`;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      tree.set([{ kind: "info", label: "Not available", description: msg, tooltip: msg }]);
      bar.text = "PantherClaw: unavailable";
      bar.tooltip = msg;
    } finally {
      busy = false;
    }
  }

  /** @param {Node} [n] */
  async function openInConsole(n) {
    if (!n || (n.kind !== "approval" && n.kind !== "transaction")) {
      return;
    }
    try {
      const link = await pclaw.consoleLink(pclawPath(), n.kind, n.id);
      await vscode.env.openExternal(vscode.Uri.parse(link, true));
    } catch (err) {
      void vscode.window.showErrorMessage(err instanceof Error ? err.message : String(err));
    }
  }

  const timer = setInterval(() => void refresh(), REFRESH_MS);
  context.subscriptions.push(
    vscode.window.createTreeView("pantherclaw.status", { treeDataProvider: tree }),
    bar,
    tree.changed,
    vscode.commands.registerCommand("pantherclaw.refresh", refresh),
    vscode.commands.registerCommand("pantherclaw.openInConsole", openInConsole),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("pantherclaw")) {
        void refresh();
      }
    }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => void refresh()),
    { dispose: () => clearInterval(timer) },
  );
  void refresh();
}

function deactivate() {}

module.exports = { activate, deactivate };
