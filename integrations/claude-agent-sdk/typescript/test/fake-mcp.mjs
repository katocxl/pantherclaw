// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// A stdio MCP server with one tool, create_refund, for the real Agent SDK
// tests: every call that reaches it is appended to the file named by its
// first argument, so a test can tell whether the tool ran.

import { appendFileSync } from "node:fs";
import { createInterface } from "node:readline";

const log = process.argv[2];
const send = (m) => process.stdout.write(`${JSON.stringify(m)}\n`);

createInterface({ input: process.stdin }).on("line", (line) => {
  let m;
  try {
    m = JSON.parse(line);
  } catch {
    return;
  }
  if (m.id === undefined) return;
  switch (m.method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id: m.id,
        result: { protocolVersion: m.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "payments", version: "0.0.0" } },
      });
      return;
    case "tools/list":
      send({
        jsonrpc: "2.0",
        id: m.id,
        result: {
          tools: [
            {
              name: "create_refund",
              description: "Refund a charge",
              inputSchema: { type: "object", properties: { amount: { type: "string" }, charge: { type: "string" } }, required: ["amount", "charge"] },
            },
          ],
        },
      });
      return;
    case "tools/call":
      appendFileSync(log, `${JSON.stringify(m.params?.arguments ?? {})}\n`);
      send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: "refunded" }] } });
      return;
    case "ping":
      send({ jsonrpc: "2.0", id: m.id, result: {} });
      return;
    default:
      send({ jsonrpc: "2.0", id: m.id, error: { code: -32601, message: "method not found" } });
  }
});
