// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// A fake Anthropic Messages API for the real Agent SDK tests, so the SDK's
// own Claude Code process runs offline and deterministically: the "model"
// asks for the tool calls a scenario names in its prompt, then ends its
// turn once it sees their results.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** One scripted model turn: text, or a tool call. */
export type Turn = { text: string } | { tool: string; input: Record<string, unknown> };

// biome-ignore lint/suspicious/noExplicitAny: the Messages API request, read loosely
type Request = any;

/** The text of a message's content, string or blocks. */
function textOf(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content.map((b) => (b?.type === "text" ? String(b.text) : "")).join("\n");
}

/** Whether a message carries a tool result. */
function hasToolResult(m: Request): boolean {
  return Array.isArray(m?.content) && m.content.some((b: Request) => b?.type === "tool_result");
}

let counter = 0;

function message(turn: Turn): Record<string, unknown> {
  const content =
    "tool" in turn ? [{ type: "tool_use", id: `toolu_fake${++counter}`, name: turn.tool, input: turn.input }] : [{ type: "text", text: turn.text }];
  return {
    id: `msg_fake${++counter}`,
    type: "message",
    role: "assistant",
    model: "claude-fake",
    content,
    stop_reason: "tool" in turn ? "tool_use" : "end_turn",
    stop_sequence: null,
    usage: { input_tokens: 10, output_tokens: 5 },
  };
}

function sse(res: ServerResponse, turn: Turn): void {
  const m = message(turn);
  const block = (m.content as Record<string, unknown>[])[0] as Record<string, unknown>;
  const ev = (type: string, data: Record<string, unknown>) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`);
  res.writeHead(200, { "Content-Type": "text/event-stream", "request-id": `req_fake${counter}` });
  ev("message_start", { message: { ...m, content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 1 } } });
  if (block.type === "tool_use") {
    ev("content_block_start", { index: 0, content_block: { ...block, input: {} } });
    ev("content_block_delta", { index: 0, delta: { type: "input_json_delta", partial_json: JSON.stringify(block.input) } });
  } else {
    ev("content_block_start", { index: 0, content_block: { type: "text", text: "" } });
    ev("content_block_delta", { index: 0, delta: { type: "text_delta", text: block.text } });
  }
  ev("content_block_stop", { index: 0 });
  ev("message_delta", { delta: { stop_reason: m.stop_reason, stop_sequence: null }, usage: { output_tokens: 5 } });
  ev("message_stop", {});
  res.end();
}

/**
 * Starts the fake API. `script` gets the text of a conversation's first
 * user message (the prompt, or a subagent's task) and the names of the
 * tools offered, and returns the model's first turn; once the conversation
 * holds a tool result, the model ends its turn with text. Requests that
 * offer no tools (the CLI's own housekeeping) get text.
 */
export async function fakeAnthropic(
  t: { after: (fn: () => void) => void },
  script: (prompt: string, tools: string[]) => Turn,
): Promise<{ url: string; requests: Request[] }> {
  const requests: Request[] = [];
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    let body = "";
    req.on("data", (c) => {
      body += c;
    });
    req.on("end", () => {
      const path = (req.url ?? "").split("?")[0];
      if (req.method === "POST" && path === "/v1/messages/count_tokens") {
        res.writeHead(200, { "Content-Type": "application/json" }).end('{"input_tokens":10}');
        return;
      }
      if (req.method !== "POST" || path !== "/v1/messages") {
        res.writeHead(404, { "Content-Type": "application/json" }).end('{"type":"error","error":{"type":"not_found_error","message":"not found"}}');
        return;
      }
      let r: Request;
      try {
        r = JSON.parse(body);
      } catch {
        res.writeHead(400).end();
        return;
      }
      requests.push(r);
      const messages: Request[] = Array.isArray(r.messages) ? r.messages : [];
      const tools: string[] = Array.isArray(r.tools) ? r.tools.map((x: Request) => String(x?.name)) : [];
      const first = messages.find((m) => m?.role === "user");
      let turn: Turn;
      if (tools.length === 0) turn = { text: "ok" };
      else if (messages.some(hasToolResult)) turn = { text: "done" };
      else turn = script(textOf(first?.content), tools);
      if (r.stream) sse(res, turn);
      else res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(message(turn)));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => {
    server.closeAllConnections();
    server.close();
  });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, requests };
}
