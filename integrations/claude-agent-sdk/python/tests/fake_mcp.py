# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""A stdio MCP server with one tool, create_refund, for the real Agent SDK
tests: every call that reaches it is appended to the file named by its first
argument, so a test can tell whether the tool ran."""

import json
import sys

log = sys.argv[1]


def send(m: dict) -> None:
    sys.stdout.write(json.dumps(m) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if "id" not in m:
        continue
    method = m.get("method")
    if method == "initialize":
        version = (m.get("params") or {}).get("protocolVersion", "2025-06-18")
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": version, "capabilities": {"tools": {}},
                                                          "serverInfo": {"name": "payments", "version": "0.0.0"}}})
    elif method == "tools/list":
        schema = {"type": "object", "properties": {"amount": {"type": "string"}, "charge": {"type": "string"}}, "required": ["amount", "charge"]}
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"tools": [{"name": "create_refund", "description": "Refund a charge", "inputSchema": schema}]}})
    elif method == "tools/call":
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps((m.get("params") or {}).get("arguments", {})) + "\n")
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"content": [{"type": "text", "text": "refunded"}]}})
    else:
        send({"jsonrpc": "2.0", "id": m["id"], "result": {}})
