# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClaw for the Google Agent Development Kit (G0 M34 D996; HR-767).

``before_tool_callback(client, connection)`` returns an ADK
``before_tool_callback``: before each tool runs, it asks the gateway's /sdk
face of ``connection`` (through ``Client.authorize``) about the call, as the
MCP tool ``mcp__<connection>__<tool name>`` of the server named after the
connection, so the connection's package maps the tool by its name. Only an
allow lets the tool run (the callback returns None). A deny, a hold, or any
failure returns a refusal dict, which ADK hands to the model as the tool's
result without running the tool (fail closed). A held call is not waited on:
once a person approves it in PantherClaw, the identical call asked again
reuses the held call's action id.

This is the only hook Vertex AI Agent Engine offers (it has no gateway
hook), so it applies to ADK agents deployed there too. Every decision is
cooperative and PARTIAL: the agent's code runs the tool with its own access,
and code that drops the callback is not asked about (R-84).
"""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any

from pantherclaw.client import Client, Result, new_action_id

__all__ = ["HELD_TEXT", "before_tool_callback", "refusal"]

# What a held call tells the model (the same words as the AgentCore face, D994).
HELD_TEXT = "held for a person's approval in PantherClaw; ask again after"
_CALL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")
# How many held calls' action ids one callback remembers, and for how long.
_MAX_HELD = 10_000
_HELD_FOR = 24 * 3600.0


def refusal(code: str, reason: str = "", transaction: str = "") -> dict[str, Any]:
    """The dict a refused call returns to the model in place of the tool's result."""
    where = f" (transaction {transaction})" if transaction else ""
    text = f"PantherClaw refused this call: {code}{where}"
    if reason:
        text += f": {reason}"
    out: dict[str, Any] = {"status": "refused", "error": text, "code": code}
    if transaction:
        out["transaction_id"] = transaction
    return out


def _transaction(answer: Any) -> str:
    txn = answer.get("transaction_id") if isinstance(answer, dict) else None
    return txn if isinstance(txn, str) else ""


class _Held:
    """Held calls' action ids, so the identical call asked again after an
    approval is the same action (bounded, and forgotten after a day)."""

    def __init__(self) -> None:
        self._calls: dict[str, tuple[str, str, float]] = {}
        self._lock = threading.Lock()

    def take(self, key: str) -> tuple[str, str]:
        now = time.monotonic()
        with self._lock:
            for k in [k for k, (_, _, exp) in self._calls.items() if exp < now]:
                del self._calls[k]
            got = self._calls.get(key)
        return (got[0], got[1]) if got else (new_action_id(), "")

    def held(self, key: str, action_id: str, res: Result) -> None:
        h = res.answer.get("action_hash") if isinstance(res.answer, dict) else ""
        with self._lock:
            if key not in self._calls and len(self._calls) >= _MAX_HELD:
                self._calls.pop(next(iter(self._calls)))
            self._calls[key] = (action_id, h if isinstance(h, str) else "", time.monotonic() + _HELD_FOR)

    def forget(self, key: str) -> None:
        with self._lock:
            self._calls.pop(key, None)


def before_tool_callback(client: Client, connection: str) -> Callable[..., dict[str, Any] | None]:
    """Returns an ADK before_tool_callback ``(tool, args, tool_context)`` that
    asks PantherClaw about each call through ``connection`` (an ``mcp`` or
    ``http`` connection with access mode ``agent_held``). It returns None to
    let the tool run, or a refusal dict; it never raises."""
    if client is None or not connection:
        raise ValueError("PantherClaw: a client and a connection are required")
    held = _Held()

    def callback(tool: Any, args: Any, tool_context: Any = None) -> dict[str, Any] | None:
        try:
            name = getattr(tool, "name", None)
            if not isinstance(name, str) or not name or not isinstance(args, dict):
                return refusal("wrapper_error", "a tool call needs a tool name and an arguments object")
            key = json.dumps([name, args], sort_keys=True, ensure_ascii=False)
            raw_id = getattr(tool_context, "function_call_id", None)
            call_id = raw_id if isinstance(raw_id, str) and _CALL_ID.match(raw_id) else "pc-" + secrets.token_hex(16)
            action_id, first_hash = held.take(key)
            res = client.authorize(connection, f"mcp__{connection}__{name}", args, call_id, action_id,
                                   server=connection, first_hash=first_hash)
            txn = _transaction(res.answer)
            if res.outcome == "hold":
                held.held(key, action_id, res)
                return refusal("held", HELD_TEXT, txn)
            held.forget(key)
            if res.outcome == "allow":
                if res.send is not None:
                    # A target-enforced connection's request is PantherClaw's own;
                    # the callback cannot send it, so the call does not run.
                    return refusal("dispatch_required", "use an agent_held connection with this callback", txn)
                return None
            if res.outcome == "deny":
                code = res.answer.get("code") if isinstance(res.answer, dict) else None
                return refusal(code if isinstance(code, str) and code else "denied", res.why, txn)
            return refusal("cannot_decide", res.why or "PantherClaw cannot decide this tool call, so it does not run", txn)
        except Exception:  # noqa: BLE001 - any failure refuses (HR-767)
            return refusal("wrapper_error", "PantherClaw cannot decide this tool call, so it does not run")

    return callback
