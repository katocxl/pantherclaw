# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClaw for the OpenAI Agents SDK (M14 PN-016.3; HR-328, HR-329).

``guard_tools`` wraps function tools so that every call is decided by
PantherClaw before the tool runs: only an allow runs it, a hold waits in
PantherClaw, and anything else returns a refusal to the model.
``gateway_mcp_server`` reaches a gateway connection's MCP face through
``pclaw mcp proxy``, where the gateway itself enforces every call. Every
decision a wrapped tool gets is cooperative and labeled PARTIAL.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Sequence
from typing import Any

from pantherclaw.client import Client, Outbound

from ._guard import Guard, PantherClawRefused, Verdict, refusal

__all__ = ["PantherClawRefused", "gateway_mcp_server", "guard_tools", "refusal"]


def _wrap(tool: Any, guard: Guard) -> Any:
    from agents import FunctionTool

    if not isinstance(tool, FunctionTool):
        raise TypeError(f"PantherClaw: guard_tools takes FunctionTools (function_tool), not {type(tool).__name__}")
    invoke, name = tool.on_invoke_tool, tool.name

    # The wrapped tool's invoker lives only in this closure: the guarded tool
    # has no attribute that reaches it, and its __wrapped__ raises.
    async def on_invoke_tool(ctx: Any, raw: str) -> Any:
        try:
            args = json.loads(raw) if raw else {}
        except ValueError:
            args = None
        v = await guard.adecide(name, args, getattr(ctx, "tool_call_id", None)) if isinstance(args, dict) else Verdict(code="wrapper_error")

        async def run() -> Any:
            return await invoke(ctx, raw)

        return await guard.afinish(v, run)

    return dataclasses.replace(tool, on_invoke_tool=on_invoke_tool)


def guard_tools(
    tools: Sequence[Any],
    client: Client,
    connection: str,
    *,
    on_hold: str = "wait",
    wait: float = 300.0,
    observe_unmapped: bool = False,
    raise_on_refusal: bool = False,
    on_dispatch: Callable[[str, Outbound], Any] | None = None,
) -> list[Any]:
    """Returns the function tools wrapped: each call goes to the /sdk face of
    ``connection``, whose package maps the tool by its name, and runs only
    on PantherClaw's allow; the model sees the same tools. The tools share
    one set of retries: an identical retry of a held call reuses its action
    id. A hold waits in PantherClaw (``on_hold="wait"``, ``wait`` seconds).
    A refused call returns ``PantherClaw refused this call: <code>
    (transaction <id>)`` to the model, or raises PantherClawRefused with
    ``raise_on_refusal``. ``on_dispatch`` sends PantherClaw's own request for
    a target-enforced connection and its return value is the tool's output;
    without it such a call is refused (dispatch_required)."""
    if on_hold != "wait":
        raise ValueError('PantherClaw: the OpenAI Agents SDK wrapper waits on holds (on_hold="wait")')
    guard = Guard(client, connection, on_hold=on_hold, wait=wait, observe_unmapped=observe_unmapped,
                  raise_on_refusal=raise_on_refusal, on_dispatch=on_dispatch)
    return [_wrap(t, guard) for t in tools]


def gateway_mcp_server(gateway: str, connection: str, key_file: str, run: str = "", pclaw: str = "pclaw", **options: Any) -> Any:
    """An MCPServerStdio that runs ``pclaw mcp proxy`` for a gateway
    connection: the agent reaches the connection's MCP server through the
    gateway's MCP face, which decides and enforces every call (no wrapper
    involved). ``key_file`` is the enrolled workload's key file and ``run``
    its run (default: the key file's). Other keyword arguments go to
    MCPServerStdio; ``name`` defaults to the connection."""
    from agents.mcp import MCPServerStdio

    args = ["mcp", "proxy", "--gateway", gateway, "--connection", connection, "--key-file", key_file]
    if run:
        args += ["--run", run]
    options.setdefault("name", connection)
    return MCPServerStdio(params={"command": pclaw, "args": args}, **options)
