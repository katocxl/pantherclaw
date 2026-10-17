# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClaw for CrewAI (M14 PN-016.3; HR-328, HR-329).

``guard_tools`` wraps CrewAI tools so that every call, sync or async, is
decided by PantherClaw before the tool runs: only an allow runs it, a hold
waits in PantherClaw, and anything else returns a refusal to the agent.
Every decision is cooperative and labeled PARTIAL.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable, Sequence
from typing import Any

from pantherclaw.client import Client, Outbound

from ._guard import Guard, PantherClawRefused, refusal

__all__ = ["PantherClawRefused", "guard_tools", "refusal"]


def _never_cache(_args: Any = None, _result: Any = None) -> bool:
    # A cached result would answer a later call without a decision, and a
    # cached refusal would outlive its approval.
    return False


def _wrap(tool: Any, guard: Guard) -> Any:
    from crewai.tools import BaseTool
    from crewai.tools.base_tool import Tool

    if not isinstance(tool, BaseTool):
        raise TypeError(f"PantherClaw: guard_tools takes CrewAI tools (BaseTool or @tool), not {type(tool).__name__}")
    name = tool.name
    sync_only = type(tool)._arun is BaseTool._arun or (isinstance(tool, Tool) and not inspect.iscoroutinefunction(tool.func))

    # The wrapped tool lives only in this closure: the guarded tool has no
    # attribute that reaches it.
    class PantherClawTool(BaseTool):
        def _run(self, *args: Any, **kwargs: Any) -> Any:
            v = guard.decide(name, kwargs if not args else None)
            return guard.finish(v, lambda: tool.run(**kwargs))

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            v = await guard.adecide(name, kwargs if not args else None)

            async def run() -> Any:
                if sync_only:
                    return await asyncio.to_thread(tool.run, **kwargs)
                return await tool.arun(**kwargs)

            return await guard.afinish(v, run)

    PantherClawTool.__name__ = PantherClawTool.__qualname__ = f"PantherClaw{type(tool).__name__}"
    return PantherClawTool(
        name=name, description=tool.description, args_schema=tool.args_schema, result_as_answer=tool.result_as_answer,
        max_usage_count=tool.max_usage_count, cache_function=_never_cache,
    )


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
    """Returns the CrewAI tools wrapped: each call goes to the /sdk face of
    ``connection``, whose package maps the tool by its name, and runs only
    on PantherClaw's allow; the agent sees the same tools. Results are never
    cached (each call is decided). The tools share one set of retries: an
    identical retry of a held call reuses its action id. A hold waits in
    PantherClaw (``on_hold="wait"``, ``wait`` seconds). A refused call
    returns ``PantherClaw refused this call: <code> (transaction <id>)`` to
    the agent, or raises PantherClawRefused with ``raise_on_refusal``.
    ``on_dispatch`` sends PantherClaw's own request for a target-enforced
    connection and its return value is the tool's result; without it such a
    call is refused (dispatch_required)."""
    if on_hold != "wait":
        raise ValueError('PantherClaw: the CrewAI wrapper waits on holds (on_hold="wait")')
    guard = Guard(client, connection, on_hold=on_hold, wait=wait, observe_unmapped=observe_unmapped,
                  raise_on_refusal=raise_on_refusal, on_dispatch=on_dispatch)
    return [_wrap(t, guard) for t in tools]
