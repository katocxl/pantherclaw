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

from ._guard import Guard, PantherClawRefused, Verdict, refusal

__all__ = ["PantherClawRefused", "guard_tools", "refusal"]


def _never_cache(_args: Any = None, _result: Any = None) -> bool:
    # A cached result would answer a later call without a decision, and a
    # cached refusal would outlive its approval.
    return False


def _fields(schema: Any) -> tuple[set[str], set[str]]:
    """A schema's field names, and the aliases they also accept."""
    fields = getattr(schema, "model_fields", None) or {}
    aliases = {a for f in fields.values() for a in (getattr(f, "alias", None), getattr(f, "validation_alias", None)) if isinstance(a, str)}
    return set(fields), aliases


def _jsonable(value: Any) -> Any:
    try:
        from pydantic_core import to_jsonable_python
    except ImportError:
        return value
    return to_jsonable_python(value)


def _wrap(tool: Any, guard: Guard) -> Any:
    from crewai.tools import BaseTool
    from crewai.tools.base_tool import Tool

    if not isinstance(tool, BaseTool):
        raise TypeError(f"PantherClaw: guard_tools takes CrewAI tools (BaseTool or @tool), not {type(tool).__name__}")
    name = tool.name
    sync_only = type(tool)._arun is BaseTool._arun or (isinstance(tool, Tool) and not inspect.iscoroutinefunction(tool.func))

    # The wrapped tool lives only in this closure: the guarded tool has no
    # attribute that reaches it.
    def decided(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[dict[str, Any] | None, set[str] | None, str]:
        """What PantherClaw decides (M14 D69): the arguments validated through
        the tool's own schema into exactly what its function receives, or a
        refusal code (positional arguments, keys outside the schema after
        alias normalisation, input the schema refuses)."""
        if args:
            return None, None, "wrapper_error"
        fields, aliases = _fields(tool.args_schema)
        if not fields:
            return kwargs, None, ""
        if any(k not in fields and k not in aliases for k in kwargs):
            return None, None, "undecided_args"
        try:
            validated = tool.args_schema.model_validate(kwargs).model_dump()
            return {k: _jsonable(v) for k, v in validated.items()}, fields, ""
        except Exception:  # noqa: BLE001 - input the schema refuses is never run undecided
            return None, None, "wrapper_error"

    def undeclared(args: tuple[Any, ...], kwargs: dict[str, Any]) -> bool:
        fields, aliases = _fields(tool.args_schema)
        return not args and bool(fields) and any(k not in fields and k not in aliases for k in kwargs)

    class PantherClawTool(BaseTool):
        # CrewAI's run and arun drop keys outside the schema before _run sees
        # them: a call carrying any is refused here (undecided_args, M14 D69).
        def run(self, *args: Any, **kwargs: Any) -> Any:
            if undeclared(args, kwargs):
                return guard.finish(Verdict(code="undecided_args"), lambda: None)
            return super().run(*args, **kwargs)

        async def arun(self, *args: Any, **kwargs: Any) -> Any:
            if undeclared(args, kwargs):
                return guard.finish(Verdict(code="undecided_args"), lambda: None)
            return await super().arun(*args, **kwargs)

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            call, parameters, code = decided(args, kwargs)
            v = Verdict(code=code) if code else guard.decide(name, call, parameters=parameters)
            return guard.finish(v, lambda: tool.run(**call))

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            call, parameters, code = decided(args, kwargs)
            v = Verdict(code=code) if code else await guard.adecide(name, call, parameters=parameters)

            async def run() -> Any:
                if sync_only:
                    return await asyncio.to_thread(tool.run, **call)
                return await tool.arun(**call)

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
