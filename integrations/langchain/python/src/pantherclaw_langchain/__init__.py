# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClaw for LangChain tools and LangGraph tool nodes (M14 PN-016.3;
HR-328, HR-329).

``guard_tools`` wraps LangChain tools so that every call, sync or async, is
decided by PantherClaw before the tool runs: only an allow runs it, a hold
waits in PantherClaw (or, in a ``PantherClawToolNode`` with
``on_hold="interrupt"``, interrupts the graph), and anything else returns a
refusal to the model. Every decision is cooperative and labeled PARTIAL.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from pantherclaw.client import Client, Outbound

from ._guard import ON_HOLD, Guard, PantherClawRefused, Verdict, refusal

__all__ = ["ON_HOLD", "PantherClawRefused", "PantherClawToolNode", "guard_tools", "refusal"]


def _model_args(tool: Any, args: dict[str, Any]) -> dict[str, Any]:
    """The arguments the model gave: the tool call schema's, without the ones
    the framework injects (state, store, the call id)."""
    schema = tool.tool_call_schema
    if isinstance(schema, dict):
        names = set((schema.get("properties") or {}).keys())
    else:
        names = set(getattr(schema, "model_fields", None) or getattr(schema, "__fields__", {}))
    return {k: v for k, v in args.items() if k in names}


def _interrupt(value: dict[str, Any]) -> Any:
    from langgraph.types import interrupt

    return interrupt(value)


def _wrap(tool: Any, guard: Guard) -> Any:
    from langchain_core.messages import ToolMessage
    from langchain_core.tools import BaseTool

    interrupt = _interrupt if guard.on_hold == "interrupt" else None
    name = tool.name

    def message(content: Any, tool_call_id: str | None, v: Verdict) -> Any:
        """A refusal or the result of PantherClaw's own request, as the framework returns tool output."""
        if tool_call_id and not isinstance(content, ToolMessage):
            text = content if isinstance(content, str) else str(content)
            return ToolMessage(content=text, tool_call_id=tool_call_id, name=name, status="success" if v.send is not None else "error")
        return content

    def verdict(tool_input: Any, tool_call_id: str | None) -> tuple[Verdict, dict[str, Any]]:
        if not isinstance(tool_input, dict):
            return Verdict(code="wrapper_error"), {}
        return Verdict(), _model_args(tool, tool_input)

    # The wrapped tool lives only in this closure: the guarded tool has no
    # attribute that reaches it.
    class PantherClawTool(BaseTool):
        def _run(self, *args: Any, **kwargs: Any) -> Any:
            raise NotImplementedError("PantherClaw: call the tool through run or invoke")

        def get_input_schema(self, config: Any = None) -> Any:
            return tool.get_input_schema(config)

        def run(self, tool_input: Any, *args: Any, tool_call_id: str | None = None, **kwargs: Any) -> Any:
            v, model_args = verdict(tool_input, tool_call_id)
            if not v.code:
                v = guard.decide(name, model_args, tool_call_id, interrupt)
            out = guard.finish(v, lambda: tool.run(tool_input, *args, tool_call_id=tool_call_id, **kwargs))
            return out if v.run else message(out, tool_call_id, v)

        async def arun(self, tool_input: Any, *args: Any, tool_call_id: str | None = None, **kwargs: Any) -> Any:
            v, model_args = verdict(tool_input, tool_call_id)
            if not v.code:
                v = await guard.adecide(name, model_args, tool_call_id, interrupt)

            async def run() -> Any:
                return await tool.arun(tool_input, *args, tool_call_id=tool_call_id, **kwargs)

            out = await guard.afinish(v, run)
            return out if v.run else message(out, tool_call_id, v)

    PantherClawTool.__name__ = PantherClawTool.__qualname__ = f"PantherClaw{type(tool).__name__}"
    return PantherClawTool(
        name=name, description=tool.description, args_schema=tool.args_schema, return_direct=tool.return_direct,
        tags=tool.tags, metadata=tool.metadata, extras=getattr(tool, "extras", None),
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
    """Returns the tools wrapped: each call goes to the /sdk face of
    ``connection``, whose package maps the tool by its name, and runs only
    on PantherClaw's allow. The tools share one set of retries: an
    identical retry of a held call reuses its action id. ``on_hold`` is
    "wait" (``wait`` seconds in PantherClaw) or "interrupt" (LangGraph's
    interrupt, see PantherClawToolNode). A refused call returns
    ``PantherClaw refused this call: <code> (transaction <id>)`` to the model,
    or raises PantherClawRefused with ``raise_on_refusal``. ``on_dispatch``
    sends PantherClaw's own request for a target-enforced connection and its
    return value is the tool's result; without it such a call is refused
    (dispatch_required). Functions are converted with langchain_core's
    ``tool`` first."""
    from langchain_core.tools import BaseTool
    from langchain_core.tools import tool as as_tool

    guard = Guard(client, connection, on_hold=on_hold, wait=wait, observe_unmapped=observe_unmapped,
                  raise_on_refusal=raise_on_refusal, on_dispatch=on_dispatch)
    return [_wrap(t if isinstance(t, BaseTool) else as_tool(t), guard) for t in tools]


def __getattr__(name: str) -> Any:
    # PantherClawToolNode subclasses LangGraph's ToolNode, so it is built on
    # first use: langgraph is an optional extra.
    if name == "PantherClawToolNode":
        from ._langgraph import PantherClawToolNode

        return PantherClawToolNode
    raise AttributeError(name)
