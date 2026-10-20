# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""pantherclaw-langchain inside the real LangChain and LangGraph (dev-only,
pinned in uv.lock): offline, a fake chat model, a fake PantherClaw (T-150)."""

from __future__ import annotations

import asyncio
import operator
import unittest
from collections.abc import Callable
from typing import Annotated, Any, TypedDict

import conformance  # noqa: F401 - puts the repository sources on the path
from conformance import Gateway, core_adapter, replay, same_copies
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, ToolMessage
from langchain_core.tools import BaseTool, InjectedToolArg, InjectedToolCallId, StructuredTool, tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import InjectedState
from langgraph.types import Command
from pydantic import BaseModel, ConfigDict, Field

from pantherclaw.client import Client
from pantherclaw_langchain import PantherClawRefused, PantherClawToolNode, guard_tools
from pantherclaw_langchain._guard import Guard

REFUND = {"amount": "30.00", "charge": "ch_1", "currency": "USD", "reason": "duplicate"}
# The cases about when an identical call reuses an action id (HR-329, M14 D68).
RETRY_CASES = (
    "held past the wait, then retried identically: the retry reuses the action id",
    "held past the wait, then called with changed input: a new decision",
    "allowed, then the identical call again: a new decision",
    "two identical calls at once while held: one runs, the other is a duplicate",
)


def refund_tool(fn: Callable[..., str]) -> BaseTool:
    def create_refund(amount: str, charge: str, currency: str, reason: str) -> str:
        """Refund a charge."""
        return fn(amount=amount, charge=charge, currency=currency, reason=reason)

    async def acreate_refund(amount: str, charge: str, currency: str, reason: str) -> str:
        """Refund a charge."""
        return fn(amount=amount, charge=charge, currency=currency, reason=reason)

    return StructuredTool.from_function(func=create_refund, coroutine=acreate_refund, name="create_refund")


def text(out: Any) -> str:
    return out.content if isinstance(out, ToolMessage) else out


class _Calls:
    n = 0

    @classmethod
    def next_id(cls) -> str:
        cls.n += 1
        return f"call_{cls.n}"


def sync_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    def call(args: Any) -> str:
        if not isinstance(args, dict):
            return text(guarded.invoke(args))
        return text(guarded.invoke({"type": "tool_call", "name": "create_refund", "args": args, "id": _Calls.next_id()}))

    return call


def async_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    return lambda args: text(asyncio.run(guarded.ainvoke(args)))


class State(TypedDict):
    messages: Annotated[list[AnyMessage], operator.add]


def graph(model: GenericFakeChatModel, node: PantherClawToolNode, checkpointer: Any = None) -> Any:
    """A one-step agent: the model's tool calls, then PantherClaw's tool node."""
    g = StateGraph(State)
    g.add_node("agent", lambda s: {"messages": [model.invoke(s["messages"])]})
    g.add_node("tools", node)
    g.add_edge(START, "agent")
    g.add_edge("agent", "tools")
    g.add_edge("tools", END)
    return g.compile(checkpointer=checkpointer)


def model_calling(args: dict[str, Any], call_id: str = "call_a") -> GenericFakeChatModel:
    msg = AIMessage(content="", tool_calls=[{"name": "create_refund", "args": args, "id": call_id, "type": "tool_call"}])
    return GenericFakeChatModel(messages=iter([msg]))


def graph_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    node = PantherClawToolNode([refund_tool(fn)], client, connection, handle_tool_errors=False, **opts)

    def call(args: dict[str, Any]) -> str:
        out = graph(model_calling(args, _Calls.next_id()), node).invoke({"messages": [HumanMessage("refund ch_1")]})
        return out["messages"][-1].content

    return call


class LangChainTest(unittest.TestCase):
    def test_HR328_every_wrapper_case_replays_through_the_decision_core(self) -> None:
        replay(self, core_adapter(Guard), PantherClawRefused)

    def test_HR328_every_wrapper_case_replays_through_invoke(self) -> None:
        replay(self, sync_adapter, PantherClawRefused)

    def test_HR328_every_wrapper_case_replays_through_ainvoke(self) -> None:
        replay(self, async_adapter, PantherClawRefused)

    def test_T150_every_wrapper_case_replays_through_a_langgraph_tool_node(self) -> None:
        replay(self, graph_adapter, PantherClawRefused, objects_only=True)

    def test_HR329_the_wrapped_tool_is_not_an_attribute_of_the_guarded_one(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        inner = refund_tool(lambda **_: "refunded")
        (guarded,) = guard_tools([inner], g.client, "payments")
        self.assertEqual((guarded.name, guarded.description, guarded.args), (inner.name, inner.description, inner.args))
        values = [getattr(guarded, a, None) for a in dir(guarded) if not a.startswith("__")]
        self.assertFalse(any(v is inner or v is getattr(inner, "func", None) for v in values))
        self.assertFalse(hasattr(guarded, "func") and guarded.func is not None)

    def test_HR328_the_model_sees_the_same_tool(self) -> None:
        g = Gateway([])
        self.addCleanup(g.close)
        inner = refund_tool(lambda **_: "refunded")
        (guarded,) = guard_tools([inner], g.client, "payments")
        self.assertEqual(guarded.tool_call_schema.model_json_schema(), inner.tool_call_schema.model_json_schema())

    def test_HR328_a_function_tool_is_converted_and_guarded(self) -> None:
        g = Gateway(["deny"])
        self.addCleanup(g.close)
        ran: list[str] = []

        @tool
        def create_refund(amount: str, charge: str, currency: str, reason: str) -> str:
            """Refund a charge."""
            ran.append(charge)
            return "refunded"

        (guarded,) = guard_tools([create_refund.func], g.client, "payments")  # a plain function
        out = guarded.invoke(REFUND)
        self.assertEqual(ran, [])
        self.assertTrue(out.startswith("PantherClaw refused this call: GRANT_AMOUNT_EXCEEDED"))

    def test_HR328_input_that_is_not_an_object_is_refused(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)

        @tool
        def lookup(query: str) -> str:
            """Look something up."""
            return "found"

        (guarded,) = guard_tools([lookup], g.client, "payments")
        self.assertEqual(guarded.run("refunds"), "PantherClaw refused this call: wrapper_error")
        self.assertEqual(g.requests, [])

    def test_HR328_injected_arguments_are_not_decided(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        seen: list[str] = []

        @tool
        def create_refund(charge: str, call: Annotated[str, InjectedToolCallId]) -> str:
            """Refund a charge."""
            seen.append(call)
            return "refunded"

        (guarded,) = guard_tools([create_refund], g.client, "payments")
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": {"charge": "ch_1"}, "id": "call_x"})
        self.assertEqual((out.content, seen), ("refunded", ["call_x"]))
        self.assertEqual(g.requests[0][1]["input"], {"charge": "ch_1"})
        self.assertEqual(g.requests[0][1]["tool_use_id"], "call_x")

    def test_HR329_an_identical_call_reuses_the_action_id_only_while_the_earlier_one_is_unresolved(self) -> None:
        replay(self, sync_adapter, PantherClawRefused, only=RETRY_CASES)

    def test_HR329_a_finished_call_never_forgets_a_later_calls_action_id(self) -> None:
        # Two calls share an id in flight; after the first ends, a new identical call gets its own id,
        # and the second ending must not forget the new one's.
        g = Gateway([])
        self.addCleanup(g.close)
        guard = Guard(g.client, "payments")
        a = guard._begin("create_refund", REFUND, None, None)
        c = guard._begin("create_refund", REFUND, None, None)
        self.assertEqual(a.action_id, c.action_id)
        guard._forget(a)
        b = guard._begin("create_refund", REFUND, None, None)
        self.assertNotEqual(b.action_id, a.action_id)
        guard._forget(c)
        self.assertEqual(guard._begin("create_refund", REFUND, None, None).action_id, b.action_id)

    def test_HR328_a_model_supplied_generic_injected_tool_arg_is_refused_undecided_args(self) -> None:
        # M14 D81: only the injected arguments the framework overwrites pass undecided; a generic
        # InjectedToolArg in the model's tool call would reach the function undecided.
        g = Gateway(["allow", "allow"])
        self.addCleanup(g.close)
        seen: list[str] = []

        @tool
        def create_refund(charge: str, account_id: Annotated[str, InjectedToolArg]) -> str:
            """Refund a charge."""
            seen.append(account_id)
            return "refunded"

        (guarded,) = guard_tools([create_refund], g.client, "payments")
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": {"charge": "ch_1", "account_id": "acct_9"}, "id": "c1"})
        self.assertEqual((out.content, seen, g.requests), ("PantherClaw refused this call: undecided_args", [], []))
        # The application itself may pass it when it invokes the tool without a tool call.
        self.assertEqual(guarded.invoke({"charge": "ch_1", "account_id": "acct_app"}), "refunded")
        self.assertEqual((seen, g.requests[0][1]["input"]), (["acct_app"], {"charge": "ch_1"}))

    def test_HR328_arguments_the_framework_overwrites_pass_undecided(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        seen: list[Any] = []

        @tool
        def create_refund(charge: str, call: Annotated[str, InjectedToolCallId], state: Annotated[dict, InjectedState]) -> str:
            """Refund a charge."""
            seen.append((call, state))
            return "refunded"

        (guarded,) = guard_tools([create_refund], g.client, "payments")
        args = {"charge": "ch_1", "state": {"messages": []}}
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": args, "id": "c9"})
        self.assertEqual((out.content, seen, g.requests[0][1]["input"]), ("refunded", [("c9", {"messages": []})], {"charge": "ch_1"}))

    def test_HR328_the_tool_runs_with_the_parsed_values_under_their_alias(self) -> None:
        # M14 D81: the tool runs with the decided, parsed values, never the caller's input again.
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        seen: list[str] = []

        class Args(BaseModel):
            from_: str = Field(alias="from")

        def transfer(from_: str) -> str:
            seen.append(from_)
            return "moved"

        t = StructuredTool(name="create_refund", description="Move.", func=transfer, args_schema=Args)
        (guarded,) = guard_tools([t], g.client, "payments")
        raw = {"from": "acct_1"}
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": raw, "id": "c4"})
        self.assertEqual((out.content, seen, raw), ("moved", ["acct_1"], {"from": "acct_1"}))
        self.assertEqual(g.requests[0][1]["input"], {"from_": "acct_1"})

    def test_HR328_keys_outside_the_schema_are_refused_undecided_args(self) -> None:
        g = Gateway(["allow", "allow"])
        self.addCleanup(g.close)
        ran: list[Any] = []

        def run_anything(**kwargs: Any) -> str:
            ran.append(kwargs)
            return "ran"

        loose = StructuredTool(name="create_refund", description="Refund.", func=run_anything,
                               args_schema={"type": "object", "properties": {"charge": {"type": "string"}}})
        (guarded,) = guard_tools([loose], g.client, "payments")
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": {"charge": "ch_1", "amount": "999.00"}, "id": "c2"})
        self.assertEqual((out.content, ran, g.requests), ("PantherClaw refused this call: undecided_args", [], []))

    def test_HR328_an_alias_is_decided_as_the_value_the_function_receives(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        seen: list[str] = []

        class Args(BaseModel):
            model_config = ConfigDict(populate_by_name=True)
            from_: str = Field(alias="from")

        def transfer(from_: str) -> str:
            seen.append(from_)
            return "moved"

        t = StructuredTool(name="create_refund", description="Move.", func=transfer, args_schema=Args)
        (guarded,) = guard_tools([t], g.client, "payments")
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": {"from_": "benign", "from": "evil"}, "id": "c3"})
        self.assertEqual(out.content, "moved")
        # PantherClaw decided exactly the value the function received.
        self.assertEqual(g.requests[0][1]["input"], {"from_": seen[0]})

    def test_HR328_arguments_that_are_not_json_are_refused_wrapper_error(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        guard = Guard(g.client, "payments")
        self.assertEqual(guard.decide("create_refund", {"when": object()}).code, "wrapper_error")
        self.assertEqual(g.requests, [])

    def test_HR328_a_wait_that_raises_is_refused_wrapper_error(self) -> None:
        g = Gateway(["hold"], "ready")
        self.addCleanup(g.close)

        def broken(*_: Any, **__: Any) -> Any:
            raise RuntimeError("the wait broke")

        g.client.resume = broken  # type: ignore[method-assign]
        ran: list[Any] = []
        (guarded,) = guard_tools([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments")
        self.assertEqual((guarded.invoke(REFUND), ran), ("PantherClaw refused this call: wrapper_error", []))

    def test_HR328_an_interrupt_outside_a_graph_is_refused_wrapper_error(self) -> None:
        g = Gateway(["hold"], "ready")
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments", on_hold="interrupt")
        self.assertEqual(guarded.invoke(REFUND), "PantherClaw refused this call: wrapper_error")

    def test_HR328_an_async_on_dispatch_on_a_sync_call_is_refused_never_left_unsent(self) -> None:
        g = Gateway(["send"])
        self.addCleanup(g.close)

        async def send(_call_id: str, _o: Any) -> str:
            return "sent"

        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments", on_dispatch=send)
        self.assertEqual(guarded.invoke(REFUND),
                         "PantherClaw refused this call: wrapper_error (transaction 01920000-0000-7000-8000-000000000009)")
        (aguarded,) = guard_tools([refund_tool(lambda **_: "refunded")], Gateway(["send"]).client, "payments", on_dispatch=send)
        self.assertEqual(asyncio.run(aguarded.ainvoke(REFUND)), "sent")

    def test_HR328_a_hold_still_pending_when_the_graph_resumes_interrupts_again(self) -> None:
        g = Gateway(["hold", "hold", "hold", "hold", "hold", "allow"], "ready")
        self.addCleanup(g.close)
        ran: list[Any] = []
        node = PantherClawToolNode([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments", on_hold="interrupt")
        app = graph(model_calling(REFUND), node, InMemorySaver())
        cfg = {"configurable": {"thread_id": "t3"}}
        self.assertIn("__interrupt__", app.invoke({"messages": [HumanMessage("refund ch_1")]}, cfg))
        # Resumed before the approval: still held, so the graph is interrupted again instead of waiting.
        self.assertIn("__interrupt__", app.invoke(Command(resume="too early"), cfg))
        self.assertEqual(ran, [])
        out = app.invoke(Command(resume="approved"), cfg)
        self.assertEqual((out["messages"][-1].content, ran), ("refunded", [REFUND]))
        self.assertEqual(len({aid for aid, _ in g.requests}), 1)

    def test_HR328_on_dispatch_sends_pantherclaws_request_instead_of_running_the_tool(self) -> None:
        g = Gateway(["send"])
        self.addCleanup(g.close)
        ran: list[Any] = []
        sent: list[Any] = []
        (guarded,) = guard_tools([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments",
                                 on_dispatch=lambda call_id, o: sent.append((call_id, o)) or "sent")
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": REFUND, "id": "call_d"})
        self.assertEqual((out.content, out.status, ran), ("sent", "success", []))
        ((call_id, o),) = sent
        self.assertEqual((call_id, o.method, o.url), ("call_d", "POST", "https://payments.example.test/v1/refunds"))
        self.assertIn("PAP-Action", o.headers)

    def test_HR328_a_refusal_is_an_error_tool_message(self) -> None:
        g = Gateway(["deny"])
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments")
        out = guarded.invoke({"type": "tool_call", "name": "create_refund", "args": REFUND, "id": "call_e"})
        self.assertIsInstance(out, ToolMessage)
        self.assertEqual((out.status, out.tool_call_id), ("error", "call_e"))

    def test_HR328_a_hold_interrupts_the_graph_and_runs_once_resumed_and_allowed(self) -> None:
        g = Gateway(["hold", "hold", "allow"], "ready")
        self.addCleanup(g.close)
        ran: list[Any] = []
        node = PantherClawToolNode([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments", on_hold="interrupt")
        app = graph(model_calling(REFUND), node, InMemorySaver())
        cfg = {"configurable": {"thread_id": "t1"}}
        out = app.invoke({"messages": [HumanMessage("refund ch_1")]}, cfg)
        (intr,) = out["__interrupt__"]
        pc = intr.value["pantherclaw"]
        self.assertEqual(pc["transaction_id"], "01920000-0000-7000-8000-000000000009")
        self.assertEqual(pc["action_id"], g.requests[0][0])
        self.assertTrue(pc["deadline"])
        self.assertEqual(ran, [])
        out = app.invoke(Command(resume="approved"), cfg)
        self.assertEqual(out["messages"][-1].content, "refunded")
        self.assertEqual(ran, [REFUND])
        # The resumed node resubmitted the identical call with the same action id.
        self.assertEqual(len({aid for aid, _ in g.requests}), 1)
        self.assertEqual(len(g.requests), 3)

    def test_HR328_an_interrupted_hold_denied_when_the_graph_resumes_is_refused(self) -> None:
        # The resumed node resubmits the identical call; a deny then is hold_declined (M14 D79).
        g = Gateway(["hold", "hold", "deny"])
        self.addCleanup(g.close)
        ran: list[Any] = []
        node = PantherClawToolNode([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments", on_hold="interrupt")
        app = graph(model_calling(REFUND), node, InMemorySaver())
        cfg = {"configurable": {"thread_id": "t2"}}
        app.invoke({"messages": [HumanMessage("refund ch_1")]}, cfg)
        out = app.invoke(Command(resume="go"), cfg)
        self.assertEqual(out["messages"][-1].content,
                         "PantherClaw refused this call: hold_declined (transaction 01920000-0000-7000-8000-000000000009)")
        self.assertEqual(ran, [])

    def test_the_options_are_checked(self) -> None:
        g = Gateway([])
        self.addCleanup(g.close)
        with self.assertRaises(ValueError):
            guard_tools([refund_tool(lambda **_: "")], g.client, "payments", on_hold="ask")
        with self.assertRaises(ValueError):
            guard_tools([refund_tool(lambda **_: "")], g.client, "")

    def test_the_shared_files_are_identical_in_every_wrapper(self) -> None:
        same_copies(self, "src/{pkg}/_guard.py")
        same_copies(self, "tests/conformance.py")


if __name__ == "__main__":
    unittest.main()

