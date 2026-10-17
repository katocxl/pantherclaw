# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""pantherclaw-openai-agents inside the real OpenAI Agents SDK (dev-only,
pinned in uv.lock): offline, its ScriptedModel, a fake PantherClaw (T-150)."""

from __future__ import annotations

import asyncio
import itertools
import json
import unittest
from collections.abc import Callable
from typing import Any

import conformance  # noqa: F401 - puts the repository sources on the path
from agents import Agent, FunctionTool, RunConfig, Runner, ToolCallOutputItem, function_tool
from agents.testing import ScriptedModel
from agents.testing.model import assistant_message, function_call
from agents.exceptions import UserError
from agents.tool_context import ToolContext
from conformance import Gateway, core_adapter, replay, same_copies

from pantherclaw.client import Client
from pantherclaw_openai_agents import PantherClawRefused, gateway_mcp_server, guard_tools
from pantherclaw_openai_agents._guard import Guard

REFUND = {"amount": "30.00", "charge": "ch_1", "currency": "USD", "reason": "duplicate"}
_ids = itertools.count(1)
# The cases about when an identical call reuses an action id (HR-329, M14 D68).
RETRY_CASES = (
    "held past the wait, then retried identically: the retry reuses the action id",
    "held past the wait, then called with changed input: a new decision",
    "allowed, then the identical call again: a new decision",
    "two identical calls at once while held: one runs, the other is a duplicate",
)


def refund_tool(fn: Callable[..., str]) -> FunctionTool:
    @function_tool
    def create_refund(amount: str, charge: str, currency: str, reason: str) -> str:
        """Refund a charge."""
        return fn(amount=amount, charge=charge, currency=currency, reason=reason)

    return create_refund


def invoke(tool: FunctionTool, args: Any) -> Any:
    raw = json.dumps(args)
    ctx = ToolContext(context=None, tool_name=tool.name, tool_call_id=f"call_{next(_ids)}", tool_arguments=raw)
    return asyncio.run(tool.on_invoke_tool(ctx, raw))


def direct_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    return lambda args: invoke(guarded, args)


def run_agent(tool: FunctionTool, args: dict[str, Any], call_id: str = "") -> str:
    """One agent turn whose scripted model calls the tool once; the tool's output as the run recorded it."""
    call_id = call_id or f"call_{next(_ids)}"
    model = ScriptedModel([[function_call("create_refund", args, call_id=call_id)], [assistant_message("done")]])
    agent = Agent(name="refunds", instructions="Refund duplicates.", model=model, tools=[tool])
    result = Runner.run_sync(agent, "refund ch_1", run_config=RunConfig(tracing_disabled=True))
    (out,) = [i for i in result.new_items if isinstance(i, ToolCallOutputItem)]
    return str(out.output)


def runner_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    def call(args: dict[str, Any]) -> str:
        try:
            return run_agent(guarded, args)
        except UserError as e:
            # The runner raises a tool's exception as the cause of its own.
            if isinstance(e.__cause__, PantherClawRefused):
                raise e.__cause__ from None
            raise

    return call


class OpenAIAgentsTest(unittest.TestCase):
    def test_HR328_every_wrapper_case_replays_through_the_decision_core(self) -> None:
        replay(self, core_adapter(Guard), PantherClawRefused)

    def test_HR328_every_wrapper_case_replays_through_the_tool_invoker(self) -> None:
        replay(self, direct_adapter, PantherClawRefused)

    def test_T150_every_wrapper_case_replays_through_an_agent_run(self) -> None:
        replay(self, runner_adapter, PantherClawRefused)

    def test_HR329_an_identical_call_reuses_the_action_id_only_while_the_earlier_one_is_unresolved(self) -> None:
        replay(self, direct_adapter, PantherClawRefused, only=RETRY_CASES)

    def test_HR328_the_call_id_is_the_models(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments")
        self.assertEqual(run_agent(guarded, REFUND, "call_model_1"), "refunded")
        self.assertEqual(g.requests[0][1]["tool_use_id"], "call_model_1")

    def test_HR329_the_wrapped_function_is_not_reachable_through_the_guarded_tool(self) -> None:
        g = Gateway([])
        self.addCleanup(g.close)
        inner = refund_tool(lambda **_: "refunded")
        (guarded,) = guard_tools([inner], g.client, "payments")
        self.assertTrue(callable(inner.__wrapped__))
        with self.assertRaises(AttributeError):
            _ = guarded.__wrapped__
        self.assertIsNot(guarded.on_invoke_tool, inner.on_invoke_tool)
        self.assertEqual((guarded.name, guarded.description, guarded.params_json_schema), (inner.name, inner.description, inner.params_json_schema))

    def test_HR328_arguments_that_are_not_an_object_are_refused(self) -> None:
        g = Gateway(["allow"])
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments")
        ctx = ToolContext(context=None, tool_name="create_refund", tool_call_id="call_x", tool_arguments="[1]")
        self.assertEqual(asyncio.run(guarded.on_invoke_tool(ctx, "[1]")), "PantherClaw refused this call: wrapper_error")
        self.assertEqual(asyncio.run(guarded.on_invoke_tool(ctx, "{")), "PantherClaw refused this call: wrapper_error")
        self.assertEqual(g.requests, [])

    def test_HR328_on_dispatch_sends_pantherclaws_request_instead_of_running_the_tool(self) -> None:
        g = Gateway(["send"])
        self.addCleanup(g.close)
        ran: list[Any] = []
        sent: list[Any] = []
        (guarded,) = guard_tools([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments",
                                 on_dispatch=lambda call_id, o: sent.append((call_id, o)) or "sent")
        self.assertEqual(run_agent(guarded, REFUND, "call_d"), "sent")
        self.assertEqual(ran, [])
        ((call_id, o),) = sent
        self.assertEqual((call_id, o.url), ("call_d", "https://payments.example.test/v1/refunds"))

    def test_only_function_tools_and_waits_are_taken(self) -> None:
        g = Gateway([])
        self.addCleanup(g.close)
        with self.assertRaises(TypeError):
            guard_tools([lambda: None], g.client, "payments")
        with self.assertRaises(ValueError):
            guard_tools([refund_tool(lambda **_: "")], g.client, "payments", on_hold="interrupt")

    def test_the_gateway_mcp_server_runs_pclaw_mcp_proxy(self) -> None:
        s = gateway_mcp_server("https://gateway.example.test", "github", "agent.key.json", run="r1")
        self.assertEqual(s.name, "github")
        self.assertEqual(s.params.command, "pclaw")
        self.assertEqual(s.params.args, ["mcp", "proxy", "--gateway", "https://gateway.example.test", "--connection", "github",
                                         "--key-file", "agent.key.json", "--run", "r1"])

    def test_the_shared_files_are_identical_in_every_wrapper(self) -> None:
        same_copies(self, "src/{pkg}/_guard.py")
        same_copies(self, "tests/conformance.py")


if __name__ == "__main__":
    unittest.main()
