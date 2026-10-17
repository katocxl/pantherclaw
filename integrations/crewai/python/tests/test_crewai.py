# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""pantherclaw-crewai inside the real CrewAI (dev-only, pinned in uv.lock,
Python 3.13): offline, a scripted LLM, a fake PantherClaw (T-150)."""

from __future__ import annotations

import os
import tempfile

# Before CrewAI loads: no telemetry, no tracing, its storage in a temporary directory.
os.environ.update({"CREWAI_DISABLE_TELEMETRY": "true", "OTEL_SDK_DISABLED": "true", "CREWAI_TRACING_ENABLED": "false",
                   "CREWAI_DISABLE_TRACKING": "true", "CREWAI_STORAGE_DIR": tempfile.mkdtemp(prefix="pc-crewai-")})

import asyncio  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402
from collections.abc import Callable  # noqa: E402
from typing import Any  # noqa: E402

import conformance  # noqa: E402, F401 - puts the repository sources on the path
from conformance import Gateway, replay  # noqa: E402

from pantherclaw.client import Client  # noqa: E402

HAVE_CREWAI = importlib.util.find_spec("crewai") is not None
REFUND = {"amount": "30.00", "charge": "ch_1", "currency": "USD", "reason": "duplicate"}

if HAVE_CREWAI:
    from crewai import Agent, Crew, Task
    from crewai.llms.base_llm import BaseLLM
    from crewai.tools import BaseTool, tool

    from pantherclaw_crewai import PantherClawRefused, guard_tools

    class ScriptedLLM(BaseLLM):
        """Calls create_refund once with ``args``, in CrewAI's ReAct text format, then answers."""

        args: dict[str, Any]
        turns: int = 0

        def call(self, messages: Any, tools: Any = None, callbacks: Any = None, available_functions: Any = None,
                 from_task: Any = None, from_agent: Any = None, response_model: Any = None) -> str:
            self.turns += 1
            if self.turns == 1:
                return "Thought: I refund the charge.\nAction: create_refund\nAction Input: " + json.dumps(self.args)
            return "Thought: I am done.\nFinal Answer: done"

        async def acall(self, *args: Any, **kwargs: Any) -> str:
            return self.call(*args, **kwargs)

        def supports_function_calling(self) -> bool:
            return False

    def refund_tool(fn: Callable[..., str]) -> BaseTool:
        @tool("create_refund", result_as_answer=True)
        def create_refund(amount: str, charge: str, currency: str, reason: str) -> str:
            """Refund a charge."""
            return fn(amount=amount, charge=charge, currency=currency, reason=reason)

        return create_refund

    def kickoff(guarded: BaseTool, args: dict[str, Any]) -> str:
        """One crew, one agent, one task: the tool's result is the crew's answer (result_as_answer)."""
        agent = Agent(role="refunds", goal="Refund duplicates", backstory="Support", llm=ScriptedLLM(model="scripted", args=args),
                      tools=[guarded], allow_delegation=False, max_iter=3, verbose=False)
        task = Task(description="Refund ch_1", expected_output="the refund", agent=agent)
        return str(Crew(agents=[agent], tasks=[task], verbose=False).kickoff().raw)

    def run_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
        (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
        return lambda args: guarded.run(**args)

    def arun_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
        (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
        return lambda args: asyncio.run(guarded.arun(**args))

    def crew_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
        (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
        return lambda args: kickoff(guarded, args)


@unittest.skipUnless(HAVE_CREWAI, "CrewAI supports Python 3.13, not this one: test_core.py replays the vectors here")
class CrewAITest(unittest.TestCase):
    def test_HR328_every_wrapper_case_replays_through_run(self) -> None:
        replay(self, run_adapter, PantherClawRefused)

    def test_HR328_every_wrapper_case_replays_through_arun(self) -> None:
        replay(self, arun_adapter, PantherClawRefused)

    def test_T150_every_wrapper_case_replays_through_a_crew(self) -> None:
        # A crew retries a tool that raised, so raise_on_refusal is replayed through run and arun.
        replay(self, crew_adapter, PantherClawRefused, raising=False)

    def test_HR328_a_crew_runs_the_tool_only_on_pantherclaws_allow(self) -> None:
        for answer, expect, runs in (("allow", "refunded", 1), ("deny", "PantherClaw refused this call: GRANT_AMOUNT_EXCEEDED", 0)):
            with self.subTest(answer=answer):
                g = Gateway([answer])
                self.addCleanup(g.close)
                ran: list[Any] = []
                (guarded,) = guard_tools([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments")
                self.assertTrue(kickoff(guarded, REFUND).startswith(expect))
                self.assertEqual(len(ran), runs)
                self.assertEqual([body["input"] for _, body in g.requests], [REFUND])

    def test_HR328_a_crew_waits_on_a_hold(self) -> None:
        g = Gateway(["hold", "allow"], "ready")
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments")
        self.assertEqual(kickoff(guarded, REFUND), "refunded")
        self.assertEqual(len({aid for aid, _ in g.requests}), 1)

    def test_HR328_results_are_never_cached(self) -> None:
        g = Gateway(["deny", "allow"])
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments")
        self.assertFalse(guarded.cache_function(REFUND, "refunded"))
        self.assertTrue(guarded.run(**REFUND).startswith("PantherClaw refused"))
        self.assertEqual(guarded.run(**REFUND), "refunded")

    def test_HR329_the_wrapped_tool_is_not_an_attribute_of_the_guarded_one(self) -> None:
        g = Gateway([])
        self.addCleanup(g.close)
        inner = refund_tool(lambda **_: "refunded")
        (guarded,) = guard_tools([inner], g.client, "payments")
        self.assertEqual((guarded.name, guarded.description, guarded.args_schema), (inner.name, inner.description, inner.args_schema))
        values = [getattr(guarded, a, None) for a in dir(guarded) if not a.startswith("__")]
        self.assertFalse(any(v is inner or v is getattr(inner, "func", None) for v in values))
        self.assertIsNot(guarded.to_structured_tool().func, inner.func)

    def test_HR328_on_dispatch_sends_pantherclaws_request_instead_of_running_the_tool(self) -> None:
        g = Gateway(["send"])
        self.addCleanup(g.close)
        ran: list[Any] = []
        sent: list[Any] = []
        (guarded,) = guard_tools([refund_tool(lambda **k: ran.append(k) or "refunded")], g.client, "payments",
                                 on_dispatch=lambda call_id, o: sent.append(o) or "sent")
        self.assertEqual(guarded.run(**REFUND), "sent")
        self.assertEqual((ran, sent[0].url), ([], "https://payments.example.test/v1/refunds"))

    def test_only_crewai_tools_and_waits_are_taken(self) -> None:
        g = Gateway([])
        self.addCleanup(g.close)
        with self.assertRaises(TypeError):
            guard_tools([lambda: None], g.client, "payments")
        with self.assertRaises(ValueError):
            guard_tools([refund_tool(lambda **_: "")], g.client, "payments", on_hold="interrupt")


if __name__ == "__main__":
    unittest.main()
