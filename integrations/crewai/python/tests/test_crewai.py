# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""pantherclaw-crewai through CrewAI's tool interface (T-150). No committed
lock contains CrewAI (M14 D60), so `task sdk:check` and CI run these tests on
a stand-in for that interface (tests/standin); `task sdk:crewai-real` runs
the same tests inside the real CrewAI, offline, with a scripted LLM inside a
Crew, and checks the stand-in against it."""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

REAL = importlib.util.find_spec("crewai") is not None
STANDIN = Path(__file__).resolve().parent / "standin"
if REAL:
    # Before CrewAI loads: no telemetry, no tracing, its storage in a temporary directory.
    os.environ.update({"CREWAI_DISABLE_TELEMETRY": "true", "OTEL_SDK_DISABLED": "true", "CREWAI_TRACING_ENABLED": "false",
                       "CREWAI_DISABLE_TRACKING": "true", "CREWAI_STORAGE_DIR": tempfile.mkdtemp(prefix="pc-crewai-")})
else:
    sys.path.insert(0, str(STANDIN))

import asyncio  # noqa: E402
import inspect  # noqa: E402
import json  # noqa: E402
import unittest  # noqa: E402
from collections.abc import Callable  # noqa: E402
from typing import Any  # noqa: E402

import conformance  # noqa: E402, F401 - puts the repository sources on the path
from conformance import Gateway, replay  # noqa: E402
from crewai.tools import BaseTool, tool  # noqa: E402

from pantherclaw.client import Client  # noqa: E402
from pantherclaw_crewai import PantherClawRefused, guard_tools  # noqa: E402

REFUND = {"amount": "30.00", "charge": "ch_1", "currency": "USD", "reason": "duplicate"}
# The cases about when an identical call reuses an action id (HR-329, M14 D68).
RETRY_CASES = (
    "held past the wait, then retried identically: the retry reuses the action id",
    "held past the wait, then called with changed input: a new decision",
    "allowed, then the identical call again: a new decision",
    "two identical calls at once while held: one runs, the other is a duplicate",
)


def refund_tool(fn: Callable[..., str]) -> BaseTool:
    @tool("create_refund", result_as_answer=True)
    def create_refund(amount: str, charge: str, currency: str, reason: str) -> str:
        """Refund a charge."""
        return fn(amount=amount, charge=charge, currency=currency, reason=reason)

    return create_refund


def run_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    return lambda args: guarded.run(**args) if isinstance(args, dict) else guarded.run(args)


def arun_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    return lambda args: asyncio.run(guarded.arun(**args) if isinstance(args, dict) else guarded.arun(args))


def structured_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
    """How a crew calls a tool: the func of the structured tool CrewAI builds from it."""
    (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
    return lambda args: guarded.to_structured_tool().func(**args) if isinstance(args, dict) else guarded.to_structured_tool().func(args)


class CrewAIToolTest(unittest.TestCase):
    def test_HR328_every_wrapper_case_replays_through_run(self) -> None:
        replay(self, run_adapter, PantherClawRefused)

    def test_HR328_every_wrapper_case_replays_through_arun(self) -> None:
        replay(self, arun_adapter, PantherClawRefused)

    def test_T150_every_wrapper_case_replays_through_the_structured_tool_a_crew_calls(self) -> None:
        replay(self, structured_adapter, PantherClawRefused)

    def test_HR329_an_identical_call_reuses_the_action_id_only_while_the_earlier_one_is_unresolved(self) -> None:
        replay(self, run_adapter, PantherClawRefused, only=RETRY_CASES)

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
        self.assertEqual((guarded.name, guarded.description, guarded.args_schema, guarded.result_as_answer),
                         (inner.name, inner.description, inner.args_schema, inner.result_as_answer))
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


if REAL:
    from crewai import Agent, Crew, Task
    from crewai.llms.base_llm import BaseLLM

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

    def kickoff(guarded: BaseTool, args: dict[str, Any]) -> str:
        """One crew, one agent, one task: the tool's result is the crew's answer (result_as_answer)."""
        agent = Agent(role="refunds", goal="Refund duplicates", backstory="Support", llm=ScriptedLLM(model="scripted", args=args),
                      tools=[guarded], allow_delegation=False, max_iter=3, verbose=False)
        task = Task(description="Refund ch_1", expected_output="the refund", agent=agent)
        return str(Crew(agents=[agent], tasks=[task], verbose=False).kickoff().raw)

    def crew_adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
        (guarded,) = guard_tools([refund_tool(fn)], client, connection, **opts)
        return lambda args: kickoff(guarded, args)


@unittest.skipUnless(REAL, "the real CrewAI is not installed: task sdk:crewai-real runs these (M14 D60)")
class RealCrewAITest(unittest.TestCase):
    def test_T150_every_wrapper_case_replays_through_a_crew(self) -> None:
        # A crew retries a tool that raised, so raise_on_refusal is replayed through run and arun.
        # A crew drops keys outside the schema before the tool and only passes objects.
        replay(self, crew_adapter, PantherClawRefused, raising=False, objects_only=True, drops_unknown=True)

    def test_HR328_a_crew_waits_on_a_hold(self) -> None:
        g = Gateway(["hold", "allow"], "ready")
        self.addCleanup(g.close)
        (guarded,) = guard_tools([refund_tool(lambda **_: "refunded")], g.client, "payments")
        self.assertEqual(kickoff(guarded, REFUND), "refunded")
        self.assertEqual(len({aid for aid, _ in g.requests}), 1)

    def test_the_standin_is_faithful_to_the_real_tool_interface(self) -> None:
        """What the wrapper and these tests use of CrewAI, compared with the stand-in that CI runs."""
        spec = importlib.util.spec_from_file_location("standin_base_tool", STANDIN / "crewai" / "tools" / "base_tool.py")
        assert spec and spec.loader
        standin = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = standin  # its dataclass looks its module up
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(standin)
        from crewai.tools import base_tool as real

        fields = {"name", "description", "args_schema", "result_as_answer", "max_usage_count", "current_usage_count", "cache_function"}
        self.assertLessEqual(fields, set(real.BaseTool.model_fields))
        self.assertIn("func", real.Tool.model_fields)
        self.assertLessEqual({"result_as_answer", "max_usage_count"}, set(inspect.signature(real.tool).parameters))
        for mod in (real, standin):
            for cls in ("BaseTool", "Tool"):
                for method in ("run", "arun", "_run", "_arun", "to_structured_tool"):
                    self.assertTrue(callable(getattr(getattr(mod, cls), method)), f"{mod.__name__}.{cls}.{method}")
            with self.subTest(module=mod.__name__):
                def join(a: str, b: str = "x") -> str:
                    """Join."""
                    return a + b

                def ok() -> str:
                    """OK."""
                    return "ok"

                with self.assertRaises(ValueError):
                    mod.tool("u")(lambda: "")  # no docstring
                t = mod.tool("t", result_as_answer=True)(join)
                self.assertEqual((t.name, t.result_as_answer, t.run(a="1")), ("t", True, "1x"))
                self.assertEqual(t.run(a="1", c="2"), "1x")  # an unknown argument is dropped
                with self.assertRaises(ValueError):
                    t.run(b="2")  # a missing one is refused
                with self.assertRaises(NotImplementedError):
                    asyncio.run(t.arun(a="1"))  # a sync function has no async path
                with self.assertRaises(NotImplementedError):
                    asyncio.run(mod.BaseTool._arun(t))
                st = t.to_structured_tool()
                self.assertEqual((st.name, st.func(a="2")), ("t", "2x"))
                capped = mod.tool("c", max_usage_count=1)(ok)
                self.assertEqual(capped.run(), "ok")
                self.assertIn("usage limit", str(capped.run()))


if __name__ == "__main__":
    unittest.main()
