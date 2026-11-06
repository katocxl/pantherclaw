# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""HR-758: guard_computer asks PantherClaw before each input action of an
OpenAI Agents SDK Computer and runs it only on an allow."""

from __future__ import annotations

import asyncio
import unittest
from typing import Any

import conformance  # noqa: F401 - puts the repository sources on the path
from agents import AsyncComputer, Computer

from pantherclaw.computer_use import ComputerDecision, ComputerUseGuard
from pantherclaw_openai_agents import PantherClawRefused, guard_computer


class _Guard(ComputerUseGuard):
    """Records each computer call and answers ``decision``."""

    def __init__(self, decision: ComputerDecision) -> None:  # noqa: D107 - no client: decide_openai is replaced
        self.decision = decision
        self.seen: list[dict[str, Any]] = []
        self.calls: list[str] = []

    def decide_openai(self, computer_call: Any) -> ComputerDecision:
        self.seen.append(computer_call["action"])
        self.calls.append(computer_call["call_id"])
        return self.decision


class _Raising(_Guard):
    def decide_openai(self, computer_call: Any) -> ComputerDecision:
        raise RuntimeError("boom")


class _Screen(Computer):
    def __init__(self) -> None:
        self.done: list[str] = []

    @property
    def environment(self) -> Any:
        return "linux"

    @property
    def dimensions(self) -> tuple[int, int]:
        return (1024, 768)

    def screenshot(self) -> str:
        self.done.append("screenshot")
        return "png"

    def click(self, x: int, y: int, button: Any) -> None:
        self.done.append("click")

    def double_click(self, x: int, y: int) -> None:
        self.done.append("double_click")

    def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
        self.done.append("scroll")

    def type(self, text: str) -> None:
        self.done.append("type")

    def wait(self) -> None:
        self.done.append("wait")

    def move(self, x: int, y: int) -> None:
        self.done.append("move")

    def keypress(self, keys: list[str]) -> None:
        self.done.append("keypress")

    def drag(self, path: list[tuple[int, int]]) -> None:
        self.done.append("drag")


class _AsyncScreen(AsyncComputer):
    def __init__(self) -> None:
        self.done: list[str] = []

    @property
    def environment(self) -> Any:
        return "linux"

    @property
    def dimensions(self) -> tuple[int, int]:
        return (1024, 768)

    async def screenshot(self) -> str:
        self.done.append("screenshot")
        return "png"

    async def click(self, x: int, y: int, button: Any) -> None:
        self.done.append("click")

    async def double_click(self, x: int, y: int) -> None:
        self.done.append("double_click")

    async def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
        self.done.append("scroll")

    async def type(self, text: str) -> None:
        self.done.append("type")

    async def wait(self) -> None:
        self.done.append("wait")

    async def move(self, x: int, y: int) -> None:
        self.done.append("move")

    async def keypress(self, keys: list[str]) -> None:
        self.done.append("keypress")

    async def drag(self, path: list[tuple[int, int]]) -> None:
        self.done.append("drag")


def _act(c: Any) -> None:
    c.click(1, 2, "left")
    c.double_click(1, 2)
    c.scroll(1, 2, 0, 3)
    c.type("hi")
    c.move(3, 4)
    c.keypress(["CTRL", "S"])
    c.drag([(0, 0), (5, 6)])


class GuardComputerTest(unittest.TestCase):
    def test_HR758_an_allowed_action_runs_after_it_was_asked(self) -> None:
        g, screen = _Guard(ComputerDecision(True)), _Screen()
        c = guard_computer(screen, g)
        self.assertIsInstance(c, Computer)
        _act(c)
        self.assertEqual(screen.done, ["click", "double_click", "scroll", "type", "move", "keypress", "drag"])
        self.assertEqual([a["type"] for a in g.seen], ["click", "double_click", "scroll", "type", "move", "keypress", "drag"])
        self.assertEqual(g.seen[5]["keys"], ["CTRL", "S"])
        self.assertEqual(g.seen[6]["path"], [{"x": 0, "y": 0}, {"x": 5, "y": 6}])
        # screenshot and wait pass through, never asked.
        self.assertEqual((c.screenshot(), c.dimensions, c.environment), ("png", (1024, 768), "linux"))
        c.wait()
        self.assertEqual(len(g.seen), 7)

    def test_HR758_a_refused_or_held_action_raises_and_never_runs(self) -> None:
        for d, code in ((ComputerDecision(False, code="denied"), "denied"), (ComputerDecision(False, held=True, transaction_id="t-2"), "held")):
            g, screen = _Guard(d), _Screen()
            c = guard_computer(screen, g)
            for act in (lambda: c.click(1, 2, "left"), lambda: c.type("x"), lambda: c.keypress(["A"]), lambda: c.drag([(1, 1)])):
                with self.assertRaises(PantherClawRefused) as e:
                    act()
                self.assertEqual(e.exception.code, code)
            self.assertEqual(screen.done, [])
        screen = _Screen()
        with self.assertRaises(PantherClawRefused) as e:
            guard_computer(screen, _Raising(ComputerDecision(True))).move(1, 1)
        self.assertEqual((e.exception.code, screen.done), ("wrapper_error", []))
        with self.assertRaises(TypeError):
            guard_computer(screen, object())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            guard_computer(object(), _Guard(ComputerDecision(True)))

    def test_HR758_an_async_computer_is_asked_the_same_way(self) -> None:
        g, screen = _Guard(ComputerDecision(True)), _AsyncScreen()
        c = guard_computer(screen, g)
        self.assertIsInstance(c, AsyncComputer)

        async def go() -> None:
            await c.click(1, 2, "left")
            await c.screenshot()
            await c.wait()
            g.decision = ComputerDecision(False, code="denied")
            with self.assertRaises(PantherClawRefused):
                await c.type("x")

        asyncio.run(go())
        self.assertEqual(screen.done, ["click", "screenshot", "wait"])
        self.assertEqual([a["type"] for a in g.seen], ["click", "type"])

    def test_HR758_a_held_action_asked_again_is_the_same_call(self) -> None:
        # The SDK passes no call_id to a Computer: the call comes from the
        # action, so asking a held action again sends the same call, and the
        # same action after an allow is a new one.
        g, screen = _Guard(ComputerDecision(False, held=True, transaction_id="t-2")), _Screen()
        c = guard_computer(screen, g)
        for _ in range(2):
            with self.assertRaises(PantherClawRefused):
                c.keypress(["ENTER"])
        held = g.calls[0]
        self.assertRegex(held, r"^oa-[0-9a-f]{32}\Z")
        self.assertEqual(g.calls, [held, held])
        g.decision = ComputerDecision(True)
        c.keypress(["ENTER"])
        c.keypress(["ENTER"])
        c.keypress(["TAB"])
        self.assertEqual(g.calls[2], held)
        self.assertEqual(len(set(g.calls[2:])), 3)
        self.assertEqual(screen.done, ["keypress", "keypress", "keypress"])
        # Another wrapped computer never repeats these calls.
        g2 = _Guard(ComputerDecision(True))
        guard_computer(_Screen(), g2).keypress(["ENTER"])
        self.assertNotIn(g2.calls[0], g.calls)

        async def go() -> list[str]:
            ga = _Guard(ComputerDecision(False, held=True))
            ca = guard_computer(_AsyncScreen(), ga)
            for _ in range(2):
                with self.assertRaises(PantherClawRefused):
                    await ca.type("x")
            return ga.calls

        a = asyncio.run(go())
        self.assertEqual(a[0], a[1])

    def test_HR758_identical_async_actions_decided_at_once_are_two_calls(self) -> None:
        # The slot is reserved when the call is made (D1221a R2): two
        # identical actions in flight together never share a call, and a
        # held one gives its slot back, so asked again it is the same call.
        import threading

        gate = threading.Barrier(2, timeout=5)

        class _Both(_Guard):
            def decide_openai(self, computer_call: Any) -> ComputerDecision:
                d = super().decide_openai(computer_call)
                gate.wait()
                return d

        async def go() -> tuple[list[str], list[str]]:
            g = _Both(ComputerDecision(True))
            c = guard_computer(_AsyncScreen(), g)
            await asyncio.gather(c.type("x"), c.type("x"))
            first = list(g.calls)
            h = _Guard(ComputerDecision(False, held=True))
            ch = guard_computer(_AsyncScreen(), h)
            for _ in range(2):
                with self.assertRaises(PantherClawRefused):
                    await ch.type("y")
            return first, h.calls

        both, held = asyncio.run(go())
        self.assertEqual(len(both), 2)
        self.assertNotEqual(both[0], both[1])
        self.assertEqual(held[0], held[1])


if __name__ == "__main__":
    unittest.main()
