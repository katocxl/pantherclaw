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

    def decide_openai(self, computer_call: Any) -> ComputerDecision:
        self.seen.append(computer_call["action"])
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


if __name__ == "__main__":
    unittest.main()
