# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Computer use in the OpenAI Agents SDK decided by PantherClaw (M33 D984;
HR-758).

``guard_computer`` wraps a ``Computer`` or ``AsyncComputer``: click,
double_click, drag, keypress, move, scroll and type are asked of
PantherClaw (``ComputerUseGuard``, package pc.computer) first and run only
on an allow; anything else raises ``PantherClawRefused``, so the action
never reaches the screen. screenshot and wait read the screen and pass
through. Every decision is cooperative and PARTIAL: only actions made
through the wrapped computer are decided.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pantherclaw.computer_use import ComputerDecision, ComputerUseGuard

from ._guard import PantherClawRefused

__all__ = ["guard_computer"]


def _check(d: ComputerDecision) -> None:
    if not d.allowed:
        raise PantherClawRefused(d.code or ("held" if d.held else "denied"), d.transaction_id)


def _decide(guard: ComputerUseGuard, action: dict[str, Any]) -> None:
    try:
        d = guard.decide_openai({"action": action})
    except Exception:  # noqa: BLE001 - any failure refuses
        d = ComputerDecision(False, code="wrapper_error")
    _check(d)


async def _adecide(guard: ComputerUseGuard, action: dict[str, Any]) -> None:
    try:
        d = await asyncio.to_thread(guard.decide_openai, {"action": action})
    except asyncio.CancelledError:
        raise
    except Exception:  # noqa: BLE001 - any failure refuses
        d = ComputerDecision(False, code="wrapper_error")
    _check(d)


def _path(path: Any) -> list[dict[str, int]]:
    return [{"x": int(p[0]), "y": int(p[1])} for p in path]


def guard_computer(computer: Any, guard: ComputerUseGuard) -> Any:
    """Returns ``computer`` wrapped in a Computer (or AsyncComputer, for an
    async one) subclass whose input actions PantherClaw decides first. The
    wrapped computer is reachable only through this closure."""
    from agents import AsyncComputer, Computer

    if not isinstance(guard, ComputerUseGuard):
        raise TypeError("PantherClaw: guard_computer takes a ComputerUseGuard")

    if isinstance(computer, AsyncComputer):
        inner_a = computer

        class GuardedAsyncComputer(AsyncComputer):
            @property
            def environment(self) -> Any:
                return inner_a.environment

            @property
            def dimensions(self) -> Any:
                return inner_a.dimensions

            async def screenshot(self) -> str:
                return await inner_a.screenshot()

            async def wait(self) -> None:
                await inner_a.wait()

            async def click(self, x: int, y: int, button: Any) -> None:
                await _adecide(guard, {"type": "click", "x": x, "y": y, "button": button})
                await inner_a.click(x, y, button)

            async def double_click(self, x: int, y: int) -> None:
                await _adecide(guard, {"type": "double_click", "x": x, "y": y})
                await inner_a.double_click(x, y)

            async def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
                await _adecide(guard, {"type": "scroll", "x": x, "y": y, "scroll_x": scroll_x, "scroll_y": scroll_y})
                await inner_a.scroll(x, y, scroll_x, scroll_y)

            async def type(self, text: str) -> None:
                await _adecide(guard, {"type": "type", "text": text})
                await inner_a.type(text)

            async def move(self, x: int, y: int) -> None:
                await _adecide(guard, {"type": "move", "x": x, "y": y})
                await inner_a.move(x, y)

            async def keypress(self, keys: list[str]) -> None:
                await _adecide(guard, {"type": "keypress", "keys": list(keys)})
                await inner_a.keypress(keys)

            async def drag(self, path: list[tuple[int, int]]) -> None:
                await _adecide(guard, {"type": "drag", "path": _path(path)})
                await inner_a.drag(path)

        return GuardedAsyncComputer()

    if not isinstance(computer, Computer):
        raise TypeError(f"PantherClaw: guard_computer takes a Computer or an AsyncComputer, not {type(computer).__name__}")
    inner = computer

    class GuardedComputer(Computer):
        @property
        def environment(self) -> Any:
            return inner.environment

        @property
        def dimensions(self) -> Any:
            return inner.dimensions

        def screenshot(self) -> str:
            return inner.screenshot()

        def wait(self) -> None:
            inner.wait()

        def click(self, x: int, y: int, button: Any) -> None:
            _decide(guard, {"type": "click", "x": x, "y": y, "button": button})
            inner.click(x, y, button)

        def double_click(self, x: int, y: int) -> None:
            _decide(guard, {"type": "double_click", "x": x, "y": y})
            inner.double_click(x, y)

        def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
            _decide(guard, {"type": "scroll", "x": x, "y": y, "scroll_x": scroll_x, "scroll_y": scroll_y})
            inner.scroll(x, y, scroll_x, scroll_y)

        def type(self, text: str) -> None:
            _decide(guard, {"type": "type", "text": text})
            inner.type(text)

        def move(self, x: int, y: int) -> None:
            _decide(guard, {"type": "move", "x": x, "y": y})
            inner.move(x, y)

        def keypress(self, keys: list[str]) -> None:
            _decide(guard, {"type": "keypress", "keys": list(keys)})
            inner.keypress(keys)

        def drag(self, path: list[tuple[int, int]]) -> None:
            _decide(guard, {"type": "drag", "path": _path(path)})
            inner.drag(path)

    return GuardedComputer()
