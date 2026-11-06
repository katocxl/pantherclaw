# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Computer use in the OpenAI Agents SDK decided by PantherClaw (M33 D984;
HR-758).

``guard_computer`` wraps a ``Computer`` or ``AsyncComputer``: click,
double_click, drag, keypress, move, scroll and type are asked of
PantherClaw (``ComputerUseGuard``, package pc.computer) first and run only
on an allow; anything else raises ``PantherClawRefused``, so the action
never reaches the screen. screenshot and wait read the screen and pass
through. The SDK does not pass the computer_call's call_id to the
Computer, so each action's call comes from the action itself (``_Calls``):
a held action asked again through the same wrapped computer is the same
call. Every decision is cooperative and PARTIAL: only actions made through
the wrapped computer are decided.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
from typing import Any

from pantherclaw.computer_use import ComputerDecision, ComputerUseGuard

from ._guard import PantherClawRefused

__all__ = ["guard_computer"]


def _check(d: ComputerDecision) -> None:
    if not d.allowed:
        raise PantherClawRefused(d.code or ("held" if d.held else "denied"), d.transaction_id)


class _Calls:
    """The call each action is asked with. The Agents SDK calls a Computer's
    methods with the action's arguments only: the computer_call's call_id
    never reaches them, and one call_id can carry several actions. So the
    call is a digest of this wrapper's random salt, the action and its slot:
    the lowest number not used by an allowed identical action and not
    reserved by one still being decided. The slot is reserved under the
    lock when the call is made, so two identical actions decided at once
    (an async computer) are two calls (D1221a R2). An action that was held
    or refused gives its slot back and, asked again, is the same call, so
    its approval releases it; the same action after an allow is a new
    call."""

    def __init__(self) -> None:
        self._salt = secrets.token_hex(16)
        self._used: dict[str, set[int]] = {}
        self._reserved: dict[str, set[int]] = {}
        self._lock = threading.Lock()

    def call(self, action: dict[str, Any]) -> tuple[str, int, str]:
        key = json.dumps(action, sort_keys=True, separators=(",", ":"))
        with self._lock:
            used = self._used.setdefault(key, set())
            reserved = self._reserved.setdefault(key, set())
            n = 0
            while n in used or n in reserved:
                n += 1
            reserved.add(n)
        digest = hashlib.sha256(f"{self._salt}\n{n}\n{key}".encode()).hexdigest()
        return key, n, "oa-" + digest[:32]

    def done(self, key: str, n: int, allowed: bool) -> None:
        with self._lock:
            self._reserved.get(key, set()).discard(n)
            if allowed:
                self._used.setdefault(key, set()).add(n)


def _decide(guard: ComputerUseGuard, calls: _Calls, action: dict[str, Any]) -> None:
    try:
        key, n, call = calls.call(action)
    except Exception:  # noqa: BLE001 - any failure refuses
        _check(ComputerDecision(False, code="wrapper_error"))
        return
    try:
        d = guard.decide_openai({"call_id": call, "action": action})
    except Exception:  # noqa: BLE001 - any failure refuses
        d = ComputerDecision(False, code="wrapper_error")
    calls.done(key, n, d.allowed)
    _check(d)


async def _adecide(guard: ComputerUseGuard, calls: _Calls, action: dict[str, Any]) -> None:
    try:
        key, n, call = calls.call(action)
    except Exception:  # noqa: BLE001 - any failure refuses
        _check(ComputerDecision(False, code="wrapper_error"))
        return
    try:
        d = await asyncio.to_thread(guard.decide_openai, {"call_id": call, "action": action})
    except asyncio.CancelledError:
        calls.done(key, n, False)
        raise
    except Exception:  # noqa: BLE001 - any failure refuses
        d = ComputerDecision(False, code="wrapper_error")
    calls.done(key, n, d.allowed)
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
    calls = _Calls()

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
                await _adecide(guard, calls, {"type": "click", "x": x, "y": y, "button": button})
                await inner_a.click(x, y, button)

            async def double_click(self, x: int, y: int) -> None:
                await _adecide(guard, calls, {"type": "double_click", "x": x, "y": y})
                await inner_a.double_click(x, y)

            async def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
                await _adecide(guard, calls, {"type": "scroll", "x": x, "y": y, "scroll_x": scroll_x, "scroll_y": scroll_y})
                await inner_a.scroll(x, y, scroll_x, scroll_y)

            async def type(self, text: str) -> None:
                await _adecide(guard, calls, {"type": "type", "text": text})
                await inner_a.type(text)

            async def move(self, x: int, y: int) -> None:
                await _adecide(guard, calls, {"type": "move", "x": x, "y": y})
                await inner_a.move(x, y)

            async def keypress(self, keys: list[str]) -> None:
                await _adecide(guard, calls, {"type": "keypress", "keys": list(keys)})
                await inner_a.keypress(keys)

            async def drag(self, path: list[tuple[int, int]]) -> None:
                await _adecide(guard, calls, {"type": "drag", "path": _path(path)})
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
            _decide(guard, calls, {"type": "click", "x": x, "y": y, "button": button})
            inner.click(x, y, button)

        def double_click(self, x: int, y: int) -> None:
            _decide(guard, calls, {"type": "double_click", "x": x, "y": y})
            inner.double_click(x, y)

        def scroll(self, x: int, y: int, scroll_x: int, scroll_y: int) -> None:
            _decide(guard, calls, {"type": "scroll", "x": x, "y": y, "scroll_x": scroll_x, "scroll_y": scroll_y})
            inner.scroll(x, y, scroll_x, scroll_y)

        def type(self, text: str) -> None:
            _decide(guard, calls, {"type": "type", "text": text})
            inner.type(text)

        def move(self, x: int, y: int) -> None:
            _decide(guard, calls, {"type": "move", "x": x, "y": y})
            inner.move(x, y)

        def keypress(self, keys: list[str]) -> None:
            _decide(guard, calls, {"type": "keypress", "keys": list(keys)})
            inner.keypress(keys)

        def drag(self, path: list[tuple[int, int]]) -> None:
            _decide(guard, calls, {"type": "drag", "path": _path(path)})
            inner.drag(path)

    return GuardedComputer()
