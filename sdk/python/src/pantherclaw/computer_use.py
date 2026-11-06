# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Computer use decided by PantherClaw (M33 D984; HR-758).

``ComputerUseGuard`` asks the local connection's /hook face (package
pc.computer, hook tool ``computer``) about each input action a model asks
for: an Anthropic ``computer_*`` tool use (``decide_anthropic``) or an
OpenAI ``computer_call`` (``decide_openai``). Only an allow lets the action
run. Screenshots, waits, cursor positions and zooms read the screen and are
allowed locally, never sent. An action the guard does not know is refused
locally (COMPUTER_ACTION_UNKNOWN), and any failure refuses (fail closed,
HR-200). Every decision is cooperative and PARTIAL: only actions sent
through the guard are decided.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .client import Client, HookResult

__all__ = ["CODE_ACTION_UNKNOWN", "CODE_CANNOT_DECIDE", "ComputerDecision", "ComputerUseGuard"]

CODE_ACTION_UNKNOWN = "COMPUTER_ACTION_UNKNOWN"
CODE_CANNOT_DECIDE = "CANNOT_DECIDE"
# The hook tool of package pc.computer.
_TOOL = "computer"
_CALL = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")

# Actions that only read the screen: allowed locally and never sent.
_LOCAL_ANTHROPIC = frozenset({"screenshot", "wait", "cursor_position", "zoom"})
_LOCAL_OPENAI = frozenset({"screenshot", "wait"})

# Anthropic computer actions → (kind, button).
_ANTHROPIC: dict[str, tuple[str, str]] = {
    "left_click": ("click", "left"),
    "right_click": ("click", "right"),
    "middle_click": ("click", "middle"),
    "double_click": ("double_click", ""),
    "triple_click": ("triple_click", ""),
    "left_click_drag": ("drag", ""),
    "left_mouse_down": ("press", ""),
    "left_mouse_up": ("release", ""),
    "type": ("type", ""),
    "key": ("key", ""),
    "hold_key": ("key", ""),
    "scroll": ("scroll", ""),
    "mouse_move": ("move", ""),
}

# OpenAI computer_call action types → kind.
_OPENAI: dict[str, str] = {
    "click": "click",
    "double_click": "double_click",
    "drag": "drag",
    "keypress": "key",
    "type": "type",
    "scroll": "scroll",
    "move": "move",
}
_OPENAI_BUTTONS = {"left": "left", "right": "right", "wheel": "middle", "middle": "middle", "back": "back", "forward": "forward"}


@dataclass(frozen=True)
class ComputerDecision:
    """What the agent may do with one computer action: only ``allowed`` lets it run."""

    allowed: bool
    held: bool = False
    code: str = ""
    reason: str = ""
    transaction_id: str = ""


def _refused(code: str, reason: str) -> ComputerDecision:
    return ComputerDecision(False, code=code, reason=reason)


def _call_id(raw: Any) -> str:
    return raw if isinstance(raw, str) and _CALL.match(raw) else "pc-" + secrets.token_hex(16)


def _int(v: Any) -> int | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v:
        return None
    return int(v)


def _point(raw: Any) -> tuple[int, int] | None:
    """An [x, y] pair or an {x, y} object."""
    if isinstance(raw, Mapping):
        x, y = _int(raw.get("x")), _int(raw.get("y"))
    elif isinstance(raw, (list, tuple)) and len(raw) == 2:
        x, y = _int(raw[0]), _int(raw[1])
    else:
        return None
    return (x, y) if x is not None and y is not None else None


def _at(out: dict[str, Any], p: tuple[int, int] | None) -> None:
    if p is not None:
        out["x"], out["y"] = p


class ComputerUseGuard:
    """Decides computer actions through ``connection``, a local connection
    whose package is pc.computer. Threads may share one guard."""

    def __init__(self, client: Client, connection: str) -> None:
        if client is None or not connection:
            raise ValueError("PantherClaw: a client and a connection are required")
        self._client, self._connection = client, connection

    def _ask(self, tool_input: dict[str, Any]) -> ComputerDecision:
        try:
            res: HookResult = self._client.hook_call(self._connection, _TOOL, tool_input)
        except Exception as e:  # noqa: BLE001 - any failure refuses (HR-200)
            return _refused(CODE_CANNOT_DECIDE, f"PantherClaw cannot decide: {e}")
        a = res.answer if isinstance(res.answer, Mapping) else {}
        txn = a.get("transaction_id")
        txn = txn if isinstance(txn, str) else ""
        code = a.get("code")
        code = code if isinstance(code, str) else ""
        if res.outcome == "allow":
            return ComputerDecision(True, reason=res.why, transaction_id=txn)
        if res.outcome == "deny":
            return ComputerDecision(False, held=res.held, code=code or "denied", reason=res.why, transaction_id=txn)
        return ComputerDecision(False, code=code or CODE_CANNOT_DECIDE, reason=res.why, transaction_id=txn)

    def decide_anthropic(self, tool_use: Mapping[str, Any]) -> ComputerDecision:
        """Decides an Anthropic computer tool use (``{id, name, input}``)."""
        try:
            if not isinstance(tool_use, Mapping):
                return _refused(CODE_ACTION_UNKNOWN, "a computer tool use is an object")
            name = tool_use.get("name")
            inp = tool_use.get("input")
            if not isinstance(name, str) or not (name == "computer" or name.startswith("computer_")) or not isinstance(inp, Mapping):
                return _refused(CODE_ACTION_UNKNOWN, "PantherClaw decides computer tool uses only")
            action = inp.get("action")
            if isinstance(action, str) and action in _LOCAL_ANTHROPIC:
                return ComputerDecision(True, reason="PantherClaw allows reading the screen locally; nothing was sent.")
            if not isinstance(action, str) or action not in _ANTHROPIC:
                return _refused(CODE_ACTION_UNKNOWN, f"PantherClaw does not know the computer action {action!r}")
            kind, button = _ANTHROPIC[action]
            out: dict[str, Any] = {"kind": kind}
            if button:
                out["button"] = button
            _at(out, _point(inp.get("coordinate")))
            text = inp.get("text")
            if isinstance(text, str) and text:
                # key and hold_key name keys; type types text; a click or a
                # scroll names the modifier keys held.
                out["text" if kind == "type" else "keys"] = text
            out["call"] = _call_id(tool_use.get("id"))
            return self._ask(out)
        except Exception as e:  # noqa: BLE001 - any failure refuses
            return _refused(CODE_CANNOT_DECIDE, f"PantherClaw cannot decide: {e}")

    def decide_openai(self, computer_call: Mapping[str, Any]) -> ComputerDecision:
        """Decides an OpenAI computer_call (``{call_id, action}``)."""
        try:
            if not isinstance(computer_call, Mapping):
                return _refused(CODE_ACTION_UNKNOWN, "a computer call is an object")
            action = computer_call.get("action")
            if not isinstance(action, Mapping):
                return _refused(CODE_ACTION_UNKNOWN, "a computer call carries an action object")
            typ = action.get("type")
            if isinstance(typ, str) and typ in _LOCAL_OPENAI:
                return ComputerDecision(True, reason="PantherClaw allows reading the screen locally; nothing was sent.")
            if not isinstance(typ, str) or typ not in _OPENAI:
                return _refused(CODE_ACTION_UNKNOWN, f"PantherClaw does not know the computer action {typ!r}")
            kind = _OPENAI[typ]
            out: dict[str, Any] = {"kind": kind}
            if kind == "click":
                b = action.get("button")
                if b not in _OPENAI_BUTTONS:
                    return _refused(CODE_ACTION_UNKNOWN, f"PantherClaw does not know the mouse button {b!r}")
                out["button"] = _OPENAI_BUTTONS[b]
            if kind == "drag":
                path = action.get("path")
                _at(out, _point(path[-1]) if isinstance(path, (list, tuple)) and path else None)
            else:
                _at(out, _point(action))
            if kind == "key":
                keys = action.get("keys")
                if not isinstance(keys, (list, tuple)) or not all(isinstance(k, str) for k in keys):
                    return _refused(CODE_ACTION_UNKNOWN, "a keypress names its keys")
                out["keys"] = "+".join(keys)
            if kind == "type":
                text = action.get("text")
                if not isinstance(text, str):
                    return _refused(CODE_ACTION_UNKNOWN, "a type action carries its text")
                out["text"] = text
            out["call"] = _call_id(computer_call.get("call_id"))
            return self._ask(out)
        except Exception as e:  # noqa: BLE001 - any failure refuses
            return _refused(CODE_CANNOT_DECIDE, f"PantherClaw cannot decide: {e}")
