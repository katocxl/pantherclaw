# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""HR-758: the computer-use guard asks PantherClaw before every input action."""

from __future__ import annotations

import json
import unittest
from http.server import BaseHTTPRequestHandler
from typing import Any

from pantherclaw.computer_use import CODE_ACTION_UNKNOWN, CODE_CANNOT_DECIDE, ComputerUseGuard
from test_client import RUN, Fake, reply


class _Gateway:
    """A /hook face that records each computer call and answers ``answer``."""

    def __init__(self, answer: dict[str, Any] | None = None, status: int = 200) -> None:
        self.answer = answer if answer is not None else {"decision": "allow", "transaction_id": "t-1", "reason": "ok"}
        self.status = status
        self.seen: list[dict[str, Any]] = []
        self.fake = Fake(lambda h, _b: reply(h, 404, b""), hook=self._hook)

    def _hook(self, h: BaseHTTPRequestHandler, body: bytes) -> None:
        self.seen.append({"path": h.path, "run": h.headers.get("PAP-Run-Id"), "body": json.loads(body)})
        reply(h, self.status, json.dumps(self.answer).encode())

    def guard(self) -> ComputerUseGuard:
        return ComputerUseGuard(self.fake.client, "desktop")

    def inputs(self) -> list[dict[str, Any]]:
        return [s["body"]["input"] for s in self.seen]

    def close(self) -> None:
        self.fake.close()


class _Raises:
    def hook_call(self, *_a: Any) -> Any:
        raise RuntimeError("boom")


class ComputerUseTest(unittest.TestCase):
    def test_HR758_anthropic_input_actions_are_asked_with_their_mapping(self) -> None:
        g = _Gateway()
        try:
            cases = [
                ({"action": "left_click", "coordinate": [10, 20]}, {"kind": "click", "button": "left", "x": 10, "y": 20}),
                ({"action": "right_click", "coordinate": [1, 2]}, {"kind": "click", "button": "right", "x": 1, "y": 2}),
                ({"action": "middle_click"}, {"kind": "click", "button": "middle"}),
                ({"action": "double_click"}, {"kind": "double_click"}),
                ({"action": "triple_click"}, {"kind": "triple_click"}),
                ({"action": "left_click_drag", "coordinate": [5, 6]}, {"kind": "drag", "x": 5, "y": 6}),
                ({"action": "left_mouse_down"}, {"kind": "press"}),
                ({"action": "left_mouse_up"}, {"kind": "release"}),
                ({"action": "type", "text": "hello"}, {"kind": "type", "text": "hello"}),
                ({"action": "key", "text": "ctrl+s"}, {"kind": "key", "keys": "ctrl+s"}),
                ({"action": "hold_key", "text": "shift"}, {"kind": "key", "keys": "shift"}),
                ({"action": "scroll", "coordinate": [3, 4], "text": "ctrl"}, {"kind": "scroll", "x": 3, "y": 4, "keys": "ctrl"}),
                ({"action": "mouse_move", "coordinate": [7, 8]}, {"kind": "move", "x": 7, "y": 8}),
            ]
            for inp, want in cases:
                d = g.guard().decide_anthropic({"id": "toolu_01", "name": "computer", "input": inp})
                self.assertTrue(d.allowed, inp)
                self.assertEqual(d.transaction_id, "t-1")
                self.assertEqual(g.inputs()[-1], {**want, "call": "toolu_01"}, inp)
            self.assertEqual(len(g.seen), len(cases))
            self.assertEqual({(s["path"], s["run"], s["body"]["tool"]) for s in g.seen}, {("/hook/desktop", RUN, "computer")})
        finally:
            g.close()

    def test_HR758_openai_input_actions_are_asked_with_their_mapping(self) -> None:
        g = _Gateway()
        try:
            cases = [
                ({"type": "click", "button": "left", "x": 1, "y": 2}, {"kind": "click", "button": "left", "x": 1, "y": 2}),
                ({"type": "click", "button": "wheel", "x": 1, "y": 2}, {"kind": "click", "button": "middle", "x": 1, "y": 2}),
                ({"type": "double_click", "x": 3, "y": 4}, {"kind": "double_click", "x": 3, "y": 4}),
                ({"type": "drag", "path": [{"x": 0, "y": 0}, {"x": 9, "y": 9}]}, {"kind": "drag", "x": 9, "y": 9}),
                ({"type": "keypress", "keys": ["CTRL", "S"]}, {"kind": "key", "keys": "CTRL+S"}),
                ({"type": "type", "text": "hi"}, {"kind": "type", "text": "hi"}),
                ({"type": "scroll", "x": 5, "y": 6, "scroll_x": 0, "scroll_y": 3}, {"kind": "scroll", "x": 5, "y": 6}),
                ({"type": "move", "x": 7, "y": 8}, {"kind": "move", "x": 7, "y": 8}),
            ]
            for action, want in cases:
                d = g.guard().decide_openai({"call_id": "call_1", "action": action})
                self.assertTrue(d.allowed, action)
                self.assertEqual(g.inputs()[-1], {**want, "call": "call_1"}, action)
        finally:
            g.close()

    def test_HR758_reading_the_screen_is_allowed_locally_and_never_sent(self) -> None:
        g = _Gateway({"decision": "deny", "reason": "no"})
        try:
            for action in ("screenshot", "wait", "cursor_position", "zoom"):
                self.assertTrue(g.guard().decide_anthropic({"id": "t", "name": "computer_20250124", "input": {"action": action}}).allowed)
            for typ in ("screenshot", "wait"):
                self.assertTrue(g.guard().decide_openai({"call_id": "c", "action": {"type": typ}}).allowed)
            self.assertEqual(g.seen, [])
        finally:
            g.close()

    def test_HR758_a_deny_or_a_hold_refuses_and_an_unknown_action_is_refused_locally(self) -> None:
        g = _Gateway({"decision": "deny", "held": True, "code": "APPROVAL_REQUIRED", "reason": "held", "transaction_id": "t-2"})
        try:
            d = g.guard().decide_anthropic({"id": "toolu_02", "name": "computer", "input": {"action": "left_click", "coordinate": [1, 1]}})
            self.assertEqual((d.allowed, d.held, d.code, d.transaction_id), (False, True, "APPROVAL_REQUIRED", "t-2"))
            g.answer = {"decision": "deny", "reason": "no"}
            d = g.guard().decide_openai({"call_id": "c", "action": {"type": "type", "text": "x"}})
            self.assertEqual((d.allowed, d.held), (False, False))
            asked = len(g.seen)
            for tool_use in (
                {"id": "t", "name": "computer", "input": {"action": "teleport"}},
                {"id": "t", "name": "bash", "input": {"action": "left_click"}},
                "not an object",
            ):
                d = g.guard().decide_anthropic(tool_use)  # type: ignore[arg-type]
                self.assertEqual((d.allowed, d.code), (False, CODE_ACTION_UNKNOWN), tool_use)
            for call in (
                {"call_id": "c", "action": {"type": "teleport"}},
                {"call_id": "c", "action": {"type": "click", "button": "thumb"}},
                {"call_id": "c", "action": {"type": "keypress", "keys": "ctrl"}},
                {"call_id": "c"},
            ):
                d = g.guard().decide_openai(call)
                self.assertEqual((d.allowed, d.code), (False, CODE_ACTION_UNKNOWN), call)
            self.assertEqual(len(g.seen), asked)
        finally:
            g.close()

    def test_HR758_any_error_refuses(self) -> None:
        d = ComputerUseGuard(_Raises(), "desktop").decide_anthropic({"id": "t", "name": "computer", "input": {"action": "type", "text": "x"}})  # type: ignore[arg-type]
        self.assertEqual((d.allowed, d.code), (False, CODE_CANNOT_DECIDE))
        g = _Gateway(status=502)
        try:
            d = g.guard().decide_openai({"call_id": "c", "action": {"type": "move", "x": 1, "y": 1}})
            self.assertEqual((d.allowed, d.code), (False, CODE_CANNOT_DECIDE))
        finally:
            g.close()
        g = _Gateway({"decision": "maybe"})
        try:
            self.assertFalse(g.guard().decide_openai({"call_id": "c", "action": {"type": "move", "x": 1, "y": 1}}).allowed)
        finally:
            g.close()
        with self.assertRaises(ValueError):
            ComputerUseGuard(None, "desktop")  # type: ignore[arg-type]

    def test_HR758_a_call_id_that_is_not_one_gets_a_stable_call(self) -> None:
        g = _Gateway()
        try:
            for _ in range(2):
                g.guard().decide_anthropic({"id": "bad id!", "name": "computer", "input": {"action": "double_click"}})
            a, b = (i["call"] for i in g.inputs())
            self.assertTrue(a.startswith("pc-") and len(a) == 35, a)
            self.assertEqual(a, b)
            g.guard().decide_anthropic({"id": "other id!", "name": "computer", "input": {"action": "double_click"}})
            self.assertNotEqual(g.inputs()[-1]["call"], a)
            # Only a missing id gets a random call.
            g.guard().decide_openai({"action": {"type": "move", "x": 1, "y": 1}})
            g.guard().decide_openai({"action": {"type": "move", "x": 1, "y": 1}})
            c, d = (i["call"] for i in g.inputs()[-2:])
            self.assertTrue(c.startswith("pc-") and c != d, (c, d))
        finally:
            g.close()

    def test_HR758_a_held_action_asked_again_with_the_same_id_is_the_same_call(self) -> None:
        g = _Gateway({"decision": "deny", "held": True, "code": "APPROVAL_REQUIRED", "reason": "held", "transaction_id": "t-2"})
        try:
            for _ in range(2):
                self.assertTrue(g.guard().decide_openai({"call_id": "call_9", "action": {"type": "type", "text": "x"}}).held)
                self.assertTrue(g.guard().decide_anthropic({"id": "toolu_9", "name": "computer", "input": {"action": "key", "text": "Return"}}).held)
            self.assertEqual([i["call"] for i in g.inputs()], ["call_9", "toolu_9", "call_9", "toolu_9"])
        finally:
            g.close()

    def test_HR758_a_bedrock_tool_use_is_decided_with_its_tool_use_id(self) -> None:
        g = _Gateway()
        try:
            inp = {"action": "left_click", "coordinate": [3, 4]}
            for tu in (
                {"toolUseId": "tooluse_ab12", "name": "computer", "input": inp},
                {"toolUse": {"toolUseId": "tooluse_ab12", "name": "computer", "input": inp}},
            ):
                self.assertTrue(g.guard().decide_anthropic(tu).allowed)
            for got in g.inputs():
                self.assertEqual(got, {"kind": "click", "button": "left", "x": 3, "y": 4, "call": "tooluse_ab12"})
            d = g.guard().decide_anthropic({"toolUse": {"toolUseId": "t", "name": "bash", "input": inp}})
            self.assertEqual((d.allowed, d.code), (False, CODE_ACTION_UNKNOWN))
            self.assertEqual(len(g.inputs()), 2)
        finally:
            g.close()


if __name__ == "__main__":
    unittest.main()
