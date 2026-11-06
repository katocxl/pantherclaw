# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""pantherclaw_adk.before_tool_callback (G0 M34 D996; HR-767): a tool runs
only on PantherClaw's allow; a deny, a hold, a target-enforced allow or any
error returns a refusal dict and the tool does not run. ADK itself is not
needed: the callback takes any tool with a name, the arguments dict and the
tool context."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any

from pantherclaw.client import Outbound, Result
from pantherclaw_adk import HELD_TEXT, before_tool_callback

REFUND = {"charge": "ch_1", "amount": "30.00", "currency": "USD", "reason": "duplicate"}


class FakeClient:
    """Answers authorize with scripted Results, in order, and records the calls."""

    def __init__(self, *results: Result | Exception) -> None:
        self.results = list(results)
        self.calls: list[dict[str, Any]] = []

    def authorize(self, connection, tool, tool_input, tool_use_id, action_id, server="", first_hash=""):
        self.calls.append({"connection": connection, "tool": tool, "input": tool_input, "call": tool_use_id,
                           "action": action_id, "server": server, "first_hash": first_hash})
        r = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(r, Exception):
            raise r
        return r


def tool(name: str = "create_refund") -> Any:
    return SimpleNamespace(name=name)


def ctx(call_id: str = "adk-call-1") -> Any:
    return SimpleNamespace(function_call_id=call_id)


class TestHR767ADKCallback(unittest.TestCase):
    def test_an_allow_lets_the_tool_run(self) -> None:
        client = FakeClient(Result("allow", answer={"transaction_id": "t1"}))
        cb = before_tool_callback(client, "payments")
        self.assertIsNone(cb(tool(), dict(REFUND), ctx()))
        c = client.calls[0]
        self.assertEqual((c["connection"], c["tool"], c["server"], c["call"]),
                         ("payments", "mcp__payments__create_refund", "payments", "adk-call-1"))
        self.assertEqual(c["input"], REFUND)

    def test_everything_but_an_allow_refuses(self) -> None:
        enforced = Result("allow", send=Outbound(method="POST", url="https://x", headers={}, body=b""))
        cases = {
            "deny": (Result("deny", "over the grant", {"code": "GRANT_AMOUNT_EXCEEDED", "transaction_id": "t2"}), "GRANT_AMOUNT_EXCEEDED"),
            "deny without a code": (Result("deny", "no"), "denied"),
            "hold": (Result("hold", "held", {"transaction_id": "t3"}), "held"),
            "cannot decide": (Result("cannot_decide", "gateway unreachable"), "cannot_decide"),
            "target enforced": (enforced, "dispatch_required"),
            "observe": (Result("observe"), "cannot_decide"),
            "error": (RuntimeError("boom"), "wrapper_error"),
        }
        for name, (result, code) in cases.items():
            with self.subTest(name):
                got = before_tool_callback(FakeClient(result), "payments")(tool(), dict(REFUND), ctx())
                self.assertIsInstance(got, dict)
                self.assertEqual(got["status"], "refused")
                self.assertEqual(got["code"], code)
        held = before_tool_callback(FakeClient(Result("hold", answer={"transaction_id": "t3"})), "payments")(tool(), dict(REFUND))
        self.assertIn(HELD_TEXT, held["error"])
        self.assertEqual(held["transaction_id"], "t3")

    def test_unreadable_calls_refuse_without_asking(self) -> None:
        client = FakeClient(Result("allow"))
        cb = before_tool_callback(client, "payments")
        for t, args in ((tool(""), {}), (SimpleNamespace(), {}), (tool(), "not a dict"), (tool(), None)):
            got = cb(t, args, ctx())
            self.assertEqual(got["code"], "wrapper_error")
        self.assertEqual(client.calls, [])

    def test_a_held_call_asked_again_is_the_same_action(self) -> None:
        client = FakeClient(Result("hold", answer={"action_hash": "h1"}), Result("allow"))
        cb = before_tool_callback(client, "payments")
        self.assertEqual(cb(tool(), dict(REFUND), ctx("c1"))["code"], "held")
        self.assertIsNone(cb(tool(), dict(REFUND), ctx("c2")))
        first, second = client.calls
        self.assertEqual(first["action"], second["action"])
        self.assertEqual(second["first_hash"], "h1")
        # Once allowed, the held action id is forgotten: a third call is new.
        cb(tool(), dict(REFUND), ctx("c3"))
        self.assertNotEqual(client.calls[2]["action"], first["action"])

    def test_a_bad_call_id_is_replaced(self) -> None:
        client = FakeClient(Result("allow"))
        before_tool_callback(client, "payments")(tool(), {}, ctx("bad id with spaces"))
        self.assertTrue(client.calls[0]["call"].startswith("pc-"))

    def test_a_client_and_connection_are_required(self) -> None:
        for client, conn in ((None, "payments"), (FakeClient(Result("allow")), "")):
            with self.assertRaises(ValueError):
                before_tool_callback(client, conn)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
