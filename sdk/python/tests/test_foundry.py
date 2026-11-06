# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""FoundryApprovals (G0 M34 D996; HR-767): only PantherClaw's allow approves
an Azure AI Foundry MCP approval request; everything else answers approve
false."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from typing import Any

from pantherclaw.client import Outbound, Result
from pantherclaw.foundry import FoundryApprovals


class FakeClient:
    """Answers authorize with a scripted Result and records the calls."""

    def __init__(self, result: Result | Exception) -> None:
        self.result = result
        self.calls: list[tuple[Any, ...]] = []

    def authorize(self, connection, tool, tool_input, tool_use_id, action_id, server="", first_hash=""):
        self.calls.append((connection, tool, tool_input, tool_use_id, action_id, server))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def request(**over: Any) -> dict[str, Any]:
    item = {"type": "mcp_approval_request", "id": "mcpr_1", "server_label": "payments", "name": "create_refund",
            "arguments": '{"charge":"ch_1","amount":"30.00","currency":"USD","reason":"duplicate"}'}
    item.update(over)
    return item


class TestHR767FoundryApprovals(unittest.TestCase):
    def test_HR767_an_allow_approves(self) -> None:
        client = FakeClient(Result("allow", answer={"transaction_id": "t1"}))
        got = FoundryApprovals(client, {"payments": "payments-conn"}).answer(request())
        self.assertEqual(got, {"type": "mcp_approval_response", "approval_request_id": "mcpr_1", "approve": True})
        conn, tool, args, call_id, _, server = client.calls[0]
        self.assertEqual((conn, tool, server, call_id), ("payments-conn", "mcp__payments-conn__create_refund", "payments-conn", "mcpr_1"))
        self.assertEqual(args["charge"], "ch_1")

    def test_an_sdk_object_and_object_arguments_are_read(self) -> None:
        client = FakeClient(Result("allow"))
        item = SimpleNamespace(id="mcpr_2", server_label="payments", name="get_refund", arguments={"refund": "re_1"})
        self.assertTrue(FoundryApprovals(client, {"payments": "c"}).answer(item)["approve"])

    def test_HR767_everything_but_an_allow_refuses(self) -> None:
        cases = {
            "deny": (Result("deny", "GRANT_AMOUNT_EXCEEDED"), request()),
            "hold": (Result("hold", "held"), request()),
            "cannot decide": (Result("cannot_decide", "gateway down"), request()),
            "target enforced": (Result("allow", send=Outbound(method="POST", url="https://x", headers={}, body=b"")), request()),
            "error": (RuntimeError("boom"), request()),
            "unknown label": (Result("allow"), request(server_label="other")),
            "bad arguments": (Result("allow"), request(arguments="{not json")),
            "list arguments": (Result("allow"), request(arguments="[1,2]")),
            "no name": (Result("allow"), request(name="")),
            "no id": (Result("allow"), request(id="")),
        }
        for name, (result, item) in cases.items():
            with self.subTest(name):
                got = FoundryApprovals(FakeClient(result), {"payments": "payments-conn"}).answer(item)
                self.assertIs(got["approve"], False)
                self.assertEqual(got["type"], "mcp_approval_response")

    def test_unknown_labels_never_reach_pantherclaw(self) -> None:
        client = FakeClient(Result("allow"))
        FoundryApprovals(client, {"payments": "c"}).answer(request(server_label="other"))
        self.assertEqual(client.calls, [])

    def test_HR767_unreadable_sdk_object_refuses(self) -> None:
        class BrokenRequest:
            id = "mcpr_broken"

            @property
            def server_label(self) -> str:
                raise RuntimeError("unreadable")

        client = FakeClient(Result("allow"))
        got = FoundryApprovals(client, {"payments": "c"}).answer(BrokenRequest())
        self.assertEqual(got, {"type": "mcp_approval_response", "approval_request_id": "mcpr_broken", "approve": False})
        self.assertEqual(client.calls, [])

    def test_required_action_approvals(self) -> None:
        run = {"required_action": {"type": "submit_tool_approval", "submit_tool_approval": {"tool_calls": [
            {"id": "call_1", "server_label": "payments", "name": "create_refund", "arguments": "{}"},
            {"id": "call_2", "server_label": "other", "name": "create_refund", "arguments": "{}"},
            {"server_label": "payments", "name": "x"},
        ]}}}
        got = FoundryApprovals(FakeClient(Result("allow")), {"payments": "c"}).answer_required_action(run)
        self.assertEqual(got, [{"tool_call_id": "call_1", "approve": True}, {"tool_call_id": "call_2", "approve": False}])
        denied = FoundryApprovals(FakeClient(Result("deny")), {"payments": "c"}).answer_required_action(run)
        self.assertEqual([a["approve"] for a in denied], [False, False])
        self.assertEqual(FoundryApprovals(FakeClient(Result("allow")), {"payments": "c"}).answer_required_action({"required_action": {"type": "submit_tool_outputs"}}), [])
        self.assertEqual(FoundryApprovals(FakeClient(Result("allow")), {"payments": "c"}).answer_required_action(object()), [])

    def test_a_client_is_required(self) -> None:
        with self.assertRaises(ValueError):
            FoundryApprovals(None, {"payments": "c"})  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
