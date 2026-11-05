# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Azure AI Foundry MCP tool approvals answered by PantherClaw (G0 M34 D996;
HR-767).

An MCP tool with ``require_approval`` makes Foundry stop before each call
and hand the client app an approval request. ``FoundryApprovals`` answers
those requests: it asks the gateway's /sdk face (through
``Client.authorize``) of the connection mapped to the request's
``server_label``, as the MCP tool ``mcp__<connection>__<name>`` of the server
named after the connection, and approves only on PantherClaw's allow.

``answer`` takes a Responses API ``mcp_approval_request`` item;
``answer_required_action`` takes a classic Agents run whose required action
is ``submit_tool_approval``. A deny, a hold, an unknown server label, or any
failure answers approve false (fail closed). Every decision is cooperative
and PARTIAL: the client app sends the answer, and an app that does not ask
is not asked about (R-84). The API shapes are unconfirmed until live checks
(R-85).
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Mapping
from typing import Any

from .client import Client, new_action_id

__all__ = ["FoundryApprovals"]

_CALL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")


def _get(obj: Any, name: str) -> Any:
    """A member of a dict or an attribute of an SDK object."""
    if isinstance(obj, Mapping):
        return obj.get(name)
    return getattr(obj, name, None)


def _arguments(raw: Any) -> dict[str, Any] | None:
    """The call's arguments: a JSON object, or a string holding one."""
    if isinstance(raw, Mapping):
        return dict(raw)
    if raw is None or raw == "":
        return {}
    if isinstance(raw, str):
        try:
            got = json.loads(raw)
        except ValueError:
            return None
        return got if isinstance(got, dict) else None
    return None


class FoundryApprovals:
    """Answers Foundry MCP approval requests. ``connections`` maps each MCP
    tool's ``server_label`` to the PantherClaw connection whose package maps
    its tools (an ``mcp`` connection with access mode ``agent_held``). One
    instance can be shared between threads."""

    def __init__(self, client: Client, connections: Mapping[str, str]) -> None:
        if client is None or not isinstance(connections, Mapping):
            raise ValueError("PantherClaw: a client and the connections by server label are required")
        self._client = client
        self._connections = {k: v for k, v in connections.items() if isinstance(k, str) and isinstance(v, str) and v}

    def _approve(self, call_id: Any, server_label: Any, name: Any, arguments: Any) -> bool:
        """Only PantherClaw's allow approves; everything else does not."""
        try:
            if not isinstance(server_label, str) or server_label not in self._connections:
                return False
            connection = self._connections[server_label]
            args = _arguments(arguments)
            if not isinstance(name, str) or not name or args is None:
                return False
            use_id = call_id if isinstance(call_id, str) and _CALL_ID.match(call_id) else "pc-" + secrets.token_hex(16)
            res = self._client.authorize(connection, f"mcp__{connection}__{name}", args, use_id, new_action_id(),
                                         server=connection)
            # An allow carrying PantherClaw's own request (target-enforced) is
            # not approved: Foundry would send its own request instead.
            return res.outcome == "allow" and res.send is None
        except Exception:  # noqa: BLE001 - any failure does not approve (HR-767)
            return False

    def answer(self, item: Any) -> dict[str, Any]:
        """The ``mcp_approval_response`` for one ``mcp_approval_request``
        item ``{id, server_label, name, arguments}``."""
        rid = _get(item, "id")
        rid = rid if isinstance(rid, str) else ""
        approve = bool(rid) and self._approve(rid, _get(item, "server_label"), _get(item, "name"), _get(item, "arguments"))
        return {"type": "mcp_approval_response", "approval_request_id": rid, "approve": approve}

    def answer_required_action(self, run: Any) -> list[dict[str, Any]]:
        """The tool approvals to submit for a classic Agents run whose
        required action is ``submit_tool_approval``: one
        ``{tool_call_id, approve}`` per tool call. Any other run gets none."""
        try:
            action = _get(run, "required_action")
            if _get(action, "type") != "submit_tool_approval":
                return []
            calls = _get(_get(action, "submit_tool_approval"), "tool_calls")
            if not isinstance(calls, (list, tuple)):
                return []
            out: list[dict[str, Any]] = []
            for call in calls:
                cid = _get(call, "id")
                if not isinstance(cid, str) or not cid:
                    continue
                approve = self._approve(cid, _get(call, "server_label"), _get(call, "name"), _get(call, "arguments"))
                out.append({"tool_call_id": cid, "approve": approve})
            return out
        except Exception:  # noqa: BLE001 - a run it cannot read gets no approvals
            return []
