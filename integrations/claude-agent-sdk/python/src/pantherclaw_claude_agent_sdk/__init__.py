# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClaw for the Claude Agent SDK (G0 M8 decision 2, HR-200).

A PreToolUse hook sends every tool call to the gateway's /sdk face before it
runs, in every permission mode, and denies when PantherClaw cannot decide. A
can_use_tool callback only turns a PantherClaw hold into a wait. Every
decision is cooperative and labeled PARTIAL: the agent runs the tool with its
own access (HR-024, HR-186).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from pantherclaw.client import Client, Result, new_action_id

__all__ = ["BUILTIN_TOOLS", "PantherClaw"]

BUILTIN_TOOLS: tuple[str, ...] = (
    "Agent", "AskUserQuestion", "Bash", "CronCreate", "CronDelete", "CronList", "Edit", "EnterPlanMode", "EnterWorktree",
    "ExitPlanMode", "ExitWorktree", "Glob", "Grep", "ListMcpResourcesTool", "LSP", "Monitor", "NotebookEdit", "PowerShell", "Read",
    "ReadMcpResourceTool", "Skill", "Task", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TaskUpdate", "TodoWrite",
    "ToolSearch", "WaitForMcpServers", "WebFetch", "WebSearch", "Write",
)  # fmt: skip
_SHELLS = {"Bash", "PowerShell"}
_NO_ASK_MODES = {"bypassPermissions", "dontAsk"}


def _types() -> tuple[Any, Any, Any]:
    """The Agent SDK's HookMatcher and permission results, or stand-ins with
    the same fields when the SDK is not installed (tests)."""
    try:
        from claude_agent_sdk import HookMatcher, PermissionResultAllow, PermissionResultDeny

        return HookMatcher, PermissionResultAllow, PermissionResultDeny
    except ImportError:
        pass

    @dataclass
    class _HookMatcher:
        matcher: str | None = None
        hooks: list[Any] = field(default_factory=list)
        timeout: float | None = None

    @dataclass
    class _Allow:
        behavior: str = "allow"
        updated_input: dict[str, Any] | None = None
        updated_permissions: list[Any] | None = None

    @dataclass
    class _Deny:
        behavior: str = "deny"
        message: str = ""
        interrupt: bool = False

    return _HookMatcher, _Allow, _Deny


HookMatcher, PermissionResultAllow, PermissionResultDeny = _types()


def _decision(kind: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": kind,
            "permissionDecisionReason": f"{reason} (PantherClaw, PARTIAL)",
        }
    }


@dataclass
class _Held:
    tool: str
    tool_input: dict[str, Any]
    tool_use_id: str
    server: str
    cwd: str
    action_id: str
    answer: dict[str, Any]
    key: str


class PantherClaw:
    """The PantherClaw integration; ``options(...)`` adds its hook and
    can_use_tool to the application's ClaudeAgentOptions arguments."""

    def __init__(
        self,
        client: Client,
        connection: str,
        mcp_servers: Sequence[str] = (),
        gateway_mcp_servers: Sequence[str] = (),
        builtin_tools: Sequence[str] = BUILTIN_TOOLS,
        observe_unmapped: bool = False,
        deadline: float = 10.0,
        wait: float = 300.0,
    ) -> None:
        if client is None or not connection:
            raise ValueError("PantherClaw: a client and a connection are required")
        self._client, self._connection = client, connection
        self._servers = list(mcp_servers)
        self._gateway_servers = set(gateway_mcp_servers)
        self._builtins = set(builtin_tools)
        self._observe_unmapped = observe_unmapped
        self._deadline, self._wait = deadline, wait
        self._mode = ""
        self._allowed: list[str] = []
        self._app_can_use_tool: Callable[..., Awaitable[Any]] | None = None
        self._can_use_tool_installed = False
        self._held: dict[str, _Held] = {}
        self._retries: dict[str, str] = {}

    def options(self, **app: Any) -> dict[str, Any]:
        """Returns the keyword arguments for ClaudeAgentOptions with
        PantherClaw added. ``permission_mode`` must be passed explicitly.
        can_use_tool needs a streaming prompt (an async iterable): pass one
        to query() or ClaudeSDKClient; PantherClaw's PreToolUse hook keeps the
        stream open, as the SDK's documented workaround requires."""
        if not app.get("permission_mode"):
            raise ValueError("PantherClaw: pass permission_mode explicitly")
        self._mode = app["permission_mode"]
        self._allowed = list(app.get("allowed_tools") or [])
        self._app_can_use_tool = app.get("can_use_tool")
        self._servers = list(dict.fromkeys([*self._servers, *(app.get("mcp_servers") or {})]))
        hooks = dict(app.get("hooks") or {})
        hooks["PreToolUse"] = [*hooks.get("PreToolUse", []), HookMatcher(hooks=[self.hook], timeout=self._deadline + 5)]
        return {**app, "hooks": hooks, "can_use_tool": self.can_use_tool()}

    def _route(self, tool: str, data: dict[str, Any]) -> tuple[str, str]:
        """("call", server), ("skip", "") or ("refuse", why)."""
        if tool.startswith("mcp__"):
            rest = tool[5:]
            server = next((s for s in sorted(self._servers, key=len, reverse=True) if rest.startswith(s + "__")), "")
            if not server or len(rest) <= len(server) + 2:
                return "refuse", f"the MCP server of {tool} is not configured"
            return ("skip", "") if server in self._gateway_servers else ("call", server)
        if tool in _SHELLS and not data.get("cwd"):
            return "refuse", f"{tool} without a working directory"
        return "call", ""

    async def hook(self, input_data: dict[str, Any], tool_use_id: str | None = None, context: Any = None) -> dict[str, Any]:
        """The PreToolUse hook (no matcher: every tool). It never raises: any
        failure denies (HR-200)."""
        try:
            return await self._decide(input_data, tool_use_id)
        except Exception as e:  # noqa: BLE001 - any failure denies
            return _decision("deny", f"PantherClaw cannot decide this call: {e or type(e).__name__}")

    async def _decide(self, data: dict[str, Any], tool_use_id: str | None) -> dict[str, Any]:
        tool, args = data.get("tool_name", ""), data.get("tool_input")
        if not isinstance(args, dict):
            return _decision("deny", "the tool input is not an object")
        kind, detail = self._route(tool, data)
        if kind == "skip":
            return {}
        if kind == "refuse":
            return _decision("deny", f"PantherClaw cannot decide this call: {detail}")
        server, cwd = detail, data.get("cwd", "") if tool in _SHELLS else ""
        use_id = data.get("tool_use_id") or tool_use_id or new_action_id()
        key = json.dumps([tool, server, cwd, args], sort_keys=True)
        action_id = self._retries.get(key) or new_action_id()
        res = await asyncio.wait_for(
            asyncio.to_thread(self._client.authorize, self._connection, tool, args, use_id, action_id, server=server, cwd=cwd), self._deadline
        )
        return self._answer(res, data, _Held(tool, args, use_id, server, cwd, action_id, res.answer, key))

    def _answer(self, res: Result, data: dict[str, Any], h: _Held) -> dict[str, Any]:
        builtin = h.tool in self._builtins
        if res.outcome == "allow":
            self._retries.pop(h.key, None)
            return _decision("allow", "PantherClaw allowed this call")
        if res.outcome == "observe":
            # An unmapped built-in is recorded, not decided: the application's own permissions apply.
            return {} if builtin else _decision("deny", "PantherClaw does not map this tool")
        if res.outcome == "hold":
            self._retries[h.key] = h.action_id
            handle = res.answer["wait"]["handle"]
            mode = data.get("permission_mode") or self._mode
            allowed = any(r == h.tool or r.startswith(h.tool + "(") for r in self._allowed)
            if self._can_use_tool_installed and mode not in _NO_ASK_MODES and not allowed:
                self._held[h.tool_use_id] = h
                return _decision("ask", f"PantherClaw holds this call for an approval (transaction {handle})")
            return _decision(
                "deny",
                f"PantherClaw holds this call for an approval by an eligible person (transaction {handle}); "
                "once it is approved, make the same call again",
            )
        if res.answer.get("code") == "unknown_tool" and self._observe_unmapped and not builtin:
            return {}
        return _decision("deny", res.why or "PantherClaw denied this call")

    def can_use_tool(self) -> Callable[[str, dict[str, Any], Any], Awaitable[Any]]:
        """The can_use_tool callback. It handles only calls PantherClaw holds:
        it waits on the hold within its own deadline, resubmits the identical
        call and allows only on PantherClaw's allow, with the original input.
        Every other call goes to the application's own callback, or is denied
        when there is none (never asking the local user for a PantherClaw hold)."""
        self._can_use_tool_installed = True

        async def callback(tool_name: str, tool_input: dict[str, Any], context: Any) -> Any:
            use_id = getattr(context, "tool_use_id", None)
            h = self._held.pop(use_id, None) if use_id else None
            if h is None or h.tool != tool_name:
                if h is not None:
                    self._held[use_id] = h
                if self._app_can_use_tool is not None:
                    return await self._app_can_use_tool(tool_name, tool_input, context)
                return PermissionResultDeny(message="no permission handler for this call")
            try:
                res = await asyncio.wait_for(asyncio.to_thread(self._resume, h), self._wait)
            except Exception as e:  # noqa: BLE001 - any failure while waiting denies
                return PermissionResultDeny(message=f"the wait for PantherClaw's decision ended: {e or type(e).__name__}")
            if res.outcome != "allow":
                return PermissionResultDeny(message=f"{res.why or 'PantherClaw did not allow this call'} (PantherClaw, PARTIAL)")
            self._retries.pop(h.key, None)
            return PermissionResultAllow(updated_input=h.tool_input)

        return callback

    def _resume(self, h: _Held) -> Result:
        return self._client.resume(
            self._connection, h.tool, h.tool_input, h.tool_use_id, h.action_id, Result("hold", "", h.answer), server=h.server, cwd=h.cwd,
            deadline=self._wait,
        )
