# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClaw for the Claude Agent SDK (G0 M8 decision 2 and design
decision 8, HR-200).

A PreToolUse hook sorts every tool call into three classes before it runs,
in every permission mode, and denies when PantherClaw cannot decide: tools of
MCP servers served by the gateway's /mcp face pass (the gateway enforces
them); Bash, PowerShell and Monitor, every tool that runs shell commands, go
to the local connection's /hook face (pc.shell, HR-186); an MCP tool goes to
the /sdk face of the connection named after its server, and a built-in to
the /sdk face of the connection that records it. A can_use_tool callback
only turns a PantherClaw hold into a wait. Every decision is cooperative and
labeled PARTIAL: the agent runs the tool with its own access (HR-024,
HR-186).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from pantherclaw import pap
from pantherclaw.client import Client, Outbound, Result, new_action_id

__all__ = ["ASK_MODES", "BUILTIN_TOOLS", "UNDECIDED_TOOLS", "PantherClaw", "rule_names"]

# The Agent SDK's built-in tools that PantherClaw records OBSERVE_ONLY and
# lets run under the application's own permissions: exactly the face's list,
# sdk_face.json's "builtins".
BUILTIN_TOOLS: tuple[str, ...] = (
    "Agent", "AskUserQuestion", "Bash", "CronCreate", "CronDelete", "CronList", "Edit", "EnterPlanMode", "EnterWorktree",
    "ExitPlanMode", "ExitWorktree", "Glob", "Grep", "ListMcpResourcesTool", "LSP", "Monitor", "NotebookEdit", "PowerShell", "Read",
    "ReadMcpResourceTool", "Skill", "Task", "TaskCreate", "TaskGet", "TaskList", "TaskOutput", "TaskStop", "TaskUpdate", "TodoWrite",
    "ToolSearch", "WaitForMcpServers", "WebFetch", "WebSearch", "Write",
)  # fmt: skip
# Built-in tools of the supported Agent SDK that are not on BUILTIN_TOOLS:
# PantherClaw can neither decide nor record them, so options() disallows them
# and the model is never offered them (a call would be denied).
UNDECIDED_TOOLS: tuple[str, ...] = ("ListAgents", "ReadMcpResourceDirTool", "ReportFindings", "ScheduleWakeup", "SendMessage", "Workflow")
# The tools that run shell commands (HR-186), and the shell /hook decides
# each one's command in.
_SHELLS = {"Bash": "bash", "PowerShell": "powershell", "Monitor": "bash"}
# The rule for a connection's name (migration 00041): a governed MCP server
# is named after its connection.
_CONNECTION_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
# The permission modes in which a hold is asked: those where the SDK
# documents, and the pinned tests prove, that can_use_tool is called after a
# hook's "ask" (HR-200). In every other mode a hold is denied.
ASK_MODES: tuple[str, ...] = ("default",)
# How many held calls wait for can_use_tool at once; beyond it a hold is
# denied, never asked.
_MAX_HELD = 256
# How many asked tool_use_ids are remembered, so that can_use_tool never
# hands one to the application.
_MAX_ASKED = 10_000
_CALL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")


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


def rule_names(rule: str, tool: str, server: str = "") -> bool:
    """Whether an allow rule names a tool: the tool itself (with any
    specifier), its MCP server, or a wildcard that matches it."""
    base = rule.split("(", 1)[0].strip()
    if base in ("*", tool):
        return True
    if server and base in (f"mcp__{server}", f"mcp__{server}__*"):
        return True
    if "*" not in base:
        return False
    return re.fullmatch(".*".join(re.escape(p) for p in base.split("*")), tool) is not None


def _call_id(use_id: Any) -> str:
    """The SDK's id of a call, or a fresh one when it is missing or one the faces refuse."""
    return use_id if isinstance(use_id, str) and _CALL_ID.match(use_id) else "pc-" + secrets.token_hex(16)


@dataclass
class _Held:
    tool: str
    tool_input: dict[str, Any]
    tool_use_id: str
    server: str
    action_id: str
    answer: dict[str, Any]
    key: str
    expires: float = 0.0


def _refuse_ungoverned_shells(app: Mapping[str, Any]) -> None:
    """With a governed shell, refuses what could run a shell command past the
    PreToolUse hook (HR-200; founder decision 2026-10-13: no skills while the shell is
    governed). A skill's ``!`` lines run when it loads, never through the
    hook, and its ``allowed-tools`` frontmatter pre-approves them in every
    permission mode, so no skill may load: no user or project settings (an
    omitted setting_sources loads them all), no ``skills``, no ``plugins``.
    Tool aliases rename a call before it is resolved, so they are refused
    too."""
    why = "a skill's `!` lines run past PreToolUse, and its allowed-tools pre-approves them"
    sources = app.get("setting_sources")
    if sources is None or any(s in ("user", "project") for s in sources):
        raise ValueError(f'PantherClaw: with a governed shell, pass setting_sources without "user" and "project" ({why})')
    if app.get("skills") is not None and app.get("skills") != []:
        raise ValueError(f"PantherClaw: with a governed shell, skills cannot be enabled ({why})")
    if app.get("plugins"):
        raise ValueError(f"PantherClaw: with a governed shell, plugins cannot be loaded (they bring skills: {why})")
    if app.get("tool_aliases"):
        raise ValueError("PantherClaw: with a governed shell, tool_aliases cannot be set (an alias renames a call before PantherClaw sees it)")


class PantherClaw:
    """The PantherClaw integration; ``options(...)`` adds its hook and
    can_use_tool to the application's ClaudeAgentOptions arguments.

    ``connection`` is the http or mcp connection whose /sdk face records
    the built-in tools' calls. An MCP tool's call goes to the connection
    named after its server, the one connection that governs it: name each
    governed MCP server after its connection. ``shell_connection`` is the
    local connection whose /hook face decides every shell command, Bash's,
    PowerShell's and Monitor's (pc.shell, HR-186); without one the
    integration refuses to start unless ``shell="observe"``, which only
    records shell calls (OBSERVE_ONLY) under the application's own
    permissions. The client must
    know the built-ins (``Client(builtins=BUILTIN_TOOLS)``; from_key_file
    does), and its timeout should not exceed ``deadline``."""

    def __init__(
        self,
        client: Client,
        connection: str,
        shell_connection: str = "",
        shell: str = "",
        mcp_servers: Sequence[str] = (),
        gateway_mcp_servers: Sequence[str] = (),
        builtin_tools: Sequence[str] = BUILTIN_TOOLS,
        observe_unmapped: bool = False,
        on_dispatch: Callable[[str, Outbound], None] | None = None,
        deadline: float = 10.0,
        wait: float = 300.0,
    ) -> None:
        if client is None or not connection:
            raise ValueError("PantherClaw: a client and a connection are required")
        if not shell_connection and shell != "observe":
            raise ValueError(
                "PantherClaw: shell commands (Bash, PowerShell, Monitor) are decided through a local connection's /hook face: "
                'set shell_connection, or shell="observe" to only record them'
            )
        missing = [t for t in builtin_tools if t not in client.builtins]
        if missing:
            raise ValueError(f"PantherClaw: build the client with builtins=BUILTIN_TOOLS (it does not know {', '.join(missing)})")
        self._client, self._connection, self._shell_connection = client, connection, shell_connection
        self._servers = list(mcp_servers)
        self._gateway_servers = list(gateway_mcp_servers)
        self._trusted: set[str] = set()
        self._builtins = set(builtin_tools)
        self._observe_unmapped = observe_unmapped
        self._on_dispatch = on_dispatch
        self._deadline, self._wait = deadline, wait
        self._mode = ""
        self._allowed: list[str] = []
        self._settings_loaded = False
        self._app_can_use_tool: Callable[..., Awaitable[Any]] | None = None
        self._can_use_tool_installed = False
        self._held: dict[str, _Held] = {}
        self._asked: OrderedDict[str, None] = OrderedDict()
        self._retries: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        # PantherClaw's own bounded threads, never the event loop's default
        # executor: one pool for decisions and one for holds' waits, so waits
        # of up to `wait` seconds never delay a new decision past its deadline.
        self._decisions = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pantherclaw-decide")
        self._waits = ThreadPoolExecutor(max_workers=32, thread_name_prefix="pantherclaw-wait")

    @classmethod
    def from_key_file(cls, path: str, gateway: str, connection: str, server: str = "", run_id: str = "", **options: Any) -> PantherClaw:
        """Builds the client from a key file, with the built-ins and a
        timeout no longer than the hook's deadline, and the integration on
        it."""
        builtins = options.get("builtin_tools", BUILTIN_TOOLS)
        timeout = min(15.0, float(options.get("deadline", 10.0)))
        client = Client(pap.KeyFile.read(path), gateway=gateway, server=server, run_id=run_id, timeout=timeout, builtins=builtins)
        return cls(client, connection, **options)

    def options(self, **app: Any) -> dict[str, Any]:
        """Returns the keyword arguments for ClaudeAgentOptions with
        PantherClaw added. ``permission_mode`` must be passed explicitly.
        can_use_tool needs a streaming prompt (an async iterable): pass one
        to query() or ClaudeSDKClient; PantherClaw's PreToolUse hook keeps the
        stream open, as the SDK's documented workaround requires."""
        if not app.get("permission_mode"):
            raise ValueError("PantherClaw: pass permission_mode explicitly")
        if self._shell_connection:
            _refuse_ungoverned_shells(app)
        self._mode = app["permission_mode"]
        self._allowed = list(app.get("allowed_tools") or [])
        # Settings files can hold allow rules this integration cannot see, so
        # a hold is never asked with them loaded. Only an explicit empty list
        # loads none: the TypeScript SDK loads every source when the option
        # is omitted, so an omitted one is treated as loading them.
        sources = app.get("setting_sources")
        self._settings_loaded = sources is None or len(sources) > 0
        self._app_can_use_tool = app.get("can_use_tool")
        configured: Mapping[str, Any] = app.get("mcp_servers") or {}
        self._servers = list(dict.fromkeys([*self._servers, *configured]))
        face = self._client.gateway + "/mcp/"
        self._trusted = {
            name for name in self._gateway_servers
            if isinstance(configured.get(name), Mapping) and str(configured[name].get("url", "")).startswith(face)
        }  # fmt: skip
        hooks = dict(app.get("hooks") or {})
        hooks["PreToolUse"] = [*hooks.get("PreToolUse", []), HookMatcher(hooks=[self.hook], timeout=self._deadline + 5)]
        undecided = [t for t in UNDECIDED_TOOLS if t not in self._builtins]
        disallowed = list(dict.fromkeys([*(app.get("disallowed_tools") or []), *undecided]))
        return {**app, "disallowed_tools": disallowed, "hooks": hooks, "can_use_tool": self.can_use_tool()}

    def _route(self, tool: str, named: str = "") -> tuple[str, str]:
        """("call", server), ("shell", shell), ("skip", "") or ("refuse", why).
        An MCP tool's server is the one the SDK names, or else the one
        configured server whose name fits the tool's. A tool whose name two
        servers' names fit is refused, and so is a server not named after a
        connection, unless the gateway's /mcp face serves it."""
        if tool.startswith("mcp__"):
            rest = tool[5:]

            def fits(s: str) -> bool:
                return len(rest) > len(s) + 2 and rest.startswith(s + "__")

            servers = [named] if named and fits(named) else [s for s in dict.fromkeys(self._servers) if fits(s)]
            if not servers:
                return "refuse", f"the MCP server of {tool} is not configured"
            if len(servers) > 1:
                return "refuse", f"the names of the MCP servers {' and '.join(servers)} both fit {tool}"
            server = servers[0]
            if server in self._trusted:
                return "skip", ""
            if not _CONNECTION_NAME.match(server):
                return "refuse", f"the MCP server {server} is not named after a connection (name a governed MCP server after its connection)"
            return "call", server
        if tool in _SHELLS and self._shell_connection:
            return "shell", _SHELLS[tool]
        return "call", ""

    async def _run(self, fn: Callable[[], Any], timeout: float, pool: ThreadPoolExecutor | None = None) -> Any:
        """Runs a blocking client call on PantherClaw's threads (the decision
        pool unless another is named), within timeout."""
        return await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(pool or self._decisions, fn), timeout)

    async def hook(self, input_data: dict[str, Any], tool_use_id: str | None = None, context: Any = None) -> dict[str, Any]:
        """The PreToolUse hook (no matcher: every tool, a subagent's included).
        It never raises: any failure denies (HR-200)."""
        try:
            return await self._decide(input_data, tool_use_id)
        except Exception as e:  # noqa: BLE001 - any failure denies
            return _decision("deny", f"PantherClaw cannot decide this call: {e or type(e).__name__}")

    async def _decide(self, data: dict[str, Any], tool_use_id: str | None) -> dict[str, Any]:
        tool, args = data.get("tool_name", ""), data.get("tool_input")
        if not isinstance(args, dict):
            return _decision("deny", "the tool input is not an object")
        named = data.get("mcp_server")
        kind, detail = self._route(tool, str(named.get("name") or "") if isinstance(named, dict) else "")
        if kind == "skip":
            return {}
        if kind == "refuse":
            return _decision("deny", f"PantherClaw cannot decide this call: {detail}")
        use_id = _call_id(data.get("tool_use_id") or tool_use_id)
        if kind == "shell":
            return await self._shell(data, detail, args, use_id)
        server = detail
        builtin = not server and tool in self._builtins
        if not server and not builtin:
            return {} if self._observe_unmapped else _decision("deny", f"PantherClaw does not know the {tool} tool")
        key = json.dumps([tool, server, args], sort_keys=True)
        self._prune()
        with self._lock:
            action_id = self._retries[key][0] if key in self._retries else new_action_id()
        res = await self._run(lambda: self._client.authorize(self._connection, tool, args, use_id, action_id, server=server), self._deadline)
        return self._answer(res, data, _Held(tool, args, use_id, server, action_id, res.answer, key), builtin)

    async def _shell(self, data: dict[str, Any], shell: str, args: dict[str, Any], use_id: str) -> dict[str, Any]:
        """A shell command, decided through the local connection's /hook face
        (pc.shell) in its final working directory. A Monitor without a
        command (a WebSocket watch) is denied: only commands are decided
        there."""
        command = args.get("command")
        if not isinstance(command, str) or not command:
            tool = data.get("tool_name", "")
            return _decision("deny", f"PantherClaw cannot decide this call: {tool} has no command, and only commands are decided while the shell is governed")
        if not data.get("cwd"):
            return _decision("deny", "PantherClaw cannot decide this call: no working directory")
        cwd = os.path.realpath(str(data["cwd"]), strict=True)
        res = await self._run(lambda: self._client.hook(self._shell_connection, shell, command, cwd, use_id), self._deadline)
        if res.outcome == "allow":
            return _decision("allow", res.why or "PantherClaw allowed this command")
        if res.held:
            txn = res.answer.get("transaction_id")
            where = f" (transaction {txn})" if txn else ""
            return _decision("deny", f"PantherClaw holds this command for an approval by an eligible person{where}; once it is approved, run the same command again")
        return _decision("deny", res.why or "PantherClaw denied this command")

    def _answer(self, res: Result, data: dict[str, Any], h: _Held, builtin: bool) -> dict[str, Any]:
        if res.outcome != "hold":
            # A final answer: an identical call later is a new decision (M14 D68).
            with self._lock:
                self._retries.pop(h.key, None)
        if res.outcome == "allow":
            if res.send is not None:
                if self._on_dispatch is None:
                    return _decision("deny", "this connection's target accepts only PantherClaw's own request: pass on_dispatch to send it")
                self._on_dispatch(h.tool_use_id, res.send)
            return _decision("allow", "PantherClaw allowed this call")
        if res.outcome == "observe":
            # A built-in is recorded, not decided: the application's own permissions apply.
            return {} if builtin else _decision("deny", "PantherClaw does not map this tool")
        if res.outcome == "hold":
            handle = res.answer["wait"]["handle"]
            with self._lock:
                self._retries[h.key] = (h.action_id, time.monotonic() + self._wait)
                if self._may_ask(data, h):
                    h.expires = time.monotonic() + self._wait
                    self._held[h.tool_use_id] = h
                    self._asked[h.tool_use_id] = None
                    if len(self._asked) > _MAX_ASKED:
                        self._asked.popitem(last=False)
                    return _decision("ask", f"PantherClaw holds this call for an approval (transaction {handle})")
            return _decision(
                "deny",
                f"PantherClaw holds this call for an approval by an eligible person (transaction {handle}); "
                "once it is approved, make the same call again",
            )
        if res.answer.get("code") == "unknown_tool" and self._observe_unmapped:
            return {}
        return _decision("deny", res.why or "PantherClaw denied this call")

    def _may_ask(self, data: dict[str, Any], h: _Held) -> bool:
        """Whether a hold may be asked: this integration's can_use_tool is
        installed, the call's permission mode is on ASK_MODES, no settings
        files are loaded, no allow rule names the tool (wildcards and server
        rules included), and there is room to remember the hold. Otherwise
        it is denied (HR-200)."""
        mode = data.get("permission_mode") or self._mode
        return (
            self._can_use_tool_installed
            and mode in ASK_MODES
            and not self._settings_loaded
            and not any(rule_names(r, h.tool, h.server) for r in self._allowed)
            and len(self._held) < _MAX_HELD
        )

    def _prune(self) -> None:
        """Forgets holds and retry ids past their wait."""
        now = time.monotonic()
        with self._lock:
            for k in [k for k, h in self._held.items() if h.expires < now]:
                del self._held[k]
            for k in [k for k, (_, exp) in self._retries.items() if exp < now]:
                del self._retries[k]

    def can_use_tool(self) -> Callable[[str, dict[str, Any], Any], Awaitable[Any]]:
        """The can_use_tool callback. It handles only calls PantherClaw holds:
        it waits on the hold within its own deadline, resubmits the identical
        call and allows only on PantherClaw's allow, with the original input.
        A call whose hook answer was "ask", or one without a tool_use_id
        while a call of its tool is held, is never handed to the application.
        Every other call goes to the application's own callback, or is denied
        when there is none (never asking the local user for a PantherClaw
        hold)."""
        self._can_use_tool_installed = True

        async def callback(tool_name: str, tool_input: dict[str, Any], context: Any) -> Any:
            self._prune()
            use_id = getattr(context, "tool_use_id", None)
            with self._lock:
                h = self._held.get(use_id) if use_id else None
                if h is not None and h.tool == tool_name:
                    del self._held[use_id]
                elif h is not None or (use_id and use_id in self._asked):
                    return PermissionResultDeny(message="PantherClaw holds this call; the wait for it has ended (PantherClaw, PARTIAL)")
                elif not use_id and any(x.tool == tool_name for x in self._held.values()):
                    return PermissionResultDeny(message="PantherClaw holds a call of this tool; it runs only after PantherClaw allows it (PantherClaw, PARTIAL)")
            if h is None:
                if self._app_can_use_tool is not None:
                    return await self._app_can_use_tool(tool_name, tool_input, context)
                return PermissionResultDeny(message="no permission handler for this call")
            cancelled = threading.Event()
            try:
                res = await self._run(lambda: self._resume(h, cancelled), self._wait, self._waits)
            except Exception as e:  # noqa: BLE001 - any failure while waiting denies
                cancelled.set()
                return PermissionResultDeny(message=f"the wait for PantherClaw's decision ended: {e or type(e).__name__}")
            if res.outcome != "allow":
                if res.outcome == "deny":
                    # The hold ended in PantherClaw: an identical call later is a new decision (M14 D68).
                    with self._lock:
                        self._retries.pop(h.key, None)
                return PermissionResultDeny(message=f"{res.why or 'PantherClaw did not allow this call'} (PantherClaw, PARTIAL)")
            # A final allow: forget the action id before anything else can return (M14 D68, D81).
            with self._lock:
                self._retries.pop(h.key, None)
            if res.send is not None:
                if self._on_dispatch is None:
                    return PermissionResultDeny(message="this connection's target accepts only PantherClaw's own request: pass on_dispatch to send it")
                self._on_dispatch(h.tool_use_id, res.send)
            return PermissionResultAllow(updated_input=h.tool_input)

        return callback

    def _resume(self, h: _Held, cancelled: threading.Event) -> Result:
        return self._client.resume(
            self._connection, h.tool, h.tool_input, h.tool_use_id, h.action_id, Result("hold", "", h.answer), server=h.server,
            deadline=self._wait, cancelled=cancelled.is_set,
        )
