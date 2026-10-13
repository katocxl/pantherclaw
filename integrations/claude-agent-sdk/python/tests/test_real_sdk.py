# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The integration inside the real Agent SDK (claude-agent-sdk, dev-only,
pinned in uv.lock): its own Claude Code process talks to a fake Messages API
and a stdio MCP server on 127.0.0.1, offline, with an environment of only
the variables a process needs, never this machine's Claude configuration.
These are the TypeScript integration's real-SDK tests, for Python."""

from __future__ import annotations

import asyncio
import glob
import json
import os
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from test_integration import OBSERVE, Face, Gateway, decided, hold_then_allow

from pantherclaw_claude_agent_sdk import BUILTIN_TOOLS, PantherClaw

try:
    import claude_agent_sdk as sdk
except ImportError:  # the assertions below say how to install it
    sdk = None  # type: ignore[assignment]

_HERE = Path(__file__).resolve().parent
_PACKAGE = _HERE.parent
_ROOT = _HERE.parents[3]
FAKE_MCP = str(_HERE / "fake_mcp.py")
REFUND = {"amount": "30.00", "charge": "ch_1"}
_KEEP = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR", "LANG", "OS", "NUMBER_OF_PROCESSORS",
         "PROCESSOR_ARCHITECTURE"}  # fmt: skip


def cli_path() -> str:
    """The Claude Code CLI the SDK runs, always named explicitly so the SDK
    never falls back to a `claude` on PATH: the one its wheel bundles, or,
    where no wheel bundles one (Windows), the platform binary the TypeScript
    integration pins in its pnpm-lock.yaml."""
    assert sdk is not None, "claude-agent-sdk is not installed: run `uv sync --locked` here (task sdk:check does)"
    bundled = Path(sdk.__file__).parent / "_bundled" / ("claude.exe" if os.name == "nt" else "claude")
    if bundled.is_file():
        return str(bundled)
    pinned = glob.glob(str(_ROOT / "integrations/claude-agent-sdk/typescript/node_modules/.pnpm/@anthropic-ai+claude-agent-sdk-win32-x64@*"
                           "/node_modules/@anthropic-ai/claude-agent-sdk-win32-x64/claude.exe"))
    assert pinned, "no Claude Code CLI: run `corepack pnpm install --frozen-lockfile` in integrations/claude-agent-sdk/typescript (task sdk:check does)"
    return pinned[0]


def model(prompt: str, tools: list[str]) -> dict[str, Any]:
    """The scripted model: each scenario's first tool call, named in the prompt (or a subagent's task)."""
    if "PC_SCENARIO=refund" in prompt:
        return {"tool": "mcp__payments__create_refund", "input": REFUND}
    if "PC_SCENARIO=bash" in prompt:
        return {"tool": "Bash", "input": {"command": "echo ran > marker.txt", "description": "Write a marker"}}
    if "PC_SCENARIO=monitor" in prompt:
        return {"tool": "Monitor", "input": {"command": "echo ran > marker.txt", "description": "Write a marker", "timeout_ms": 60000}}
    if "PC_SCENARIO=subagent" in prompt:
        agent = "Agent" if "Agent" in tools else "Task"
        return {"tool": agent, "input": {"description": "Refund the charge", "prompt": "PC_SCENARIO=refund", "subagent_type": "general-purpose"}}
    return {"text": "nothing to do"}


class FakeAnthropic:
    """A fake Messages API: the model asks for the tool call a scenario
    names, then ends its turn once the conversation holds a tool result;
    requests that offer no tools (the CLI's own housekeeping) get text."""

    def __init__(self, script: Callable[[str, list[str]], dict[str, Any]]) -> None:
        self.requests: list[dict[str, Any]] = []
        counter = [0]
        api = self

        def message(turn: dict[str, Any]) -> dict[str, Any]:
            counter[0] += 1
            if "tool" in turn:
                content = [{"type": "tool_use", "id": f"toolu_fake{counter[0]}", "name": turn["tool"], "input": turn["input"]}]
            else:
                content = [{"type": "text", "text": turn["text"]}]
            return {"id": f"msg_fake{counter[0]}", "type": "message", "role": "assistant", "model": "claude-fake", "content": content,
                    "stop_reason": "tool_use" if "tool" in turn else "end_turn", "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 5}}  # fmt: skip

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                path = self.path.split("?")[0]
                if path == "/v1/messages/count_tokens":
                    return self._send(200, "application/json", b'{"input_tokens":10}')
                if path != "/v1/messages":
                    return self._send(404, "application/json", b'{"type":"error","error":{"type":"not_found_error","message":"not found"}}')
                r = json.loads(body)
                api.requests.append(r)
                messages = r.get("messages") or []
                tools = [str(t.get("name")) for t in r.get("tools") or []]
                if not tools:
                    turn: dict[str, Any] = {"text": "ok"}
                elif any(isinstance(m.get("content"), list) and any(b.get("type") == "tool_result" for b in m["content"]) for m in messages):
                    turn = {"text": "done"}
                else:
                    first = next((m for m in messages if m.get("role") == "user"), {})
                    c = first.get("content")
                    text = c if isinstance(c, str) else "\n".join(str(b.get("text", "")) for b in c or [] if b.get("type") == "text")
                    turn = script(text, tools)
                m = message(turn)
                if not r.get("stream"):
                    return self._send(200, "application/json", json.dumps(m).encode())
                block = m["content"][0]
                events = [("message_start", {"message": {**m, "content": [], "stop_reason": None, "usage": {"input_tokens": 10, "output_tokens": 1}}})]
                if block["type"] == "tool_use":
                    events += [("content_block_start", {"index": 0, "content_block": {**block, "input": {}}}),
                               ("content_block_delta", {"index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}})]
                else:
                    events += [("content_block_start", {"index": 0, "content_block": {"type": "text", "text": ""}}),
                               ("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": block["text"]}})]
                events += [("content_block_stop", {"index": 0}),
                           ("message_delta", {"delta": {"stop_reason": m["stop_reason"], "stop_sequence": None}, "usage": {"output_tokens": 5}}),
                           ("message_stop", {})]
                stream = "".join(f"event: {t}\ndata: {json.dumps({'type': t, **d})}\n\n" for t, d in events).encode()
                self._send(200, "text/event-stream", stream)

            def _send(self, status: int, kind: str, b: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", kind)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def face_for(mcp: Face) -> Face:
    """A face that observes the SDK's built-ins and answers MCP tools with `mcp`."""
    return lambda call, aid: mcp(call, aid) if str(call.get("tool", "")).startswith("mcp__") else OBSERVE(call, aid)


DENY: Face = lambda _c, aid: decided(aid, "deny", error_class="policy_denied", reason="denied")  # noqa: E731
ALLOW: Face = lambda _c, aid: decided(aid, "allow")  # noqa: E731
HOOK_DENY = lambda _c: (200, json.dumps({"decision": "deny", "reason": "no", "mode": "enforce"}).encode())  # noqa: E731


def hook_output(decision: str, reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision, "permissionDecisionReason": reason}}


class Run:
    def __init__(self, refunds: list[dict[str, Any]], tools: list[str], directory: str) -> None:
        self.refunds, self.tools, self.dir = refunds, tools, directory


class RealSDKTest(unittest.TestCase):
    def setUp(self) -> None:
        self.closers: list[Callable[[], None]] = []

    def tearDown(self) -> None:
        for close in self.closers:
            close()

    def gateway(self, face: Face, states: tuple[str, ...] = ("READY",), hook: Any = None) -> Gateway:
        g = Gateway(face, states, hook)
        self.closers.append(g.close)
        return g

    def integration(self, g: Gateway, **kw: Any) -> PantherClaw:
        return PantherClaw(g.client, "payments", **({"shell": "observe", "deadline": 5.0, "wait": 5.0} | kw))

    def run_sdk(self, prompt: str, options: Callable[[dict[str, Any]], dict[str, Any]], features: dict[str, Any] | None = None) -> Run:
        """Runs one scenario through the real SDK. `options` gets the options
        the run needs (cwd, environment, CLI, the MCP server) and returns the
        ClaudeAgentOptions arguments, usually through PantherClaw's options()."""
        assert sdk is not None, "claude-agent-sdk is not installed: run `uv sync --locked` here (task sdk:check does)"
        api = FakeAnthropic(model)
        self.closers.append(api.close)
        d = tempfile.mkdtemp(prefix="pc-agent-sdk-")
        log = os.path.join(d, "refunds.log")
        # The CLI's feature flags, from its own cache on disk (it never fetches them here).
        os.makedirs(os.path.join(d, "config"))
        Path(d, "config", ".claude.json").write_text(json.dumps({"cachedGrowthBookFeatures": features or {}}), encoding="utf-8")
        # The SDK hands the CLI this process's whole environment, so the run has only these variables.
        env = {k: v for k, v in os.environ.items() if k.upper() in _KEEP} | {
            "HOME": d, "USERPROFILE": d, "APPDATA": os.path.join(d, "appdata"), "LOCALAPPDATA": os.path.join(d, "localappdata"),
            "CLAUDE_CONFIG_DIR": os.path.join(d, "config"), "ANTHROPIC_BASE_URL": api.url, "ANTHROPIC_API_KEY": "sk-ant-test-not-a-key",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_GB_DISK_CACHE_WHEN_TELEMETRY_OFF": "1",
            "CLAUDE_AGENT_SDK_SKIP_VERSION_CHECK": "1",
        }  # fmt: skip
        base = {"cwd": d, "max_turns": 6, "cli_path": cli_path(), "mcp_servers": {"payments": {"type": "stdio", "command": sys.executable,
                                                                                              "args": [FAKE_MCP, log]}}}

        async def go() -> None:
            done = asyncio.Event()

            async def prompt_stream() -> Any:
                # A streaming prompt, held open until the result, as can_use_tool needs.
                yield {"type": "user", "message": {"role": "user", "content": prompt}, "parent_tool_use_id": None, "session_id": ""}
                await done.wait()

            try:
                # The result ends the prompt, and with it the query: never left mid-iteration.
                async for m in sdk.query(prompt=prompt_stream(), options=sdk.ClaudeAgentOptions(**options(base))):
                    if isinstance(m, sdk.ResultMessage):
                        done.set()
            finally:
                done.set()

        with mock.patch.dict(os.environ, env, clear=True):
            asyncio.run(go())
        refunds = [json.loads(line) for line in Path(log).read_text(encoding="utf-8").splitlines() if line] if os.path.exists(log) else []
        tools = list(dict.fromkeys(str(t.get("name")) for r in api.requests for t in r.get("tools") or []))
        return Run(refunds, tools, d)

    def test_HR200_the_supported_agent_sdk_version_is_the_one_installed_and_every_built_in_it_offers_is_known(self) -> None:
        assert sdk is not None, "claude-agent-sdk is not installed: run `uv sync --locked` here (task sdk:check does)"
        supported = tomllib.loads((_PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))["project"]["optional-dependencies"]["agent-sdk"][0]
        lo, hi = supported.split(">=")[1].split(",<")
        version = tuple(int(x) for x in sdk.__version__.split("."))
        self.assertTrue(tuple(int(x) for x in lo.split(".")) <= version < tuple(int(x) for x in hi.split(".")), f"{sdk.__version__} within {supported}")
        g = self.gateway(face_for(DENY))
        r = self.run_sdk("PC_SCENARIO=none", lambda base: self.integration(g).options(**base, permission_mode="default", setting_sources=[]))
        unknown = [t for t in r.tools if not t.startswith("mcp__") and t not in BUILTIN_TOOLS]
        self.assertEqual(unknown, [], "a built-in the integration does not know would be denied")

    def test_HR200_in_the_real_sdk_pantherclaws_deny_stops_the_tool_in_every_permission_mode(self) -> None:
        for mode in ("default", "acceptEdits", "bypassPermissions", "dontAsk", "auto"):
            with self.subTest(mode):
                g = self.gateway(face_for(DENY))
                r = self.run_sdk("PC_SCENARIO=refund", lambda base, g=g, mode=mode: self.integration(g).options(
                    **base, permission_mode=mode, setting_sources=[],
                    extra_args={"allow-dangerously-skip-permissions": None} if mode == "bypassPermissions" else {}))  # fmt: skip
                self.assertEqual(r.refunds, [], f"{mode}: the tool ran")
                self.assertTrue(any(c["tool"] == "mcp__payments__create_refund" for c in g.calls), f"{mode}: PantherClaw was not asked")
        # The harness itself: PantherClaw's allow lets the tool run.
        g = self.gateway(face_for(ALLOW))
        r = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(g).options(
            **base, permission_mode="bypassPermissions", setting_sources=[], extra_args={"allow-dangerously-skip-permissions": None}))
        self.assertEqual(r.refunds, [REFUND])

    def test_HR200_in_the_real_sdk_a_hold_is_asked_in_default_mode_waited_on_and_runs_once_pantherclaw_allows_it(self) -> None:
        g = self.gateway(face_for(hold_then_allow()))
        r = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(g).options(**base, permission_mode="default", setting_sources=[]))
        self.assertEqual(r.refunds, [REFUND], "the tool ran once, with its original input")
        self.assertEqual(sum(c["tool"] == "mcp__payments__create_refund" for c in g.calls), 2, "the identical call was resubmitted once")
        # In any other mode the hold is denied, never asked.
        d = self.gateway(face_for(hold_then_allow()))
        b = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(d).options(
            **base, permission_mode="bypassPermissions", setting_sources=[], extra_args={"allow-dangerously-skip-permissions": None}))
        self.assertEqual(b.refunds, [])

    def test_HR200_in_the_real_sdk_a_tool_never_runs_after_a_hooks_ask_without_can_use_tools_allow(self) -> None:
        async def ask(_input: Any, _id: Any, _ctx: Any) -> dict[str, Any]:
            return hook_output("ask", "test")

        hooks = {"PreToolUse": [sdk.HookMatcher(hooks=[ask])]} if sdk else {}
        none = self.run_sdk("PC_SCENARIO=refund", lambda base: base | {"permission_mode": "default", "setting_sources": [], "hooks": hooks})
        self.assertEqual(none.refunds, [], "ask without can_use_tool")
        asked = [0]

        async def deny(_name: str, _input: Any, _ctx: Any) -> Any:
            asked[0] += 1
            return sdk.PermissionResultDeny(message="no")

        denied = self.run_sdk("PC_SCENARIO=refund", lambda base: base | {"permission_mode": "default", "setting_sources": [], "hooks": hooks,
                                                                        "can_use_tool": deny})
        self.assertEqual(asked[0], 1, "can_use_tool was called after the hook's ask")
        self.assertEqual(denied.refunds, [], "ask, then can_use_tool's deny")

    def test_HR200_in_the_real_sdk_the_applications_own_hook_never_overrides_pantherclaws_deny(self) -> None:
        async def app_allow(_input: Any, _id: Any, _ctx: Any) -> dict[str, Any]:
            return hook_output("allow", "app")

        async def app_deny(_input: Any, _id: Any, _ctx: Any) -> dict[str, Any]:
            return hook_output("deny", "app")

        g = self.gateway(face_for(DENY))
        r = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(g).options(
            **base, permission_mode="default", setting_sources=[], hooks={"PreToolUse": [sdk.HookMatcher(hooks=[app_allow])]}))
        self.assertEqual(r.refunds, [], "an app allow with PantherClaw's deny")
        a = self.gateway(face_for(ALLOW))
        d = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(a).options(
            **base, permission_mode="default", setting_sources=[], hooks={"PreToolUse": [sdk.HookMatcher(hooks=[app_deny])]}))
        self.assertEqual(d.refunds, [], "an app deny with PantherClaw's allow")

    def test_HR200_in_the_real_sdk_the_applications_allow_never_runs_a_call_pantherclaw_holds_and_asks_about(self) -> None:
        async def app_allow(_input: Any, _id: Any, _ctx: Any) -> dict[str, Any]:
            return hook_output("allow", "app")

        # The hold never becomes ready: only can_use_tool's allow could run the tool, and it denies at its deadline.
        g = self.gateway(face_for(hold_then_allow()), states=("PENDING",))
        start = time.monotonic()
        r = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(g, wait=1.5).options(
            **base, permission_mode="default", setting_sources=[], hooks={"PreToolUse": [sdk.HookMatcher(hooks=[app_allow])]}))
        self.assertEqual(r.refunds, [], "an app allow ran a held call")
        self.assertEqual(sum(c["tool"] == "mcp__payments__create_refund" for c in g.calls), 1, "a held call was resubmitted without PantherClaw's ready")
        self.assertGreaterEqual(time.monotonic() - start, 1.4, "the call was not left to can_use_tool's wait")

    def test_HR200_in_the_real_sdk_a_pantherclaw_that_does_not_answer_is_denied_at_the_integrations_deadline(self) -> None:
        g = self.gateway(face_for(lambda _c, _a: None))
        start = time.monotonic()
        r = self.run_sdk("PC_SCENARIO=refund", lambda base: self.integration(g, deadline=1.5).options(
            **base, permission_mode="bypassPermissions", setting_sources=[], extra_args={"allow-dangerously-skip-permissions": None}))
        self.assertEqual(r.refunds, [])
        self.assertLess(time.monotonic() - start, 6.5 + 10, "denied well before the registered hook timeout")

    def test_HR200_in_the_real_sdk_a_subagents_tool_calls_go_through_pantherclaws_hook(self) -> None:
        seen: list[dict[str, Any]] = []

        async def record(data: Any, _id: Any, _ctx: Any) -> dict[str, Any]:
            seen.append(data)
            return {}

        g = self.gateway(face_for(DENY))
        r = self.run_sdk("PC_SCENARIO=subagent", lambda base: self.integration(g).options(
            **base, permission_mode="bypassPermissions", setting_sources=[], extra_args={"allow-dangerously-skip-permissions": None},
            hooks={"PreToolUse": [sdk.HookMatcher(hooks=[record])]}))  # fmt: skip
        self.assertEqual(r.refunds, [], "the subagent's refund ran")
        sub = next((i for i in seen if i.get("tool_name") == "mcp__payments__create_refund"), {})
        self.assertTrue(sub.get("agent_id"), "the hook saw the subagent's call")
        self.assertTrue(any(c["tool"] == "mcp__payments__create_refund" for c in g.calls), "PantherClaw decided the subagent's call")

    def test_HR200_in_the_real_sdk_bash_goes_to_the_local_connections_hook_face_and_its_deny_stops_it(self) -> None:
        g = self.gateway(face_for(DENY), hook=HOOK_DENY)
        r = self.run_sdk("PC_SCENARIO=bash", lambda base: self.integration(g, shell="", shell_connection="local").options(
            **base, permission_mode="bypassPermissions", setting_sources=[], extra_args={"allow-dangerously-skip-permissions": None}))
        self.assertEqual(len(g.hooks), 1, "the command went to /hook")
        self.assertEqual([c for c in g.calls if c["tool"] == "Bash"], [], "never to /sdk")
        self.assertFalse(os.path.exists(os.path.join(r.dir, "marker.txt")), "the command ran")

    def test_HR186_in_the_real_sdk_monitors_command_goes_to_the_local_connections_hook_face_and_its_deny_stops_it(self) -> None:
        g = self.gateway(face_for(DENY), hook=HOOK_DENY)
        r = self.run_sdk("PC_SCENARIO=monitor", lambda base: self.integration(g, shell="", shell_connection="local").options(
            **base, permission_mode="bypassPermissions", setting_sources=[], extra_args={"allow-dangerously-skip-permissions": None}),
            # Monitor is offered only behind this flag.
            features={"tengu_amber_sentinel": True})
        self.assertIn("Monitor", r.tools, "the model was offered Monitor")
        self.assertEqual(len(g.hooks), 1, "the command went to /hook")
        self.assertEqual(g.hooks[0]["input"]["shell"], "bash")
        self.assertEqual([c for c in g.calls if c["tool"] == "Monitor"], [], "never to /sdk")
        self.assertFalse(os.path.exists(os.path.join(r.dir, "marker.txt")), "the command ran")


if __name__ == "__main__":
    unittest.main()
