# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import sys
from pathlib import Path

# The core client and this package from the repository, until both are published.
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parents[4]
sys.path[:0] = [str(_ROOT / "sdk" / "python" / "src"), str(_HERE.parents[1] / "src")]

import asyncio  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from collections.abc import Callable  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from typing import Any  # noqa: E402

from pantherclaw import pap  # noqa: E402
from pantherclaw.client import Client, Outbound  # noqa: E402
from pantherclaw_claude_agent_sdk import BUILTIN_TOOLS, PantherClaw, rule_names  # noqa: E402

IDENT = "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005"
RUN = "01920000-0000-7000-8000-000000000003"


def _vectors(name: str) -> dict[str, Any]:
    return json.loads((_ROOT / "sdk" / "conformance" / name).read_text(encoding="utf-8"))


_SDK_ACTION = next(c["canonical"] for c in _vectors("actionir.json")["cases"] if c["name"] == "sdk channel through a connection")

Face = Callable[[dict[str, Any], str], tuple[int, bytes] | None]
HookFace = Callable[[dict[str, Any]], tuple[int, bytes]]


def decided(aid: str, decision: str, **extra: Any) -> tuple[int, bytes]:
    """The face's answer for an action id: the canonical sdk-channel action and its hash."""
    act = _SDK_ACTION.replace('"action_id":"01920000-0000-7000-8000-000000000004"', f'"action_id":"{aid}"')
    a = {"decision": decision, "action_id": aid, "action_hash": hashlib.sha256(act.encode()).hexdigest(), "action_ir": pap.b64url(act.encode()),
         "coverage": "PARTIAL", "mode": "enforce", **extra}
    return 200, json.dumps(a).encode()


class Gateway:
    """A PantherClaw server and gateway in one: unsigned tokens, the /sdk
    face of connection "payments", the /hook face of "local", and an SSE
    wait stream of ``states``."""

    def __init__(self, face: Face, states: tuple[str, ...] = ("READY",), hook: HookFace | None = None) -> None:
        self.kf = pap.KeyFile.new()
        self.kf.identifier = IDENT
        jkt = self.kf.key().jkt
        self.calls: list[dict[str, Any]] = []
        self.hooks: list[dict[str, Any]] = []
        gw = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                self.do_POST()

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.path == "/pantherclaw.v1.WorkloadService/IssueToken":
                    claims = {"aud": "pantherclaw-gateway", "exp": int(time.time()) + 600, "cnf": {"jkt": jkt}, "pap": {"v": 1}}
                    unsigned = pap.b64url(b'{"alg":"EdDSA"}') + "." + pap.b64url(json.dumps(claims).encode()) + "." + pap.b64url(b"sig")
                    self._send(200, json.dumps({"workloadToken": unsigned}).encode())
                elif self.path == "/sdk/payments":
                    call = json.loads(body)
                    gw.calls.append(call)
                    out = face(call, self.headers.get("PC-Action-Id", ""))
                    if out is None:
                        time.sleep(2)
                        return
                    self._send(*out)
                elif self.path == "/hook/local" and hook is not None:
                    call = json.loads(body)
                    gw.hooks.append(call)
                    self._send(*hook(call))
                elif self.path.startswith("/v1/wait/"):
                    stream = "".join(f"event: state\ndata: {json.dumps({'handle': 'h', 'state': s})}\n\n" for s in states).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(stream)))
                    self.end_headers()
                    self.wfile.write(stream)
                else:
                    self._send(404, b"")

            def _send(self, status: int, b: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.kf.server = self.base
        self.client = Client(self.kf, gateway=self.base, run_id=RUN, timeout=1.0, builtins=BUILTIN_TOOLS)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def answer(decision: str, **extra: Any) -> Face:
    return lambda _call, aid: decided(aid, decision, **extra)


def hold_then_allow() -> Face:
    n = [0]

    def face(call: dict[str, Any], aid: str) -> tuple[int, bytes]:
        n[0] += 1
        return decided(aid, "hold", wait={"handle": "h", "state": "PENDING"}) if n[0] == 1 else decided(aid, "allow")

    return face


OBSERVE: Face = lambda _c, _a: (200, json.dumps({"decision": "allow", "coverage": "OBSERVE_ONLY", "mode": "monitor"}).encode())  # noqa: E731
UNMAPPED: Face = lambda _c, a: (200, json.dumps({"decision": "deny", "code": "unknown_tool", "action_id": a, "coverage": "PARTIAL", "mode": "enforce"}).encode())  # noqa: E731


def refund(mode: str = "default", use_id: str = "toolu_01") -> dict[str, Any]:
    return {"hook_event_name": "PreToolUse", "tool_name": "mcp__payments__create_refund", "tool_input": {"amount": "30.00", "charge": "ch_1"},
            "tool_use_id": use_id, "cwd": "/repo", "permission_mode": mode}


def decision(out: dict[str, Any]) -> str:
    return out.get("hookSpecificOutput", {}).get("permissionDecision", "none")


class IntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.gateways: list[Gateway] = []

    def tearDown(self) -> None:
        for g in self.gateways:
            g.close()

    def gw(self, face: Face, states: tuple[str, ...] = ("READY",), hook: HookFace | None = None) -> Gateway:
        g = Gateway(face, states, hook)
        self.gateways.append(g)
        return g

    def pc(self, g: Gateway, **kw: Any) -> PantherClaw:
        options: dict[str, Any] = {"shell": "observe", "mcp_servers": ["payments"], "deadline": 1.5, "wait": 2.0} | kw
        return PantherClaw(g.client, "payments", **options)

    def run_hook(self, p: PantherClaw, data: dict[str, Any]) -> str:
        return decision(asyncio.run(p.hook(data, data.get("tool_use_id"), None)))

    def test_HR200_the_hook_denies_when_pantherclaw_cannot_decide(self) -> None:
        for name, face in {"a gateway error": lambda _c, _a: (502, b""), "a malformed answer": lambda _c, _a: (200, b"{"),
                           "no answer in time": lambda _c, _a: None}.items():
            with self.subTest(name):
                self.assertEqual(self.run_hook(self.pc(self.gw(face)), refund()), "deny")
        kf = pap.KeyFile.new()
        kf.identifier, kf.server = IDENT, "http://127.0.0.1:9"
        down = PantherClaw(Client(kf, gateway="http://127.0.0.1:9", run_id=RUN, timeout=1.0, builtins=BUILTIN_TOOLS), "payments",
                           shell="observe", mcp_servers=["payments"])
        self.assertEqual(self.run_hook(down, refund()), "deny")
        broken = self.pc(self.gw(answer("allow")))

        async def boom(*_a: Any) -> dict[str, Any]:
            raise RuntimeError("boom")

        broken._decide = boom  # type: ignore[method-assign]
        self.assertEqual(self.run_hook(broken, refund()), "deny")

    def test_HR200_pre_tool_use_decides_in_every_permission_mode(self) -> None:
        for mode in ("default", "acceptEdits", "plan", "bypassPermissions", "dontAsk", "auto"):
            with self.subTest(mode):
                self.assertEqual(self.run_hook(self.pc(self.gw(answer("deny"))), refund(mode)), "deny")
                self.assertEqual(self.run_hook(self.pc(self.gw(answer("allow"))), refund(mode)), "allow")

    def test_HR200_a_hold_never_runs_without_a_later_allow_and_is_asked_only_in_default_mode(self) -> None:
        cases: dict[str, tuple[str, dict[str, Any] | None]] = {
            "no can_use_tool": ("default", None),
            "bypassPermissions": ("bypassPermissions", {"permission_mode": "bypassPermissions"}),
            "dontAsk": ("dontAsk", {"permission_mode": "dontAsk"}),
            "acceptEdits": ("acceptEdits", {"permission_mode": "acceptEdits"}),
            "plan": ("plan", {"permission_mode": "plan"}),
            "auto": ("auto", {"permission_mode": "auto"}),
            "a mode it does not know": ("someNewMode", {"permission_mode": "someNewMode"}),
            "an allow rule naming the tool": ("default", {"permission_mode": "default", "allowed_tools": ["mcp__payments__create_refund"]}),
            "an allow rule with a specifier": ("default", {"permission_mode": "default", "allowed_tools": ["mcp__payments__create_refund(amount:*)"]}),
            "an allow rule naming the server": ("default", {"permission_mode": "default", "allowed_tools": ["mcp__payments"]}),
            "a server wildcard": ("default", {"permission_mode": "default", "allowed_tools": ["mcp__payments__*"]}),
            "a wildcard": ("default", {"permission_mode": "default", "allowed_tools": ["*"]}),
            "settings files loaded": ("default", {"permission_mode": "default", "setting_sources": ["project"]}),
        }
        for name, (mode, opts) in cases.items():
            with self.subTest(name):
                p = self.pc(self.gw(hold_then_allow()))
                if opts is not None:
                    p.options(**opts)
                self.assertEqual(self.run_hook(p, refund(mode)), "deny")
        g = self.gw(hold_then_allow())
        opts = self.pc(g).options(permission_mode="default", mcp_servers={"payments": {}}, allowed_tools=["Read", "mcp__github__*"])
        hook = opts["hooks"]["PreToolUse"][-1].hooks[0]
        self.assertEqual(decision(asyncio.run(hook(refund("default", "toolu_09"), "toolu_09", None))), "ask")
        ctx = SimpleNamespace(tool_use_id="toolu_09")
        r = asyncio.run(opts["can_use_tool"]("mcp__payments__create_refund", {"amount": "999.00", "charge": "ch_1"}, ctx))
        self.assertEqual((r.behavior, r.updated_input), ("allow", {"amount": "30.00", "charge": "ch_1"}))
        self.assertEqual(len(g.calls), 2)

    def test_allow_rules_name_a_tool_by_itself_its_server_or_a_wildcard(self) -> None:
        for rule, tool, server in [("Bash", "Bash", ""), ("Bash(git push:*)", "Bash", ""), ("mcp__payments", "mcp__payments__x", "payments"),
                                   ("mcp__payments__*", "mcp__payments__x", "payments"), ("mcp__*", "mcp__payments__x", "payments"), ("*", "Write", "")]:
            self.assertTrue(rule_names(rule, tool, server), rule)
        for rule, tool, server in [("Read", "Write", ""), ("mcp__github__*", "mcp__payments__x", "payments"), ("mcp__pay", "mcp__payments__x", "payments"),
                                   ("Bash.*", "Bash", "")]:
            self.assertFalse(rule_names(rule, tool, server), rule)

    def test_HR200_can_use_tool_waits_only_on_holds_and_never_hands_a_held_call_to_the_application(self) -> None:
        g = self.gw(hold_then_allow(), states=("PENDING",))
        app_calls: list[str] = []

        async def app(name: str, _input: dict[str, Any], _ctx: Any) -> Any:
            app_calls.append(name)
            return SimpleNamespace(behavior="allow", updated_input={})

        p = self.pc(g, wait=0.5)
        opts = p.options(permission_mode="default", can_use_tool=app)
        can = opts["can_use_tool"]
        self.assertEqual(asyncio.run(can("Write", {"file_path": "x"}, SimpleNamespace(tool_use_id="toolu_other"))).behavior, "allow")
        self.assertEqual(self.run_hook(p, refund("default", "toolu_10")), "ask")
        self.assertEqual(asyncio.run(can("mcp__payments__create_refund", {}, SimpleNamespace())).behavior, "deny")
        self.assertEqual(asyncio.run(can("mcp__payments__create_refund", {}, SimpleNamespace(tool_use_id="toolu_10"))).behavior, "deny")
        self.assertEqual(asyncio.run(can("mcp__payments__create_refund", {}, SimpleNamespace(tool_use_id="toolu_10"))).behavior, "deny")
        self.assertEqual(app_calls, ["Write"])

    def test_callers_must_pass_permission_mode(self) -> None:
        with self.assertRaises(ValueError):
            self.pc(self.gw(answer("allow"))).options()

    def test_HR200_bash_and_powershell_are_decided_through_the_local_connections_hook_face(self) -> None:
        held = [False]

        def hook(_call: dict[str, Any]) -> tuple[int, bytes]:
            a = {"decision": "deny", "held": True, "transaction_id": "t1", "mode": "enforce"} if held[0] else {"decision": "allow", "mode": "enforce"}
            return 200, json.dumps(a).encode()

        g = self.gw(answer("allow"), hook=hook)
        p = self.pc(g, shell="", shell_connection="local")
        with tempfile.TemporaryDirectory() as d:
            bash = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "git push"}, "tool_use_id": "toolu_11", "cwd": d}
            self.assertEqual(self.run_hook(p, bash), "allow")
            self.assertEqual(g.hooks[0], {"input": {"call": "toolu_11", "command": "git push", "cwd": os.path.realpath(d), "shell": "bash"}, "tool": "shell"})
            self.assertEqual(g.calls, [])
            held[0] = True
            out = asyncio.run(p.hook(bash | {"tool_name": "PowerShell", "tool_use_id": "toolu_12"}))
            self.assertEqual(decision(out), "deny")
            self.assertIn("t1", out["hookSpecificOutput"]["permissionDecisionReason"])
            self.assertEqual(g.hooks[1]["input"]["shell"], "powershell")
            self.assertEqual(self.run_hook(p, bash | {"cwd": os.path.join(d, "missing")}), "deny")
        down = self.gw(answer("allow"), hook=lambda _c: (502, b""))
        self.assertEqual(self.run_hook(self.pc(down, shell="", shell_connection="local"), bash), "deny")

    def test_HR200_without_a_local_connection_the_integration_refuses_to_start_unless_the_shell_is_observed(self) -> None:
        g = self.gw(OBSERVE)
        with self.assertRaises(ValueError):
            PantherClaw(g.client, "payments")
        p = PantherClaw(g.client, "payments", shell="observe")
        bash = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "toolu_13", "cwd": "/repo"}
        self.assertEqual(self.run_hook(p, bash), "none")
        self.assertEqual(g.calls[0], {"tool": "Bash", "input": {"command": "ls"}, "tool_use_id": "toolu_13"})

    def test_the_client_must_know_the_integrations_built_ins(self) -> None:
        g = self.gw(answer("allow"))
        with self.assertRaises(ValueError):
            PantherClaw(Client(g.kf, gateway=g.base, run_id=RUN), "payments", shell="observe")

    def test_unmapped_built_ins_are_observed_and_other_tools_denied(self) -> None:
        read = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}, "tool_use_id": "toolu_14"}
        self.assertEqual(self.run_hook(self.pc(self.gw(OBSERVE)), read), "none")
        self.assertEqual(self.run_hook(self.pc(self.gw(OBSERVE)), refund()), "deny")
        self.assertEqual(self.run_hook(self.pc(self.gw(UNMAPPED)), refund()), "deny")
        self.assertEqual(self.run_hook(self.pc(self.gw(UNMAPPED), observe_unmapped=True), refund()), "none")
        other = {"hook_event_name": "PreToolUse", "tool_name": "mcp__unknown__run", "tool_input": {}, "tool_use_id": "toolu_15"}
        self.assertEqual(self.run_hook(self.pc(self.gw(UNMAPPED)), other), "deny")
        custom = {"hook_event_name": "PreToolUse", "tool_name": "deploy", "tool_input": {}, "tool_use_id": "toolu_16"}
        self.assertEqual(self.run_hook(self.pc(self.gw(UNMAPPED)), custom), "deny")
        self.assertEqual(self.run_hook(self.pc(self.gw(UNMAPPED), observe_unmapped=True), custom), "none")

    def test_HR200_a_subagents_tool_calls_go_through_the_same_hook(self) -> None:
        g = self.gw(answer("deny"))
        self.assertEqual(self.run_hook(self.pc(g), refund() | {"agent_id": "agent-1", "agent_type": "general-purpose"}), "deny")
        self.assertEqual(len(g.calls), 1)

    def test_an_mcp_server_is_trusted_as_the_gateways_only_with_the_gateways_mcp_face(self) -> None:
        g = self.gw(answer("deny"))
        p = self.pc(g, gateway_mcp_servers=["payments", "github"])
        p.options(permission_mode="default", mcp_servers={"payments": {"type": "http", "url": "https://elsewhere.example.test/mcp/payments"},
                                                          "github": {"type": "http", "url": f"{g.base}/mcp/github"}})
        self.assertEqual(self.run_hook(p, refund()), "deny")
        gh = {"hook_event_name": "PreToolUse", "tool_name": "mcp__github__merge", "tool_input": {}, "tool_use_id": "toolu_17"}
        self.assertEqual(self.run_hook(p, gh), "none")
        self.assertEqual(len(g.calls), 1)

    def test_HR201_a_target_enforced_allow_sends_pantherclaws_own_request_or_is_denied(self) -> None:
        face = next(a for a in _vectors("sdk_face.json")["answers"] if "send" in a)
        dispatch = json.loads(face["body"])["dispatch"]
        g = self.gw(answer("allow", dispatch=dispatch))
        self.assertEqual(self.run_hook(self.pc(g), refund()), "deny")
        sent: list[tuple[str, Outbound]] = []
        p = self.pc(g, on_dispatch=lambda use_id, o: sent.append((use_id, o)))
        self.assertEqual(self.run_hook(p, refund("default", "toolu_18")), "allow")
        self.assertEqual((sent[0][0], sent[0][1].body), ("toolu_18", face["send"]["body"].encode()))

    def test_T080_a_forged_answer_never_runs_the_tool(self) -> None:
        forged = answer("allow", action_hash=hashlib.sha256(b"another action").hexdigest(), action_ir=pap.b64url(b"{}"))
        self.assertEqual(self.run_hook(self.pc(self.gw(forged)), refund()), "deny")
        unlabeled = answer("allow", coverage="")
        self.assertEqual(self.run_hook(self.pc(self.gw(unlabeled)), refund()), "deny")


if __name__ == "__main__":
    unittest.main()
