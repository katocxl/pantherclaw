# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import sys
from pathlib import Path

# The core client and this package from the repository, until both are published.
_HERE = Path(__file__).resolve()
sys.path[:0] = [str(_HERE.parents[4] / "sdk" / "python" / "src"), str(_HERE.parents[1] / "src")]

import asyncio  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import unittest  # noqa: E402
from collections.abc import Callable  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402
from types import SimpleNamespace  # noqa: E402
from typing import Any  # noqa: E402

from pantherclaw import pap  # noqa: E402
from pantherclaw.client import Client  # noqa: E402
from pantherclaw_claude_agent_sdk import PantherClaw  # noqa: E402

IDENT = "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005"
RUN = "01920000-0000-7000-8000-000000000003"

Face = Callable[[dict[str, Any], str], tuple[int, bytes] | None]


class Gateway:
    """A PantherClaw server and gateway in one: unsigned tokens, the /sdk
    contract through ``face``, and an SSE wait stream of ``states``."""

    def __init__(self, face: Face, states: tuple[str, ...] = ("READY",)) -> None:
        self.kf = pap.KeyFile.new()
        self.kf.identifier = IDENT
        jkt = self.kf.key().jkt
        self.calls: list[dict[str, Any]] = []
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
                elif self.path == "/sdk/local":
                    call = json.loads(body)
                    gw.calls.append(call)
                    out = face(call, self.headers.get("PC-Action-Id", ""))
                    if out is None:
                        time.sleep(2)
                        return
                    self._send(*out)
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
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.kf.server = base
        self.client = Client(self.kf, gateway=base, run_id=RUN, timeout=1.0)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _hash(aid: str) -> str:
    return hashlib.sha256(json.dumps({"action_id": aid}, separators=(",", ":")).encode()).hexdigest()


def answer(decision: str, **extra: Any) -> Face:
    def face(_call: dict[str, Any], aid: str) -> tuple[int, bytes]:
        a: dict[str, Any] = {"decision": decision, "action_id": aid, "coverage": "PARTIAL", "mode": "enforce"}
        if decision in ("allow", "hold"):
            a["action_hash"] = _hash(aid)
        if decision == "hold":
            a["wait"] = {"handle": "h", "state": "PENDING"}
        a.update(extra)
        return 200, json.dumps(a).encode()

    return face


def hold_then_allow() -> Face:
    n = [0]

    def face(call: dict[str, Any], aid: str) -> tuple[int, bytes]:
        n[0] += 1
        return answer("hold" if n[0] == 1 else "allow")(call, aid)

    return face


OBSERVE: Face = lambda _c, _a: (200, json.dumps({"decision": "allow", "coverage": "OBSERVE_ONLY", "mode": "monitor"}).encode())  # noqa: E731


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

    def gw(self, face: Face, states: tuple[str, ...] = ("READY",)) -> Gateway:
        g = Gateway(face, states)
        self.gateways.append(g)
        return g

    def pc(self, g: Gateway, **kw: Any) -> PantherClaw:
        return PantherClaw(g.client, "local", mcp_servers=["payments"], deadline=1.5, wait=2.0, **kw)

    def run_hook(self, p: PantherClaw, data: dict[str, Any]) -> str:
        return decision(asyncio.run(p.hook(data, data.get("tool_use_id"), None)))

    def test_HR200_the_hook_denies_when_pantherclaw_cannot_decide(self) -> None:
        for name, face in {"a gateway error": lambda _c, _a: (502, b""), "a malformed answer": lambda _c, _a: (200, b"{"),
                           "no answer in time": lambda _c, _a: None}.items():
            with self.subTest(name):
                self.assertEqual(self.run_hook(self.pc(self.gw(face)), refund()), "deny")
        kf = pap.KeyFile.new()
        kf.identifier, kf.server = IDENT, "http://127.0.0.1:9"
        down = PantherClaw(Client(kf, gateway="http://127.0.0.1:9", run_id=RUN, timeout=1.0), "local", mcp_servers=["payments"])
        self.assertEqual(self.run_hook(down, refund()), "deny")
        broken = self.pc(self.gw(answer("allow")))

        async def boom(*_a: Any) -> dict[str, Any]:
            raise RuntimeError("boom")

        broken._decide = boom  # type: ignore[method-assign]
        self.assertEqual(self.run_hook(broken, refund()), "deny")

    def test_HR200_pre_tool_use_decides_in_every_permission_mode(self) -> None:
        for mode in ("default", "acceptEdits", "plan", "bypassPermissions"):
            with self.subTest(mode):
                self.assertEqual(self.run_hook(self.pc(self.gw(answer("deny"))), refund(mode)), "deny")
                self.assertEqual(self.run_hook(self.pc(self.gw(answer("allow"))), refund(mode)), "allow")

    def test_HR200_a_hold_never_runs_without_a_later_allow(self) -> None:
        cases: dict[str, tuple[str, dict[str, Any] | None]] = {
            "no can_use_tool": ("default", None),
            "bypassPermissions": ("bypassPermissions", {"permission_mode": "bypassPermissions"}),
            "dontAsk": ("dontAsk", {"permission_mode": "dontAsk"}),
            "an allow rule": ("default", {"permission_mode": "default", "allowed_tools": ["mcp__payments__create_refund"]}),
        }
        for name, (mode, opts) in cases.items():
            with self.subTest(name):
                p = self.pc(self.gw(hold_then_allow()))
                if opts is not None:
                    p.options(**opts)
                self.assertEqual(self.run_hook(p, refund(mode)), "deny")
        g = self.gw(hold_then_allow())
        opts = self.pc(g).options(permission_mode="default", mcp_servers={"payments": {}})
        hook = opts["hooks"]["PreToolUse"][-1].hooks[0]
        self.assertEqual(decision(asyncio.run(hook(refund("default", "toolu_09"), "toolu_09", None))), "ask")
        ctx = SimpleNamespace(tool_use_id="toolu_09")
        r = asyncio.run(opts["can_use_tool"]("mcp__payments__create_refund", {"amount": "999.00", "charge": "ch_1"}, ctx))
        self.assertEqual((r.behavior, r.updated_input), ("allow", {"amount": "30.00", "charge": "ch_1"}))
        self.assertEqual(len(g.calls), 2)

    def test_HR200_can_use_tool_waits_only_on_holds_and_denies_at_its_deadline(self) -> None:
        g = self.gw(hold_then_allow(), states=("PENDING",))

        async def app(_name: str, _input: dict[str, Any], _ctx: Any) -> Any:
            return SimpleNamespace(behavior="deny", message="the application's own answer")

        p = PantherClaw(g.client, "local", mcp_servers=["payments"], deadline=1.5, wait=0.5)
        opts = p.options(permission_mode="default", can_use_tool=app)
        other = asyncio.run(opts["can_use_tool"]("Write", {"file_path": "x"}, SimpleNamespace(tool_use_id="toolu_other")))
        self.assertEqual(other.message, "the application's own answer")
        self.assertEqual(self.run_hook(p, refund("default", "toolu_10")), "ask")
        r = asyncio.run(opts["can_use_tool"]("mcp__payments__create_refund", {}, SimpleNamespace(tool_use_id="toolu_10")))
        self.assertEqual(r.behavior, "deny")

    def test_callers_must_pass_permission_mode(self) -> None:
        with self.assertRaises(ValueError):
            self.pc(self.gw(answer("allow"))).options()

    def test_shell_tools_send_their_working_directory(self) -> None:
        g = self.gw(answer("allow"))
        data = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "toolu_11", "cwd": "/repo"}
        self.assertEqual(self.run_hook(self.pc(g), data), "allow")
        self.assertEqual(g.calls[0], {"tool": "Bash", "input": {"command": "ls"}, "tool_use_id": "toolu_11", "cwd": "/repo"})

    def test_unmapped_built_ins_are_observed_and_other_tools_denied(self) -> None:
        read = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}, "tool_use_id": "toolu_12"}
        self.assertEqual(self.run_hook(self.pc(self.gw(OBSERVE)), read), "none")
        unmapped = answer("deny", code="unknown_tool")
        self.assertEqual(self.run_hook(self.pc(self.gw(unmapped)), refund()), "deny")
        self.assertEqual(self.run_hook(self.pc(self.gw(unmapped), observe_unmapped=True), refund()), "none")
        other = {"hook_event_name": "PreToolUse", "tool_name": "mcp__unknown__run", "tool_input": {}, "tool_use_id": "toolu_13"}
        self.assertEqual(self.run_hook(self.pc(self.gw(unmapped)), other), "deny")

    def test_T080_a_forged_answer_never_runs_the_tool(self) -> None:
        forged = answer("allow", action_hash=_hash("another action"), action_ir=pap.b64url(b"{}"))
        self.assertEqual(self.run_hook(self.pc(self.gw(forged)), refund()), "deny")
        unlabeled = answer("allow", coverage="")
        self.assertEqual(self.run_hook(self.pc(self.gw(unlabeled)), refund()), "deny")


if __name__ == "__main__":
    unittest.main()
