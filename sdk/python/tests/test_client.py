# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import hashlib
import io
import json
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pantherclaw import pap
from pantherclaw.check import check_proof
from pantherclaw.client import Client, classify, evaluate, new_action_id, next_step, parse_wait_response, read_stream, retry
from vectors import load

RUN = "01920000-0000-7000-8000-000000000003"
NONCE = "Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ"
IDENT = "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005"
REFUND = {"amount": "30.00", "charge": "ch_1"}

SDK = Callable[[BaseHTTPRequestHandler, bytes], None]


class Fake:
    """A PantherClaw server and gateway in one: unsigned tokens (the client
    never verifies them), every proof checked with the SDK's checker."""

    def __init__(
        self, sdk: SDK, require_nonce: bool = False, expire_first: bool = False, wait: Callable[[BaseHTTPRequestHandler], None] | None = None,
        hook: SDK | None = None, builtins: tuple[str, ...] = ("Bash", "Read"),
    ) -> None:
        self.kf = pap.KeyFile.new()
        self.kf.identifier = IDENT
        self.jkt = self.kf.key().jkt
        self.issued = 0
        self.calls = 0
        self.expire_first = expire_first
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                self.do_POST()

            def do_POST(self) -> None:
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                auth = self.headers.get("Authorization", "")
                tok = auth[4:] if auth.startswith("PAP ") else ""
                url = f"http://127.0.0.1:{fake.server.server_address[1]}{self.path}"
                answer = check_proof(self.headers.get("PAP-Proof", ""), self.command, url, body, token=tok, now=int(time.time()))
                if answer == "use_nonce" and not require_nonce:
                    answer = "ok"
                if answer != "ok":
                    self.send_response(401)
                    self.send_header("PAP-Error", answer)
                    self.send_header("PAP-Nonce", NONCE)
                    self.end_headers()
                    return
                if self.path == "/pantherclaw.v1.WorkloadService/IssueToken":
                    assert tok == "", "token issuance uses a key-only proof"
                    fake.issued += 1
                    self._json({"workloadToken": fake.token(), "attestationLevel": 1})
                elif self.path.startswith("/hook/") and hook is not None:
                    hook(self, body)
                elif self.path.startswith("/sdk/"):
                    fake.calls += 1
                    if fake.expire_first:
                        fake.expire_first = False
                        self.send_response(401)
                        self.send_header("PAP-Error", "token_expired")
                        self.end_headers()
                        return
                    sdk(self, body)
                elif wait is not None and (self.path.startswith("/v1/wait/") or self.path == "/pantherclaw.v1.WorkloadService/Wait"):
                    wait(self)
                else:
                    self.send_response(404)
                    self.end_headers()

            def _json(self, v: Any) -> None:
                b = json.dumps(v).encode()
                self.send_response(200)
                self.send_header("PAP-Nonce", NONCE)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.kf.server = base
        self.client = Client(self.kf, gateway=base, run_id=RUN, timeout=1.0, builtins=builtins)

    def token(self) -> str:
        now = int(time.time())
        claims = {"iss": "x", "sub": IDENT, "aud": "pantherclaw-gateway", "iat": now, "nbf": now, "exp": now + 600, "jti": "j",
                  "cnf": {"jkt": self.jkt}, "pap": {"v": 1, "org": "o", "env": "e", "att_lvl": 1}}
        return pap.b64url(b'{"alg":"EdDSA","kid":"k","typ":"pap-wt+jwt"}') + "." + pap.b64url(json.dumps(claims).encode()) + ".c2ln"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def reply(h: BaseHTTPRequestHandler, status: int, body: bytes) -> None:
    h.send_response(status)
    h.send_header("Content-Length", str(len(body)))
    h.end_headers()
    h.wfile.write(body)


_SDK_ACTION = next(c["canonical"] for c in load("actionir.json")["cases"] if c["name"] == "sdk channel through a connection")


def decided(h: BaseHTTPRequestHandler, decision: str, **extra: Any) -> None:
    """Answers ``decision`` for the request's action id with the canonical
    sdk-channel action and its hash, as the face does."""
    aid = h.headers.get("PC-Action-Id", "")
    act = _SDK_ACTION.replace('"action_id":"01920000-0000-7000-8000-000000000004"', f'"action_id":"{aid}"')
    a = {"decision": decision, "action_id": aid, "action_hash": hashlib.sha256(act.encode()).hexdigest(), "action_ir": pap.b64url(act.encode()),
         "coverage": "PARTIAL", "mode": "enforce", **extra}
    reply(h, 200, json.dumps(a).encode())


def allowed(h: BaseHTTPRequestHandler, _body: bytes) -> None:
    decided(h, "allow")


class ClientTest(unittest.TestCase):
    def test_HR200_fails_closed_when_pantherclaw_cannot_decide(self) -> None:
        answers: dict[str, SDK] = {
            "a gateway error": lambda h, _b: reply(h, 502, b""),
            "not JSON": lambda h, _b: reply(h, 200, b"<html>"),
            "an empty body": lambda h, _b: reply(h, 200, b""),
            "too slow": lambda h, _b: time.sleep(1.5),
        }
        for name, sdk in answers.items():
            with self.subTest(name):
                f = Fake(sdk)
                try:
                    r = f.client.authorize("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
                    self.assertEqual(r.outcome, "cannot_decide", r.why)
                finally:
                    f.close()
        kf = pap.KeyFile.new()
        kf.identifier, kf.server = IDENT, "http://127.0.0.1:9"
        r = Client(kf, gateway="http://127.0.0.1:9", run_id=RUN, timeout=1.0).authorize("payments", "Read", {}, "toolu_02", new_action_id())
        self.assertEqual(r.outcome, "cannot_decide")

    def test_retries_once_for_a_nonce_and_once_for_an_expired_token(self) -> None:
        seen: dict[str, Any] = {}

        def sdk(h: BaseHTTPRequestHandler, body: bytes) -> None:
            seen["call"], seen["path"], seen["action"] = json.loads(body), h.path, h.headers.get("PC-Action-Id")
            allowed(h, body)

        f = Fake(sdk, require_nonce=True, expire_first=True)
        try:
            aid = new_action_id()
            r = f.client.authorize("payments", "mcp__payments__create_refund", REFUND, "toolu_01", aid, server="payments")
            self.assertEqual(r.outcome, "allow", r.why)
            want = {"tool": "mcp__payments__create_refund", "server": "payments", "input": REFUND, "tool_use_id": "toolu_01"}
            self.assertEqual((seen["call"], seen["path"], seen["action"], f.issued), (want, "/sdk/payments", aid, 2))
        finally:
            f.close()

    def test_HR201_conformance_answers(self) -> None:
        for a in load("sdk_face.json")["answers"]:
            with self.subTest(a["name"]):
                r = evaluate(a["status"], a["body"], a["class"], a["action_id"], a.get("first_hash", ""))
                got = retry(a["status"], a.get("headers") or {}) or r.outcome
                self.assertEqual(got, a["outcome"], r.why)
                if "send" not in a:
                    self.assertIsNone(r.send)
                    continue
                assert r.send is not None
                self.assertEqual((r.send.method, r.send.url, r.send.headers, r.send.body),
                                 (a["send"]["method"], a["send"]["url"], a["send"]["headers"], a["send"]["body"].encode()))

    def test_HR200_conformance_calls(self) -> None:
        """An MCP tool goes to the connection named after its server, a
        built-in to the connection given, and other names are never sent."""
        f = load("sdk_face.json")
        got: list[tuple[str, Any]] = []

        def record(h: BaseHTTPRequestHandler, body: bytes) -> None:
            got.append((h.path, json.loads(body)))
            reply(h, 200, json.dumps({"decision": "deny", "reason": "recorded", "mode": "enforce", "coverage": "PARTIAL"}).encode())

        fake = Fake(record, builtins=tuple(f["builtins"]))
        try:
            for c in f["calls"]:
                with self.subTest(c["name"]):
                    cls, server = classify(c["tool"], f["servers"], f["builtins"])
                    self.assertEqual(cls, c["class"])
                    got.clear()
                    r = fake.client.authorize(f["connection"], c["tool"], c["input"], c["tool_use_id"], new_action_id(), server=server)
                    if cls == "refused":
                        self.assertEqual((got, r.outcome), ([], "cannot_decide"))
                        continue
                    self.assertEqual(got, [(c["path"], c["body"])])
        finally:
            fake.close()

    def test_HR200_a_server_named_like_no_connection_is_never_sent(self) -> None:
        f = Fake(lambda h, _b: reply(h, 200, json.dumps({"decision": "allow", "mode": "monitor", "coverage": "OBSERVE_ONLY"}).encode()))
        try:
            for server in ("git__hub", "Payments", "-payments", "pay%2fments"):
                r = f.client.authorize("payments", f"mcp__{server}__create_refund", {}, "toolu_01", new_action_id(), server=server)
                self.assertEqual(r.outcome, "cannot_decide", server)
            for connection in ("Payments", "pay/ments", "", "payments-"):
                r = f.client.authorize(connection, "Read", {"file_path": "/etc/hosts"}, "toolu_02", new_action_id())
                self.assertEqual(r.outcome, "cannot_decide", f"a built-in recorded at {connection!r}")
            self.assertEqual(f.calls, 0)
        finally:
            f.close()

    def test_HR200_an_observe_answer_lets_only_a_configured_built_in_run(self) -> None:
        f = Fake(lambda h, _b: reply(h, 200, json.dumps({"decision": "allow", "mode": "monitor", "coverage": "OBSERVE_ONLY"}).encode()))
        try:
            self.assertEqual(f.client.authorize("payments", "Read", {"file_path": "/etc/hosts"}, "toolu_02", new_action_id()).outcome, "observe")
            self.assertEqual(f.client.authorize("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments").outcome,
                             "cannot_decide")
            sent = f.calls
            for tool in ("deploy", "bash", "mcp__payments__create_refund"):
                self.assertEqual(f.client.authorize("payments", tool, {}, "toolu_03", new_action_id()).outcome, "cannot_decide", tool)
            self.assertEqual(f.calls, sent)
        finally:
            f.close()

    def test_the_client_refuses_plain_http_outside_loopback(self) -> None:
        kf = pap.KeyFile.new()
        kf.identifier = IDENT
        for u in ("http://pantherclaw.example.test", "http://10.0.0.1:8443", "https://user@pantherclaw.example.test", "ftp://x"):
            with self.assertRaises(ValueError):
                Client(kf, server="https://pantherclaw.example.test", gateway=u)
            with self.assertRaises(ValueError):
                Client(kf, server=u)
        for u in ("https://pantherclaw.example.test", "http://127.0.0.1:8080", "http://[::1]:8080", "http://localhost:8080"):
            Client(kf, server=u, gateway=u)

    def test_a_shell_command_goes_to_the_hook_face_and_a_hold_there_is_a_deny(self) -> None:
        seen: dict[str, Any] = {"held": False}

        def hook(h: BaseHTTPRequestHandler, body: bytes) -> None:
            seen["path"], seen["body"], seen["run"] = h.path, body, h.headers.get("PAP-Run-Id")
            a = {"decision": "deny", "held": True, "transaction_id": "t", "mode": "enforce"} if seen["held"] else {"decision": "allow", "mode": "enforce"}
            reply(h, 200, json.dumps(a).encode())

        f = Fake(lambda h, _b: reply(h, 404, b""), hook=hook)
        try:
            self.assertEqual(f.client.hook("local", "bash", "git push", "/repo", "toolu_04").outcome, "allow")
            self.assertEqual((seen["path"], seen["run"]), ("/hook/local", RUN))
            self.assertEqual(seen["body"], b'{"input":{"call":"toolu_04","command":"git push","cwd":"/repo","shell":"bash"},"tool":"shell"}')
            seen["held"] = True
            r = f.client.hook("local", "bash", "git push", "/repo", "toolu_04")
            self.assertEqual((r.outcome, r.held), ("deny", True))
        finally:
            f.close()
        down = Fake(lambda h, _b: reply(h, 404, b""), hook=lambda h, _b: reply(h, 502, b""))
        try:
            self.assertEqual(down.client.hook("local", "bash", "ls", "/repo", "toolu_05").outcome, "cannot_decide")
        finally:
            down.close()

    def test_a_wait_event_whose_data_never_ends_is_refused(self) -> None:
        stream = io.BytesIO(b"event: state\n" + (b"data: " + b"x" * 1000 + b"\n") * 100)
        with self.assertRaises(ValueError):
            read_stream(iter(stream.readline, b""), lambda _w: True)

    def test_conformance_exchanges(self) -> None:
        for e in load("sdk_face.json")["exchanges"]:
            with self.subTest(e["name"]):
                states: list[str] = []
                got = retry(e["status"], e.get("headers") or {})
                if got:
                    pass
                elif e["outcome"] == "token":
                    t = json.loads(e["body"])
                    self.assertEqual(t["workloadToken"], e["token"])
                    got = "token"
                elif e["path"].startswith("/v1/wait/"):
                    result: list[str] = []

                    def fn(w: dict[str, Any]) -> bool:
                        states.append(w["state"])
                        result[:] = [next_step(w)]
                        return True

                    read_stream(iter(io.BytesIO(e["body"].encode()).readline, b""), fn)
                    got = result[0]
                else:
                    state, _ = parse_wait_response(e["body"])
                    states, got = [state["state"]], next_step(state)
                self.assertEqual(got, e["outcome"])
                self.assertEqual(states, e.get("states", []))


def held_then_allowed(calls: list[int], deadline: datetime | None = None) -> SDK:
    if deadline is None:
        deadline = datetime.now(timezone.utc) + timedelta(hours=1)

    def sdk(h: BaseHTTPRequestHandler, body: bytes) -> None:
        calls.append(1)
        if len(calls) > 1:
            allowed(h, body)
            return
        decided(h, "hold", wait={"handle": "h", "state": "PENDING", "deadline": deadline.strftime("%Y-%m-%dT%H:%M:%SZ")})

    return sdk


class WaitTest(unittest.TestCase):
    def test_a_held_call_waits_on_the_stream_and_is_resubmitted_once_ready(self) -> None:
        calls: list[int] = []

        def stream(h: BaseHTTPRequestHandler) -> None:
            reply(h, 200, b'event: state\ndata: {"handle":"h","state":"PENDING"}\n\n: heartbeat\n\nevent: state\ndata: {"handle":"h","state":"READY"}\n\n')

        f = Fake(held_then_allowed(calls), wait=stream)
        try:
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
            self.assertEqual((r.outcome, len(calls)), ("allow", 2), r.why)
        finally:
            f.close()

    def test_without_the_stream_the_client_long_polls_and_a_declined_hold_denies(self) -> None:
        calls: list[int] = []
        polls: list[int] = []

        def wait(h: BaseHTTPRequestHandler) -> None:
            if h.command == "GET":
                reply(h, 404, b"")
                return
            polls.append(1)
            state = "WAIT_STATE_DECLINED" if len(polls) > 1 else "WAIT_STATE_PENDING"
            reply(h, 200, json.dumps({"wait": {"handle": "h", "state": state, "code": "APPROVAL_DECLINED"}, "timedOut": len(polls) == 1}).encode())

        f = Fake(held_then_allowed(calls), wait=wait)
        try:
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
            self.assertEqual((r.outcome, len(calls), len(polls)), ("deny", 1, 2), r.why)
        finally:
            f.close()

    def test_HR200_a_stream_that_falls_silent_ends_at_the_deadline_not_at_its_open_timeout(self) -> None:
        def stream(h: BaseHTTPRequestHandler) -> None:
            h.send_response(200)
            h.send_header("Content-Type", "text/event-stream")
            h.end_headers()
            try:
                for _ in range(4):
                    h.wfile.write(b": heartbeat\n\n")
                    h.wfile.flush()
                    time.sleep(0.5)
                time.sleep(5)
            except OSError:
                pass

        f = Fake(held_then_allowed([]), wait=stream)
        try:
            start = time.monotonic()
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments", deadline=2.5)
            self.assertEqual(r.outcome, "cannot_decide", r.why)
            self.assertLess(time.monotonic() - start, 3.5)
        finally:
            f.close()

    def test_HR200_a_stream_of_heartbeats_ends_at_the_deadline(self) -> None:
        def stream(h: BaseHTTPRequestHandler) -> None:
            h.send_response(200)
            h.send_header("Content-Type", "text/event-stream")
            h.end_headers()
            try:
                for _ in range(100):
                    h.wfile.write(b": heartbeat\n\n")
                    h.wfile.flush()
                    time.sleep(0.1)
            except OSError:
                pass

        f = Fake(held_then_allowed([]), wait=stream)
        try:
            start = time.monotonic()
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments", deadline=1.0)
            self.assertEqual(r.outcome, "cannot_decide", r.why)
            self.assertLess(time.monotonic() - start, 3.0)
        finally:
            f.close()

    def test_HR200_a_wait_ends_at_the_holds_own_deadline(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(seconds=4)
        f = Fake(held_then_allowed([], deadline=past), wait=lambda _h: time.sleep(5))
        try:
            start = time.monotonic()
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments", deadline=60.0)
            self.assertEqual(r.outcome, "cannot_decide", r.why)
            self.assertLess(time.monotonic() - start, 4.0)
        finally:
            f.close()

    def test_HR200_resubmissions_are_bounded(self) -> None:
        calls: list[int] = []

        def sdk(h: BaseHTTPRequestHandler, _b: bytes) -> None:
            calls.append(1)
            decided(h, "hold", wait={"handle": "h", "state": "PENDING"})

        f = Fake(sdk, wait=lambda h: reply(h, 200, b'event: state\ndata: {"handle":"h","state":"READY"}\n\n'))
        try:
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
            self.assertEqual((r.outcome, len(calls)), ("cannot_decide", 4), r.why)
        finally:
            f.close()

    def test_HR200_a_wait_past_its_deadline_cannot_decide(self) -> None:
        f = Fake(held_then_allowed([]), wait=lambda _h: time.sleep(3))
        try:
            r = f.client.authorize_and_wait("payments", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments", deadline=1.0)
            self.assertEqual(r.outcome, "cannot_decide", r.why)
        finally:
            f.close()


if __name__ == "__main__":
    unittest.main()
