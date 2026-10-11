# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import hashlib
import io
import json
import threading
import time
import unittest
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pantherclaw import pap
from pantherclaw.check import check_proof
from pantherclaw.client import Client, evaluate, new_action_id, next_step, parse_wait_response, read_stream, retry
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
        self, sdk: SDK, require_nonce: bool = False, expire_first: bool = False, wait: Callable[[BaseHTTPRequestHandler], None] | None = None
    ) -> None:
        self.kf = pap.KeyFile.new()
        self.kf.identifier = IDENT
        self.jkt = self.kf.key().jkt
        self.issued = 0
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
                elif self.path.startswith("/sdk/"):
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
        self.client = Client(self.kf, gateway=base, run_id=RUN, timeout=1.0)

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


def allowed(h: BaseHTTPRequestHandler, _body: bytes) -> None:
    aid = h.headers.get("PC-Action-Id", "")
    digest = hashlib.sha256(json.dumps({"action_id": aid}, separators=(",", ":")).encode()).hexdigest()
    reply(h, 200, json.dumps({"decision": "allow", "action_id": aid, "action_hash": digest, "coverage": "PARTIAL", "mode": "enforce"}).encode())


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
                    r = f.client.authorize("local", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
                    self.assertEqual(r.outcome, "cannot_decide", r.why)
                finally:
                    f.close()
        kf = pap.KeyFile.new()
        kf.identifier, kf.server = IDENT, "http://127.0.0.1:9"
        r = Client(kf, gateway="http://127.0.0.1:9", run_id=RUN, timeout=1.0).authorize("local", "Read", {}, "toolu_02", new_action_id())
        self.assertEqual(r.outcome, "cannot_decide")

    def test_retries_once_for_a_nonce_and_once_for_an_expired_token(self) -> None:
        seen: dict[str, Any] = {}

        def sdk(h: BaseHTTPRequestHandler, body: bytes) -> None:
            seen["call"], seen["path"], seen["action"] = json.loads(body), h.path, h.headers.get("PC-Action-Id")
            allowed(h, body)

        f = Fake(sdk, require_nonce=True, expire_first=True)
        try:
            aid = new_action_id()
            r = f.client.authorize("local", "mcp__payments__create_refund", REFUND, "toolu_01", aid, server="payments")
            self.assertEqual(r.outcome, "allow", r.why)
            want = {"tool": "mcp__payments__create_refund", "server": "payments", "input": REFUND, "tool_use_id": "toolu_01"}
            self.assertEqual((seen["call"], seen["path"], seen["action"], f.issued), (want, "/sdk/local", aid, 2))
        finally:
            f.close()

    def test_HR201_conformance_answers(self) -> None:
        for a in load("sdk_face.json")["answers"]:
            with self.subTest(a["name"]):
                got = retry(a["status"], a.get("headers") or {}) or evaluate(a["status"], a["body"], a["action_id"], a.get("first_hash", "")).outcome
                self.assertEqual(got, a["outcome"])

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


def held_then_allowed(calls: list[int]) -> SDK:
    def sdk(h: BaseHTTPRequestHandler, body: bytes) -> None:
        calls.append(1)
        if len(calls) > 1:
            allowed(h, body)
            return
        aid = h.headers.get("PC-Action-Id", "")
        digest = hashlib.sha256(json.dumps({"action_id": aid}, separators=(",", ":")).encode()).hexdigest()
        a = {"decision": "hold", "action_id": aid, "action_hash": digest, "coverage": "PARTIAL", "mode": "enforce", "wait": {"handle": "h", "state": "PENDING"}}
        reply(h, 200, json.dumps(a).encode())

    return sdk


class WaitTest(unittest.TestCase):
    def test_a_held_call_waits_on_the_stream_and_is_resubmitted_once_ready(self) -> None:
        calls: list[int] = []

        def stream(h: BaseHTTPRequestHandler) -> None:
            reply(h, 200, b'event: state\ndata: {"handle":"h","state":"PENDING"}\n\n: heartbeat\n\nevent: state\ndata: {"handle":"h","state":"READY"}\n\n')

        f = Fake(held_then_allowed(calls), wait=stream)
        try:
            r = f.client.authorize_and_wait("local", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
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
            r = f.client.authorize_and_wait("local", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments")
            self.assertEqual((r.outcome, len(calls), len(polls)), ("deny", 1, 2), r.why)
        finally:
            f.close()

    def test_HR200_a_wait_past_its_deadline_cannot_decide(self) -> None:
        f = Fake(held_then_allowed([]), wait=lambda _h: time.sleep(3))
        try:
            r = f.client.authorize_and_wait("local", "mcp__payments__create_refund", REFUND, "toolu_01", new_action_id(), server="payments", deadline=1.0)
            self.assertEqual(r.outcome, "cannot_decide", r.why)
        finally:
            f.close()


if __name__ == "__main__":
    unittest.main()
