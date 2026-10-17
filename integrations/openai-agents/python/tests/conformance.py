# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The wrapper conformance runner (sdk/conformance/wrappers.json), shared byte
for byte by every Python framework wrapper's tests: a fake PantherClaw
server and gateway, and the replay of every case through a wrapper."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
import unittest
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
_SRC = [str(ROOT / "sdk" / "python" / "src"), str(Path(__file__).resolve().parents[1] / "src")]
sys.path[:0] = [p for p in _SRC if p not in sys.path]

from pantherclaw import pap  # noqa: E402
from pantherclaw.client import Client  # noqa: E402

IDENT = "pc:org/01920000-0000-7000-8000-000000000001/agent/01920000-0000-7000-8000-000000000006/inst/01920000-0000-7000-8000-000000000005"
RUN = "01920000-0000-7000-8000-000000000003"


def vectors(name: str = "wrappers.json") -> dict[str, Any]:
    return json.loads((ROOT / "sdk" / "conformance" / name).read_text(encoding="utf-8"))


V = vectors()


def rewrite(body: str, action_id: str) -> str:
    """An answer made for the file's action id, for the one the wrapper sent."""
    try:
        a = json.loads(body)
    except ValueError:
        return body
    if not isinstance(a, dict):
        return body
    if "action_id" in a:
        a["action_id"] = action_id
    if a.get("action_ir"):
        old = pap.from_b64url(a["action_ir"])
        new = old.replace(V["action_id"].encode(), action_id.encode())
        if a.get("action_hash") == hashlib.sha256(old).hexdigest():
            a["action_hash"] = hashlib.sha256(new).hexdigest()
        a["action_ir"] = pap.b64url(new)
    return json.dumps(a)


class Gateway:
    """A PantherClaw server and gateway in one: unsigned tokens for the
    client's key, the /sdk face answering ``answers`` in order (names of the
    file's answers), and every wait answered with ``waits[wait]``."""

    def __init__(self, answers: list[str], wait: str = "") -> None:
        self.kf = pap.KeyFile.new()
        self.kf.identifier = IDENT
        jkt = self.kf.key().jkt
        self.answers = list(answers)
        w = V["waits"].get(wait, {"stream": "", "long_poll": ""})
        # (action id, call body) of each /sdk request, in order.
        self.requests: list[tuple[str, dict[str, Any]]] = []
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
                    tok = pap.b64url(b'{"alg":"EdDSA"}') + "." + pap.b64url(json.dumps(claims).encode()) + "." + pap.b64url(b"sig")
                    self._send(200, json.dumps({"workloadToken": tok}).encode())
                elif self.path == V["path"]:
                    aid = self.headers.get("PC-Action-Id", "")
                    gw.requests.append((aid, json.loads(body)))
                    if not gw.answers:
                        self._send(500, b"")
                        return
                    a = V["answers"][gw.answers.pop(0)]
                    self._send(a["status"], rewrite(a["body"], aid).encode())
                elif self.path.startswith("/v1/wait/"):
                    self._send(200, w["stream"].encode(), "text/event-stream")
                elif self.path == "/pantherclaw.v1.WorkloadService/Wait":
                    time.sleep(0.05)
                    self._send(200, w["long_poll"].encode())
                else:
                    self._send(404, b"")

            def _send(self, status: int, b: bytes, ctype: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.kf.server = self.base
        self.client = Client(self.kf, gateway=self.base, run_id=RUN, timeout=3.0)

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# A wrapper adapter: given the client, the connection, the case's options
# (wrapper keyword arguments) and the tool's own function, returns a function
# that makes one call of the wrapped tool with an input and returns what the
# model reads (a string), raising whatever the wrapper raises.
Adapter = Callable[[Client, str, dict[str, Any], Callable[..., str]], Callable[[dict[str, Any]], str]]


def options(case: dict[str, Any]) -> dict[str, Any]:
    o = case.get("options") or {}
    out: dict[str, Any] = {}
    if "wait" in o:
        out["wait"] = float(o["wait"])
    if o.get("observe_unmapped"):
        out["observe_unmapped"] = True
    if o.get("raise_on_refusal"):
        out["raise_on_refusal"] = True
    return out


def replay(t: unittest.TestCase, adapter: Adapter, refused: type[Exception], raising: bool = True) -> None:
    """Replays every case of wrappers.json through a wrapper (HR-328, HR-329);
    without ``raising``, the cases that raise are left to another adapter (a
    framework that retries a tool which raised, as CrewAI does)."""
    t.assertEqual(V["group"], "wrappers")
    for case in V["cases"]:
        if not raising and any(c.get("raises") for c in case["calls"]):
            continue
        with t.subTest(case=case["name"]):
            g = Gateway(case["answers"], case.get("wait", ""))
            try:
                ran: list[dict[str, Any]] = []

                def fn(**kwargs: Any) -> str:
                    ran.append(kwargs)
                    return "refunded"

                call = adapter(g.client, V["connection"], options(case), fn)
                previous = ""
                for i, c in enumerate(case["calls"]):
                    before, n = len(ran), len(g.requests)
                    try:
                        out, raised = call(json.loads(json.dumps(c["input"]))), None
                    except refused as e:
                        out, raised = "", e
                    reqs = g.requests[n:]
                    t.assertEqual(len(reqs), c["requests"], f"call {i}: /sdk requests")
                    ids = {aid for aid, _ in reqs}
                    t.assertEqual(len(ids), 1, f"call {i}: one action id")
                    (aid,) = ids
                    t.assertEqual("same" if aid == previous else "new", c["action_id"], f"call {i}: action id")
                    previous = aid
                    for _, body in reqs:
                        t.assertEqual((body["tool"], body["server"], body["input"]), (V["sdk_tool"], V["connection"], c["input"]))
                    if c["ran"]:
                        t.assertIsNone(raised, f"call {i}")
                        t.assertEqual(ran[before:], [c["input"]], f"call {i}: the tool ran with the input")
                        t.assertEqual(out, "refunded", f"call {i}")
                        continue
                    t.assertEqual(ran[before:], [], f"call {i}: the tool did not run")
                    if c.get("raises"):
                        t.assertIsNotNone(raised, f"call {i}: raised")
                        t.assertEqual((getattr(raised, "code", ""), str(raised)), (c["code"], c["refusal"]), f"call {i}")
                    else:
                        t.assertIsNone(raised, f"call {i}")
                        t.assertEqual(out, c["refusal"], f"call {i}: the refusal")
            finally:
                g.close()


def same_copies(t: unittest.TestCase, relative: str) -> None:
    """Each Python wrapper carries the shared files byte for byte."""
    copies = {d: (ROOT / "integrations" / d / "python" / relative.format(pkg=p)).read_bytes()
              for d, p in (("langchain", "pantherclaw_langchain"), ("openai-agents", "pantherclaw_openai_agents"), ("crewai", "pantherclaw_crewai"))}
    t.assertEqual(len(set(copies.values())), 1, f"{relative} differs between the wrappers: keep every copy identical")


def core_adapter(guard: type) -> Adapter:
    """The decision core alone (the package's _guard.Guard), without the framework."""

    def adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[dict[str, Any]], str]:
        g = guard(client, connection, **opts)
        return lambda args: g.finish(g.decide("create_refund", args, None), lambda: fn(**args))

    return adapter
