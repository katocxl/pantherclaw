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
from collections.abc import Callable, Collection
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
    file's answers), and every wait answered with ``waits[wait]``; a gated
    wait answers only once the face has had ``gate`` requests."""

    def __init__(self, answers: list[str], wait: str = "", gate: int = 0) -> None:
        self.kf = pap.KeyFile.new()
        self.kf.identifier = IDENT
        jkt = self.kf.key().jkt
        self.answers = list(answers)
        w = V["waits"].get(wait, {"stream": "", "long_poll": ""})
        gated = bool(w.get("gated"))
        # (action id, call body) of each /sdk request, in order, and how many waits the server served.
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self.waits = 0
        lock = threading.Lock()
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
                    with lock:
                        gw.requests.append((aid, json.loads(body)))
                        name = gw.answers.pop(0) if gw.answers else ""
                    if not name:
                        self._send(500, b"")
                        return
                    a = V["answers"][name]
                    self._send(a["status"], rewrite(a["body"], aid).encode())
                elif self.path.startswith("/v1/wait/") or self.path == "/pantherclaw.v1.WorkloadService/Wait":
                    with lock:
                        gw.waits += 1
                    end = time.monotonic() + 10
                    while gated and len(gw.requests) < gate and time.monotonic() < end:
                        time.sleep(0.02)
                    if self.path.startswith("/v1/wait/"):
                        self._send(200, w["stream"].encode(), "text/event-stream")
                    else:
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
Adapter = Callable[[Client, str, dict[str, Any], Callable[..., str]], Callable[[Any], str]]

# The members a runner knows: anything else in wrappers.json fails the replay.
_FILE = {"format", "group", "description", "source", "connection", "tool", "sdk_tool", "path", "parameters", "action_id", "codes", "answers",
         "waits", "cases"}
_CASE = {"name", "options", "answers", "wait", "concurrent", "calls"}
_OPTIONS = {"observe_unmapped", "raise_on_refusal", "wait", "on_dispatch"}
_CALL = {"input", "requests", "resumes", "action_id", "ran", "code", "transaction", "refusal", "raises", "dispatched"}
_WAIT = {"stream", "long_poll", "gated"}


def options(case: dict[str, Any], sent: list[tuple[str, Any]]) -> dict[str, Any]:
    """The wrapper's keyword arguments for a case; an on_dispatch handler records into ``sent``."""
    o = case.get("options") or {}
    out: dict[str, Any] = {}
    if o.get("on_dispatch"):
        out["on_dispatch"] = lambda call_id, outbound: sent.append((call_id, outbound)) or "dispatched"
    if "wait" in o:
        out["wait"] = float(o["wait"])
    if o.get("observe_unmapped"):
        out["observe_unmapped"] = True
    if o.get("raise_on_refusal"):
        out["raise_on_refusal"] = True
    return out


def _expect(c: dict[str, Any], drops_unknown: bool) -> dict[str, Any]:
    """A call's expectation. Through a framework that drops undeclared keys
    before the tool is reached (drops_unknown), an undecided_args call is
    decided and run with the declared keys alone: the function never
    receives the others."""
    if drops_unknown and c.get("code") == "undecided_args":
        declared = {k: v for k, v in c["input"].items() if k in V["parameters"]}
        return {"input": declared, "requests": 1, "resumes": 0, "action_id": "new", "ran": True}
    return c


def replay(t: unittest.TestCase, adapter: Adapter, refused: type[Exception], *, raising: bool = True, objects_only: bool = False,
           drops_unknown: bool = False, only: Collection[str] = ()) -> None:
    """Replays the cases of wrappers.json through a wrapper (HR-328, HR-329):
    every case, or those named in ``only``. Without ``raising`` the cases
    that raise are left to another adapter (a framework that retries a tool
    which raised, as CrewAI does); with ``objects_only`` the calls whose input
    is not an object, which a framework's model path cannot make; for
    ``drops_unknown`` see _expect."""
    t.assertEqual(V["group"], "wrappers")
    t.assertLessEqual(set(V), _FILE, "wrappers.json members")
    for w in V["waits"].values():
        t.assertLessEqual(set(w), _WAIT, "wait members")
    names = {case["name"] for case in V["cases"]}
    t.assertLessEqual(set(only), names, "cases named in only")
    for case in V["cases"]:
        t.assertLessEqual(set(case), _CASE, case["name"])
        t.assertLessEqual(set(case.get("options") or {}), _OPTIONS, case["name"])
        for c in case["calls"]:
            t.assertLessEqual(set(c), _CALL, case["name"])
        if only and case["name"] not in only:
            continue
        if not raising and any(c.get("raises") for c in case["calls"]):
            continue
        if objects_only and any(not isinstance(c["input"], dict) for c in case["calls"]):
            continue
        with t.subTest(case=case["name"]):
            _replay_case(t, adapter, refused, case, drops_unknown)


def _replay_case(t: unittest.TestCase, adapter: Adapter, refused: type[Exception], case: dict[str, Any], drops_unknown: bool) -> None:
    calls = [_expect(c, drops_unknown) for c in case["calls"]]
    g = Gateway(case["answers"], case.get("wait", ""), gate=len(calls))
    try:
        ran: list[dict[str, Any]] = []

        def fn(**kwargs: Any) -> str:
            ran.append(kwargs)
            return "refunded"

        sent: list[tuple[str, Any]] = []
        call = adapter(g.client, V["connection"], options(case, sent), fn)
        dispatch = json.loads(V["answers"]["send"]["body"])["dispatch"]

        def make(c: dict[str, Any]) -> tuple[Any, Exception | None]:
            try:
                return call(json.loads(json.dumps(c["input"]))), None
            except refused as e:
                return "", e

        if case.get("concurrent"):
            _concurrent(t, calls, make, g, ran)
            return
        seen: set[str] = set()
        previous = ""
        for i, c in enumerate(calls):
            before, n, dispatched, waits = len(ran), len(g.requests), len(sent), g.waits
            out, raised = make(c)
            reqs = g.requests[n:]
            t.assertEqual(len(reqs), c["requests"], f"call {i}: /sdk requests")
            t.assertEqual(max(c["requests"] - 1, 0), c.get("resumes", 0), f"call {i}: resumes in the vector")
            t.assertGreaterEqual(g.waits - waits, c.get("resumes", 0), f"call {i}: a wait before each resubmission")
            if reqs:
                ids = {aid for aid, _ in reqs}
                t.assertEqual(len(ids), 1, f"call {i}: one action id")
                (aid,) = ids
                t.assertEqual("same" if aid == previous else ("new" if aid not in seen else "earlier"), c["action_id"], f"call {i}: action id")
                previous = aid
                seen.add(aid)
                for _, body in reqs:
                    t.assertEqual((body["tool"], body["server"], body["input"]), (V["sdk_tool"], V["connection"], c["input"]))
            if c["ran"]:
                t.assertIsNone(raised, f"call {i}")
                t.assertEqual(ran[before:], [c["input"]], f"call {i}: the tool ran with the input")
                t.assertEqual(out, "refunded", f"call {i}")
                continue
            t.assertEqual(ran[before:], [], f"call {i}: the tool did not run")
            if c.get("dispatched"):
                t.assertIsNone(raised, f"call {i}")
                ((call_id, o),) = sent[dispatched:]
                t.assertEqual(call_id, reqs[-1][1]["tool_use_id"], f"call {i}: the handler got the call's id")
                t.assertEqual((o.method, o.url, o.body), (dispatch["method"], dispatch["url"], pap.from_b64url(dispatch["body"])))
                t.assertEqual(out, "dispatched", f"call {i}: the handler's result")
                continue
            t.assertEqual(sent[dispatched:], [], f"call {i}: nothing dispatched")
            if c.get("raises"):
                t.assertIsNotNone(raised, f"call {i}: raised")
                t.assertEqual((getattr(raised, "code", ""), str(raised)), (c["code"], c["refusal"]), f"call {i}")
            else:
                t.assertIsNone(raised, f"call {i}")
                t.assertEqual(out, c["refusal"], f"call {i}: the refusal")
    finally:
        g.close()


def _concurrent(t: unittest.TestCase, calls: list[dict[str, Any]], make: Callable[[dict[str, Any]], tuple[Any, Exception | None]],
                g: Gateway, ran: list[dict[str, Any]]) -> None:
    """The calls at once: their outcomes match the expectations in some order."""
    results: list[tuple[Any, Exception | None]] = [("", None)] * len(calls)

    def one(i: int) -> None:
        results[i] = make(calls[i])

    threads = [threading.Thread(target=one, args=(i,)) for i in range(len(calls))]
    for th in threads:
        th.start()
    for th in threads:
        th.join(60)
    t.assertTrue(all(not th.is_alive() for th in threads), "the concurrent calls ended")
    got = sorted("refunded" if out == "refunded" else str(out) for out, _ in results)
    want = sorted("refunded" if c["ran"] else c["refusal"] for c in calls)
    t.assertEqual(got, want, "the outcomes")
    t.assertEqual(len(ran), sum(1 for c in calls if c["ran"]), "the tool ran once per allowed call")
    per_call: dict[str, int] = {}
    for _, body in g.requests:
        per_call[body["tool_use_id"]] = per_call.get(body["tool_use_id"], 0) + 1
    t.assertEqual(sorted(per_call.values()), sorted(c["requests"] for c in calls), "the requests of each call")
    if any(c["action_id"] == "same" for c in calls):
        t.assertEqual(len({aid for aid, _ in g.requests}), 1, "one action id")


def same_copies(t: unittest.TestCase, relative: str) -> None:
    """Each Python wrapper carries the shared files byte for byte."""
    copies = {d: (ROOT / "integrations" / d / "python" / relative.format(pkg=p)).read_bytes()
              for d, p in (("langchain", "pantherclaw_langchain"), ("openai-agents", "pantherclaw_openai_agents"), ("crewai", "pantherclaw_crewai"))}
    t.assertEqual(len(set(copies.values())), 1, f"{relative} differs between the wrappers: keep every copy identical")


def core_adapter(guard: type) -> Adapter:
    """The decision core alone (the package's _guard.Guard), without the framework."""

    def adapter(client: Client, connection: str, opts: dict[str, Any], fn: Callable[..., str]) -> Callable[[Any], str]:
        g = guard(client, connection, **opts)
        params = set(V["parameters"])
        return lambda args: g.finish(g.decide("create_refund", args, None, parameters=params), lambda: fn(**args))

    return adapter
