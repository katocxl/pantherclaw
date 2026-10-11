# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The PantherClaw workload client (PAP/1): a proof over every request, the
servers' nonces, workload token renewal, the gateway's /sdk face and waits on
held calls. It fails closed (HR-200): when PantherClaw cannot decide, the
outcome is "cannot_decide", never "allow"."""

from __future__ import annotations

import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

from . import pap
from .action import ActionError, parse_action

__all__ = ["Client", "Result", "evaluate", "new_action_id", "next_step", "parse_wait_response", "read_stream", "retry"]

CONNECT = {"Content-Type": "application/json", "Connect-Protocol-Version": "1"}
_HEX = re.compile(r"^[0-9a-f]{64}\Z")


@dataclass
class Result:
    """What the agent may do with a call: only "allow", and "observe" for an
    unmapped built-in tool, let it run."""

    outcome: str
    why: str = ""
    answer: dict[str, Any] = field(default_factory=dict)


def _cannot(why: str) -> Result:
    return Result("cannot_decide", why)


def retry(status: int, headers: dict[str, str]) -> str:
    """The one retry a 401 allows: "retry_nonce" (with its fresh nonce) or
    "refresh_token" (with a renewed token); "" otherwise."""
    h = {k.lower(): v for k, v in headers.items()}
    if status != 401:
        return ""
    code = h.get(pap.HEADER_ERROR.lower(), "")
    if code == "use_nonce" and h.get(pap.HEADER_NONCE.lower()):
        return "retry_nonce"
    if code in ("token_expired", "invalid_token"):
        return "refresh_token"
    return ""


def _check_action(a: dict[str, Any], action_id: str, first_hash: str) -> str:
    if a.get("coverage") != "PARTIAL":
        return "a decided call that is not labeled PARTIAL"
    if a.get("action_id") != action_id:
        return "the answer is for another action"
    if not isinstance(a.get("action_hash"), str) or not _HEX.match(a["action_hash"]):
        return "the answer has no action hash"
    if first_hash and a["action_hash"] != first_hash:
        return "the resubmitted call mapped to another action"
    if not a.get("action_ir"):
        return ""
    try:
        p = parse_action(pap.from_b64url(a["action_ir"]))
    except (ActionError, ValueError):
        return "the canonical action is not valid ActionIR"
    if p.hash != a["action_hash"]:
        return "the action hash does not match the action"
    if p.action.get("action_id") != action_id:
        return "the mapped action is for another action id"
    return ""


def evaluate(status: int, body: bytes | str, action_id: str, first_hash: str = "") -> Result:
    """Reads a /sdk answer for the action id the SDK sent; ``first_hash`` is
    the hash of an earlier answer for the same action. Anything it cannot
    read or check is cannot_decide (HR-200, HR-201)."""
    if status != 200:
        return _cannot(f"the gateway answered HTTP {status}")
    try:
        a = json.loads(body)
    except ValueError:
        return _cannot("the gateway's answer is not readable")
    if not isinstance(a, dict):
        return _cannot("the gateway's answer is not readable")
    r = Result("deny", str(a.get("reason", "")), a)
    decision = a.get("decision")
    if decision == "deny":
        return r
    if decision == "allow":
        if a.get("coverage") == "OBSERVE_ONLY":
            if a.get("mode") != "monitor" or a.get("action_hash"):
                return _cannot("an observed call that is not only recorded")
            r.outcome = "observe"
            return r
        r.outcome = "allow"
    elif decision == "hold":
        if not isinstance(a.get("wait"), dict) or not a["wait"].get("handle"):
            return _cannot("a hold without a wait handle")
        r.outcome = "hold"
    else:
        return _cannot(f"unknown decision {decision}")
    problem = _check_action(a, action_id, first_hash)
    return _cannot(problem) if problem else r


def new_action_id() -> str:
    """A fresh UUIDv7 for one logical tool call; send it for every retry and resubmission."""
    b = bytearray(int(time.time() * 1000).to_bytes(6, "big") + secrets.token_bytes(10))
    b[6] = (b[6] & 0x0F) | 0x70
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def next_step(state: dict[str, Any]) -> str:
    """What a wait state asks: "wait", "resubmit" the identical call, or "deny"."""
    s = state.get("state")
    if s in ("PENDING", "EVIDENCE_REQUESTED"):
        return "wait"
    if s in ("READY", "CONSUMED"):
        return "resubmit"
    return "deny"


def parse_wait_response(body: bytes | str) -> tuple[dict[str, Any], bool]:
    """Reads a WorkloadService.Wait answer (Connect JSON)."""
    r = json.loads(body)
    w = r.get("wait") if isinstance(r, dict) else None
    if not isinstance(w, dict):
        raise ValueError("no wait state")
    state = {
        "handle": w.get("handle", ""),
        "state": str(w.get("state", "")).removeprefix("WAIT_STATE_"),
        "code": w.get("code", ""),
        "deadline": w.get("deadlineTime", ""),
        "consume_by": w.get("consumeByTime", ""),
        "approval_request_id": w.get("approvalRequestId", ""),
        "retry_after_seconds": w.get("retryAfterSeconds", 0),
    }
    return state, bool(r.get("timedOut"))


def read_stream(lines: Iterator[bytes], fn: Callable[[dict[str, Any]], bool]) -> None:
    """Reads an SSE wait stream line by line, calling ``fn`` for every state
    event until it returns False or the stream ends."""
    event, data = "", ""
    for raw in lines:
        line = raw.decode("utf-8").rstrip("\r\n")
        if line == "":
            if event == "state" and data and not fn(json.loads(data)):
                return
            event, data = "", ""
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data += line[5:].removeprefix(" ")


@dataclass
class _Sent:
    status: int
    headers: dict[str, str]
    body: bytes
    stream: Any = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class Client:
    """A PAP/1 workload client. It is safe to share between threads."""

    def __init__(self, key_file: pap.KeyFile, gateway: str = "", server: str = "", run_id: str = "", timeout: float = 15.0) -> None:
        if not key_file.identifier:
            raise ValueError("the key file has no identifier: enroll the workload first")
        self._server = (server or key_file.server).rstrip("/")
        if not self._server:
            raise ValueError("the PantherClaw server URL is required")
        self._kf, self._key = key_file, key_file.key()
        self._gateway, self._run = gateway.rstrip("/"), run_id or key_file.run_id
        self._timeout = timeout
        self._token, self._expiry = "", 0
        self._nonces: dict[str, str] = {}
        self._lock = threading.Lock()
        self._opener = urllib.request.build_opener(_NoRedirect)

    def workload_token(self, force: bool = False) -> str:
        """A workload token valid for at least another minute, renewed at the server when needed."""
        with self._lock:
            if not force and self._token and time.time() + 60 < self._expiry:
                return self._token
        body = json.dumps({"identifier": self._kf.identifier}, separators=(",", ":")).encode()
        res = self._send("POST", self._server + "/pantherclaw.v1.WorkloadService/IssueToken", body, CONNECT, True, 0)
        if res.status != 200:
            raise RuntimeError(f"token issuance: HTTP {res.status} {res.headers.get(pap.HEADER_ERROR.lower(), '')}")
        token = str(json.loads(res.body).get("workloadToken", ""))
        claims = pap.parse_token_claims(token)
        if claims["cnf"]["jkt"] != self._key.jkt:
            raise RuntimeError("the server issued a token for another key")
        with self._lock:
            self._token, self._expiry = token, int(claims["exp"])
        return token

    def _do(self, method: str, url: str, body: bytes, headers: dict[str, str], extra: float = 0) -> _Sent:
        res = self._send(method, url, body, headers, False, extra)
        if retry(res.status, res.headers) != "refresh_token":
            return res
        self.workload_token(force=True)
        return self._send(method, url, body, headers, False, extra)

    def _send(self, method: str, url: str, body: bytes, headers: dict[str, str], key_only: bool, extra: float) -> _Sent:
        stream = headers.get("Accept") == "text/event-stream"
        origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(url))
        for attempt in range(2):
            token = "" if key_only else self.workload_token()
            with self._lock:
                nonce = self._nonces.get(origin, "")
            proof = pap.sign_proof(self._key, method, url, body, token=token, nonce=nonce)
            h = dict(headers) | {pap.HEADER_PROOF: proof}
            if token:
                h["Authorization"] = "PAP " + token
            req = urllib.request.Request(url, data=None if method == "GET" else body, method=method, headers=h)
            try:
                res = self._opener.open(req, timeout=extra if stream else self._timeout + extra)  # noqa: S310 - configured URLs
            except urllib.error.HTTPError as e:
                res = e
            got = {k.lower(): v for k, v in res.headers.items()}
            if got.get(pap.HEADER_NONCE.lower()):
                with self._lock:
                    self._nonces[origin] = got[pap.HEADER_NONCE.lower()]
            if stream and res.status == 200:
                return _Sent(200, got, b"", res)
            data = res.read(1 << 20)
            res.close()
            if attempt == 0 and retry(res.status, got) == "retry_nonce":
                continue
            return _Sent(res.status, got, data)
        raise AssertionError("unreachable")

    def authorize(self, connection: str, tool: str, tool_input: dict[str, Any], tool_use_id: str, action_id: str,
                  server: str = "", cwd: str = "", first_hash: str = "") -> Result:
        """Asks the gateway's /sdk face about one raw call through the named
        connection. Never raises: every failure is cannot_decide."""
        if not self._gateway or not self._run:
            return _cannot("the gateway URL and the run id are required")
        if not tool or not tool_use_id or not isinstance(tool_input, dict):
            return _cannot("a tool call needs a tool name, its id and an input object")
        call: dict[str, Any] = {"tool": tool}
        if server:
            call["server"] = server
        call |= {"input": tool_input, "tool_use_id": tool_use_id}
        if cwd:
            call["cwd"] = cwd
        headers = {"Content-Type": "application/json", "PAP-Run-Id": self._run, "PC-Action-Id": action_id}
        try:
            body = json.dumps(call, separators=(",", ":"), ensure_ascii=False).encode()
            res = self._do("POST", f"{self._gateway}/sdk/{urllib.parse.quote(connection, safe='')}", body, headers)
        except Exception as e:  # noqa: BLE001 - every failure is "cannot decide" (HR-200)
            return _cannot(f"PantherClaw cannot decide: {e}")
        return evaluate(res.status, res.body, action_id, first_hash)

    def wait(self, handle: str, known: str = "", timeout: int = 30) -> tuple[dict[str, Any], bool]:
        """Long-polls a held call: answers when the state differs from ``known`` or after ``timeout`` (at most 30 s)."""
        req: dict[str, Any] = {"runId": self._run, "handle": handle, "timeoutSeconds": min(timeout, 30)}
        if known:
            req["knownState"] = "WAIT_STATE_" + known
        res = self._do("POST", self._server + "/pantherclaw.v1.WorkloadService/Wait", json.dumps(req).encode(), CONNECT, extra=timeout)
        if res.status != 200:
            raise RuntimeError(f"wait: HTTP {res.status}")
        return parse_wait_response(res.body)

    def stream(self, handle: str, fn: Callable[[dict[str, Any]], bool], timeout: float = 300.0) -> None:
        """Follows the server's SSE stream for a held call until ``fn`` returns
        False, the state is final, or no byte arrives for ``timeout`` seconds."""
        res = self._do("GET", f"{self._server}/v1/wait/{urllib.parse.quote(handle, safe='')}", b"", {"Accept": "text/event-stream"}, extra=timeout)
        if res.status != 200 or res.stream is None:
            raise RuntimeError(f"wait stream: HTTP {res.status}")
        with res.stream:
            read_stream(iter(res.stream.readline, b""), lambda w: fn(w) and next_step(w) == "wait")

    def authorize_and_wait(self, connection: str, tool: str, tool_input: dict[str, Any], tool_use_id: str, action_id: str,
                           server: str = "", cwd: str = "", deadline: float = 300.0) -> Result:
        """Asks about a call and, while it is held, waits in PantherClaw and
        resubmits the identical call (see resume)."""
        until = time.monotonic() + deadline
        first = self.authorize(connection, tool, tool_input, tool_use_id, action_id, server=server, cwd=cwd)
        return self.resume(connection, tool, tool_input, tool_use_id, action_id, first, server=server, cwd=cwd,
                           deadline=max(0.0, until - time.monotonic()))

    def resume(self, connection: str, tool: str, tool_input: dict[str, Any], tool_use_id: str, action_id: str, first: Result,
               server: str = "", cwd: str = "", deadline: float = 300.0) -> Result:
        """Continues from an answer: while it is a hold, waits in PantherClaw
        (the SSE stream, else long-polls) and resubmits the identical call
        with the same action id once it is ready, checking that it maps to the
        same action (PAP/1 §8). Past ``deadline`` seconds the call cannot be
        decided."""
        until = time.monotonic() + deadline
        res = first
        while res.outcome == "hold":
            first_hash, held = res.answer["action_hash"], res.answer["wait"]
            try:
                state = self._wait_ready(held, until)
            except Exception as e:  # noqa: BLE001 - any failure while waiting cannot decide
                return _cannot(f"the wait for PantherClaw's decision ended: {e}")
            if next_step(state) == "deny":
                return Result("deny", f"the hold ended: {state.get('state')} {state.get('code', '')}", res.answer)
            res = self.authorize(connection, tool, tool_input, tool_use_id, action_id, server=server, cwd=cwd, first_hash=first_hash)
        return res

    def _wait_ready(self, held: dict[str, Any], until: float) -> dict[str, Any]:
        last: dict[str, Any] = {}

        def keep(w: dict[str, Any]) -> bool:
            last.clear()
            last.update(w)
            return time.monotonic() < until

        try:
            self.stream(held["handle"], keep, timeout=max(1.0, until - time.monotonic()))
        except Exception:  # noqa: BLE001, S110 - the stream is not available: long-poll instead
            pass
        if last and next_step(last) != "wait":
            return last
        known = str(held.get("state", ""))
        while time.monotonic() < until:
            state, _ = self.wait(held["handle"], known, timeout=max(1, min(30, int(until - time.monotonic()))))
            if next_step(state) != "wait":
                return state
            known = state["state"]
        raise TimeoutError("deadline")
