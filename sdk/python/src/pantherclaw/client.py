# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The PantherClaw workload client (PAP/1): a proof over every request, the
servers' nonces, workload token renewal, the gateway's /sdk and /hook faces
and waits on held calls. It fails closed (HR-200): when PantherClaw cannot
decide, the outcome is "cannot_decide", never "allow"."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import jcs, pap
from .action import ActionError, parse_action

__all__ = [
    "MAX_CALL_BODY",
    "Client",
    "HookResult",
    "Outbound",
    "Result",
    "classify",
    "evaluate",
    "new_action_id",
    "next_step",
    "parse_wait_response",
    "read_stream",
    "retry",
    "send_outbound",
]

CONNECT = {"Content-Type": "application/json", "Connect-Protocol-Version": "1"}
_HEX = re.compile(r"^[0-9a-f]{64}\Z")
_TOOL_USE_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")
# The largest request the /sdk and /hook faces read.
MAX_CALL_BODY = 64 << 10
# The longest line or event an SSE wait stream may send.
_MAX_EVENT = 64 << 10
# How long past a hold's deadline the client still waits to hear how it ended.
_WAIT_GRACE = 5.0
# How often one call is resubmitted and held again before the client gives up.
_MAX_RESUBMITS = 3
# The longest a single read of the wait stream may block.
_STREAM_READ = 20.0


@dataclass
class Outbound:
    """The request to send a target-enforced connection's target: exactly
    the one the gateway built (HR-201)."""

    method: str
    url: str
    headers: dict[str, str]
    body: bytes


@dataclass
class Result:
    """What the agent may do with a call: only "allow", and "observe" for a
    built-in tool, let it run. ``send`` is, for an allow on a
    target-enforced connection, the request to send instead of building
    one."""

    outcome: str
    why: str = ""
    answer: dict[str, Any] = field(default_factory=dict)
    send: Outbound | None = None


@dataclass
class HookResult:
    """The /hook face's answer: "allow", "deny" (``held``: an eligible person
    may approve it in PantherClaw, never the local user) or
    "cannot_decide"."""

    outcome: str
    held: bool = False
    why: str = ""
    answer: dict[str, Any] = field(default_factory=dict)


def _cannot(why: str) -> Result:
    return Result("cannot_decide", why)


def classify(tool: str, servers: Iterable[str], builtins: Iterable[str]) -> tuple[str, str]:
    """Sorts an agent's tool name into (class, server): mcp__<server>__<tool>,
    with server the longest of ``servers`` that fits (a server name may
    contain "__") and a tool name after it, is "mapped"; a name in
    ``builtins`` (exactly) is "builtin"; anything else is "refused", never
    sent and never run (HR-200)."""
    if tool.startswith("mcp__"):
        rest, server = tool[5:], ""
        for s in servers:
            if len(s) > len(server) and len(rest) > len(s) + 2 and rest.startswith(s + "__"):
                server = s
        return ("mapped", server) if server else ("refused", "")
    return ("builtin", "") if tool in set(builtins) else ("refused", "")


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
    if not isinstance(a.get("action_ir"), str) or not a["action_ir"]:
        return "the answer does not carry the action it decided"
    try:
        p = parse_action(pap.from_b64url(a["action_ir"]))
    except (ActionError, ValueError):
        return "the canonical action is not valid ActionIR"
    if p.hash != a["action_hash"]:
        return "the action hash does not match the action"
    if p.action.get("action_id") != action_id:
        return "the mapped action is for another action id"
    if p.action.get("channel") != "sdk" or not isinstance(p.action.get("connection"), str) or not p.action["connection"]:
        return "the mapped action did not come through an SDK connection"
    return ""


def _check_dispatch(d: Any) -> Outbound | str:
    """Checks a dispatch: its PAP-Action header is its token, whose pap.bh
    binds the body. The token's signature is the target's to verify."""
    try:
        if not isinstance(d, dict) or not isinstance(d.get("headers"), dict):
            return "the request to send is not readable"
        body = pap.from_b64url(str(d.get("body", "")))
        u = urllib.parse.urlsplit(str(d.get("url", "")))
        if u.scheme not in ("https", "http") or not u.netloc or not d.get("method"):
            return "the request to send has no method or absolute URL"
        headers = {str(k): str(v) for k, v in d["headers"].items()}
        action = next((v for k, v in headers.items() if k.lower() == "pap-action"), None)
        token = d.get("action_token")
        if not isinstance(token, str) or not token or action != token:
            return "the request to send does not carry its action token"
        parts = token.split(".")
        if len(parts) != 3:
            return "the action token is not a compact JWS"
        claims = jcs.parse(pap.from_b64url(parts[1]))
        pap_claims = claims.get("pap") if isinstance(claims, dict) else None
        if not isinstance(pap_claims, dict) or pap_claims.get("bh") != hashlib.sha256(body).hexdigest():
            return "the action token does not bind the body to send"
        return Outbound(str(d["method"]), str(d["url"]), headers, body)
    except (ValueError, jcs.JCSError):
        return "the request to send is not readable"


def _answer(body: bytes | str) -> dict[str, Any] | None:
    """A gateway answer, parsed strictly (a duplicate member is refused)."""
    try:
        a = jcs.parse(body)
    except jcs.JCSError:
        return None
    return a if isinstance(a, dict) else None


def evaluate(status: int, body: bytes | str, cls: str, action_id: str, first_hash: str = "") -> Result:
    """Reads a /sdk answer to a call of class ``cls`` ("mapped" or "builtin")
    for the action id the SDK sent; ``first_hash`` is the hash of an earlier
    answer for the same action. Anything it cannot read or check is
    cannot_decide (HR-200, HR-201)."""
    if status != 200:
        return _cannot(f"the gateway answered HTTP {status}")
    a = _answer(body)
    if a is None:
        return _cannot("the gateway's answer is not readable")
    r = Result("deny", str(a.get("reason", "")), a)
    decision = a.get("decision")
    if decision == "deny":
        return r
    if decision == "allow":
        if a.get("coverage") == "OBSERVE_ONLY":
            if cls != "builtin":
                return _cannot("an observe answer for a call that is not a built-in tool")
            if a.get("mode") != "monitor" or a.get("action_hash") or a.get("action_ir") or a.get("dispatch"):
                return _cannot("an observed call that is not only recorded")
            r.outcome = "observe"
            return r
        r.outcome = "allow"
    elif decision == "hold":
        if not isinstance(a.get("wait"), dict) or not a["wait"].get("handle"):
            return _cannot("a hold without a wait handle")
        if a.get("dispatch") is not None:
            return _cannot("a hold with a request to send")
        r.outcome = "hold"
    else:
        return _cannot(f"unknown decision {decision}")
    problem = _check_action(a, action_id, first_hash)
    if problem:
        return _cannot(problem)
    if a.get("dispatch") is not None:
        send = _check_dispatch(a["dispatch"])
        if isinstance(send, str):
            return _cannot(send)
        r.send = send
    return r


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def send_outbound(o: Outbound, headers: dict[str, str] | None = None, timeout: float = 30.0) -> tuple[int, dict[str, str], bytes]:
    """Sends an outbound request exactly as the gateway built it, with the
    application's own credential for the target in ``headers`` when it has
    one, following no redirect. Change nothing else: the target refuses any
    other body (HR-202). Returns the status, headers and body (at most 1 MiB)."""
    req = urllib.request.Request(o.url, data=o.body or None, method=o.method, headers=dict(o.headers) | (headers or {}))
    try:
        res = urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)  # noqa: S310 - the gateway's URL
    except urllib.error.HTTPError as e:
        res = e
    with res:
        return res.status, {k.lower(): v for k, v in res.headers.items()}, res.read(1 << 20)


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
    r = jcs.parse(body)
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
    event until it returns False or the stream ends. A line or an event
    longer than 64 KiB is refused."""
    event, data = "", ""
    for raw in lines:
        if len(raw) > _MAX_EVENT or (len(raw) == _MAX_EVENT and not raw.endswith(b"\n")):
            raise ValueError("wait event too long")
        line = raw.decode("utf-8").rstrip("\r\n")
        if line == "":
            if event == "state" and data and not fn(jcs.parse(data)):
                return
            event, data = "", ""
        elif line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data += line[5:].removeprefix(" ")
            if len(data) > _MAX_EVENT:
                raise ValueError("wait event too long")


def _secure(url: str) -> bool:
    """Whether a base URL may carry workload tokens and proofs: https, or
    http to a loopback address, without user information."""
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ""
    except ValueError:
        return False
    if "@" in u.netloc or not host:
        return False
    if u.scheme == "https":
        return True
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    return u.scheme == "http" and loopback


def _deadline(held: dict[str, Any]) -> float | None:
    """A hold's deadline (RFC 3339) as a time.time() value, if it has one."""
    raw = held.get("deadline")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _read_timeout(res: Any, seconds: float) -> None:
    """Sets the timeout of the stream's next socket read. Where the socket
    cannot be reached, the timeout set when the stream opened applies."""
    sock = getattr(getattr(getattr(res, "fp", None), "raw", None), "_sock", None)
    if sock is not None:
        sock.settimeout(max(0.05, seconds))


@dataclass
class _Sent:
    status: int
    headers: dict[str, str]
    body: bytes
    stream: Any = None


class Client:
    """A PAP/1 workload client. It is safe to share between threads.

    ``builtins`` are the names of the tools the agent SDK has built in: only
    these are sent without a server, and only for them does an observe
    answer let the call run."""

    def __init__(self, key_file: pap.KeyFile, gateway: str = "", server: str = "", run_id: str = "", timeout: float = 15.0,
                 builtins: Iterable[str] = ()) -> None:
        if not key_file.identifier:
            raise ValueError("the key file has no identifier: enroll the workload first")
        self._server = (server or key_file.server).rstrip("/")
        if not self._server:
            raise ValueError("the PantherClaw server URL is required")
        self._gateway, self._run = gateway.rstrip("/"), run_id or key_file.run_id
        if not _secure(self._server) or (self._gateway and not _secure(self._gateway)):
            raise ValueError("the server and gateway URLs must use https (http only on a loopback address) and carry no user information")
        self._kf, self._key = key_file, key_file.key()
        self._timeout = timeout
        self._builtins = frozenset(builtins)
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
        answer = jcs.parse(res.body)
        token = str(answer.get("workloadToken", "")) if isinstance(answer, dict) else ""
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
                # A stream's timeout bounds each read; the caller's deadline bounds the whole.
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

    def _class(self, tool: str, server: str) -> str:
        if server:
            return "mapped" if tool.startswith(f"mcp__{server}__") and len(tool) > len(server) + 7 else "refused"
        return "builtin" if not tool.startswith("mcp__") and tool in self._builtins else "refused"

    def authorize(self, connection: str, tool: str, tool_input: dict[str, Any], tool_use_id: str, action_id: str,
                  server: str = "", first_hash: str = "") -> Result:
        """Asks the gateway's /sdk face about one raw call through the named
        connection: an MCP tool with its server, or a configured built-in;
        any other name is never sent. Never raises: every failure is
        cannot_decide."""
        if not self._gateway or not self._run:
            return _cannot("the gateway URL and the run id are required")
        if not tool or not isinstance(tool_use_id, str) or not _TOOL_USE_ID.match(tool_use_id) or not isinstance(tool_input, dict):
            return _cannot("a tool call needs a tool name, its id and an input object")
        cls = self._class(tool, server)
        if cls == "refused":
            return _cannot(f"PantherClaw neither maps {tool} as an MCP tool nor knows it as a built-in tool")
        call: dict[str, Any] = {"tool": tool}
        if server:
            call["server"] = server
        call |= {"input": tool_input, "tool_use_id": tool_use_id}
        headers = {"Content-Type": "application/json", "PAP-Run-Id": self._run, "PC-Action-Id": action_id}
        try:
            body = json.dumps(call, separators=(",", ":"), ensure_ascii=False).encode()
            if len(body) > MAX_CALL_BODY:
                return _cannot("the tool call is larger than the /sdk face takes")
            res = self._do("POST", f"{self._gateway}/sdk/{urllib.parse.quote(connection, safe='')}", body, headers)
        except Exception as e:  # noqa: BLE001 - every failure is "cannot decide" (HR-200)
            return _cannot(f"PantherClaw cannot decide: {e}")
        return evaluate(res.status, res.body, cls, action_id, first_hash)

    def hook(self, connection: str, shell: str, command: str, cwd: str, call: str) -> HookResult:
        """Asks the local connection's /hook face (pc.shell) about a shell
        command ("bash" or "powershell") in the absolute, final working
        directory ``cwd``, as Claude Code's hook does. Allow only on an
        allow; a hold is a deny with ``held``. Never raises."""
        if not self._gateway or not self._run:
            return HookResult("cannot_decide", why="the gateway URL and the run id are required")
        if shell not in ("bash", "powershell") or not command or not cwd or not isinstance(call, str) or not _TOOL_USE_ID.match(call):
            return HookResult("cannot_decide", why="a shell call needs its shell, a command, a working directory and its id")
        body = json.dumps({"input": {"call": call, "command": command, "cwd": cwd, "shell": shell}, "tool": "shell"},
                          separators=(",", ":"), ensure_ascii=False).encode()
        if len(body) > MAX_CALL_BODY:
            return HookResult("cannot_decide", why="the command is larger than the /hook face takes")
        try:
            res = self._do("POST", f"{self._gateway}/hook/{urllib.parse.quote(connection, safe='')}", body,
                           {"Content-Type": "application/json", "PAP-Run-Id": self._run})
        except Exception as e:  # noqa: BLE001 - every failure is "cannot decide" (HR-200)
            return HookResult("cannot_decide", why=f"PantherClaw cannot decide: {e}")
        if res.status != 200:
            return HookResult("cannot_decide", why=f"the gateway answered HTTP {res.status}")
        a = _answer(res.body)
        if a is None:
            return HookResult("cannot_decide", why="the gateway's answer is not readable")
        if a.get("decision") == "allow":
            return HookResult("allow", why=str(a.get("reason", "")), answer=a)
        if a.get("decision") == "deny":
            return HookResult("deny", held=a.get("held") is True, why=str(a.get("reason", "")), answer=a)
        return HookResult("cannot_decide", why=f"unknown decision {a.get('decision')}")

    def wait(self, handle: str, known: str = "", timeout: int = 30) -> tuple[dict[str, Any], bool]:
        """Long-polls a held call: answers when the state differs from ``known`` or after ``timeout`` (at most 30 s)."""
        req: dict[str, Any] = {"runId": self._run, "handle": handle, "timeoutSeconds": min(timeout, 30)}
        if known:
            req["knownState"] = "WAIT_STATE_" + known
        res = self._do("POST", self._server + "/pantherclaw.v1.WorkloadService/Wait", json.dumps(req).encode(), CONNECT, extra=timeout)
        if res.status != 200:
            raise RuntimeError(f"wait: HTTP {res.status}")
        return parse_wait_response(res.body)

    def stream(self, handle: str, fn: Callable[[dict[str, Any]], bool], until: float | None = None) -> None:
        """Follows the server's SSE stream for a held call until ``fn``
        returns False, the state is final, or ``until`` (a time.monotonic()
        value) passes. The deadline is checked on every line, heartbeats
        included, and each read's socket timeout is the time left (at most 20
        seconds), so no read blocks past it."""
        if until is None:
            until = time.monotonic() + 300.0
        read = max(0.1, min(_STREAM_READ, until - time.monotonic()))
        res = self._do("GET", f"{self._server}/v1/wait/{urllib.parse.quote(handle, safe='')}", b"", {"Accept": "text/event-stream"}, extra=read)
        if res.status != 200 or res.stream is None:
            raise RuntimeError(f"wait stream: HTTP {res.status}")

        def lines() -> Iterator[bytes]:
            while True:
                left = until - time.monotonic()
                if left <= 0:
                    raise TimeoutError("deadline")
                _read_timeout(res.stream, min(_STREAM_READ, left))
                line = res.stream.readline(_MAX_EVENT)
                if not line:
                    return
                yield line

        with res.stream:
            read_stream(lines(), lambda w: fn(w) and next_step(w) == "wait")

    def authorize_and_wait(self, connection: str, tool: str, tool_input: dict[str, Any], tool_use_id: str, action_id: str,
                           server: str = "", deadline: float = 300.0) -> Result:
        """Asks about a call and, while it is held, waits in PantherClaw and
        resubmits the identical call (see resume)."""
        until = time.monotonic() + deadline
        first = self.authorize(connection, tool, tool_input, tool_use_id, action_id, server=server)
        return self.resume(connection, tool, tool_input, tool_use_id, action_id, first, server=server,
                           deadline=max(0.0, until - time.monotonic()))

    def resume(self, connection: str, tool: str, tool_input: dict[str, Any], tool_use_id: str, action_id: str, first: Result,
               server: str = "", deadline: float = 300.0, cancelled: Callable[[], bool] | None = None) -> Result:
        """Continues from an answer: while it is a hold, waits in PantherClaw
        (the SSE stream, else long-polls) and resubmits the identical call
        with the same action id once it is ready, checking that it maps to
        the same action (PAP/1 §8). A wait ends at ``deadline`` seconds or at
        the hold's own deadline (plus a few seconds' grace), a call held
        again after three resubmissions is not resubmitted, and nothing is
        resubmitted once ``cancelled()`` is true; each is cannot_decide."""
        until = time.monotonic() + deadline
        res = first
        resubmits = 0
        while res.outcome == "hold":
            if resubmits == _MAX_RESUBMITS:
                return _cannot(f"the call was held again after {_MAX_RESUBMITS} resubmissions")
            first_hash, held = res.answer["action_hash"], res.answer["wait"]
            end = until
            hold_end = _deadline(held)
            if hold_end is not None:
                end = min(end, time.monotonic() + (hold_end + _WAIT_GRACE - time.time()))
            try:
                state = self._wait_ready(held, end)
            except Exception as e:  # noqa: BLE001 - any failure while waiting cannot decide
                return _cannot(f"the wait for PantherClaw's decision ended: {e}")
            if next_step(state) == "deny":
                return Result("deny", f"the hold ended: {state.get('state')} {state.get('code', '')}", res.answer)
            if (cancelled is not None and cancelled()) or time.monotonic() >= until:
                return _cannot("the wait for PantherClaw's decision ended")
            resubmits += 1
            res = self.authorize(connection, tool, tool_input, tool_use_id, action_id, server=server, first_hash=first_hash)
        return res

    def _wait_ready(self, held: dict[str, Any], until: float) -> dict[str, Any]:
        last: dict[str, Any] = {}

        def keep(w: dict[str, Any]) -> bool:
            last.clear()
            last.update(w)
            return True

        try:
            self.stream(held["handle"], keep, until=until)
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
