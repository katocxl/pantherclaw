# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The decision every PantherClaw framework wrapper makes before a tool runs
(M14 PN-016.3; HR-328, HR-329; sdk/conformance/wrappers.json).

Each wrapper package carries this module byte for byte (its tests check
that): a wrapped tool's call goes to the gateway's /sdk face of the
connection, as the MCP tool ``mcp__<connection>__<tool>`` of the server
named after it, so the connection's package maps ``<tool>``. The wrapper
decides on the arguments the tool's function receives, and refuses a call
carrying arguments outside the tool's schema (undecided_args). Only an allow
runs the tool; a hold is waited on (or, in LangGraph, interrupts the graph)
and the identical call resubmitted; an identical call reuses the action id
of an earlier one only while that call is unresolved, in flight or held
(M14 D68); anything else returns a refusal to the model without running the
tool, or raises with ``raise_on_refusal``. Every decision is cooperative and
labeled PARTIAL: the agent's process runs the tool with its own access
(HR-024).
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Collection, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pantherclaw.client import Client, Outbound, Result, new_action_id

__all__ = ["ON_HOLD", "Guard", "PantherClawRefused", "Verdict", "refusal"]

# What a hold does: "wait" in PantherClaw (the default), or "interrupt",
# which hands the hold to the framework (LangGraph's interrupt) and
# resubmits the identical call each time the graph resumes.
ON_HOLD = ("wait", "interrupt")
_CALL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")
# How many unresolved calls' action ids one wrapper remembers.
_MAX_RETRIES = 10_000
# How often one held call interrupts the graph before it is refused.
_MAX_INTERRUPTS = 100


class PantherClawRefused(Exception):  # noqa: N818 - the name says what happened
    """A refused call, raised instead of returned with ``raise_on_refusal``."""

    def __init__(self, code: str, transaction: str = "") -> None:
        super().__init__(refusal(code, transaction))
        self.code, self.transaction = code, transaction


def refusal(code: str, transaction: str = "") -> str:
    """The text a refused call returns to the model (M14 D47)."""
    where = f" (transaction {transaction})" if transaction else ""
    return f"PantherClaw refused this call: {code}{where}"


@dataclass
class Verdict:
    """What a call comes to: ``run`` the tool, ``dispatch`` PantherClaw's own
    request (``send``) through the on_dispatch handler, or refuse with
    ``code``."""

    run: bool = False
    call_id: str = ""
    code: str = ""
    transaction: str = ""
    send: Outbound | None = None
    hold: dict[str, Any] = field(default_factory=dict)

    @property
    def refusal(self) -> str:
        return refusal(self.code, self.transaction)


@dataclass
class _Call:
    tool: str
    args: dict[str, Any]
    call_id: str
    action_id: str
    key: str


def _transaction(answer: Mapping[str, Any]) -> str:
    txn = answer.get("transaction_id")
    return txn if isinstance(txn, str) else ""


def _expires(answer: Mapping[str, Any], wait: float) -> float:
    """When a held call's action id is forgotten: after its hold's deadline,
    or ``wait`` seconds when the hold has none."""
    raw = (answer.get("wait") or {}).get("deadline")
    if isinstance(raw, str) and raw:
        try:
            left = datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp() - time.time()
            return time.monotonic() + max(wait, left)
        except ValueError:
            pass
    return time.monotonic() + wait


class Guard:
    """One wrapper instance's decisions: the tools it wraps share its
    unresolved calls. ``client`` is the core client and ``connection`` the
    http or mcp connection whose package maps the tools (an agent_held or
    target_enforced connection). ``wait`` bounds a hold's wait in seconds."""

    def __init__(
        self,
        client: Client,
        connection: str,
        *,
        on_hold: str = "wait",
        wait: float = 300.0,
        observe_unmapped: bool = False,
        raise_on_refusal: bool = False,
        on_dispatch: Callable[[str, Outbound], Any] | None = None,
    ) -> None:
        if client is None or not connection:
            raise ValueError("PantherClaw: a client and a connection are required")
        if on_hold not in ON_HOLD:
            raise ValueError(f"PantherClaw: on_hold is one of {', '.join(ON_HOLD)}")
        self._client, self._connection = client, connection
        self.on_hold, self._wait = on_hold, float(wait)
        self._observe_unmapped, self.raise_on_refusal = observe_unmapped, raise_on_refusal
        self._on_dispatch = on_dispatch
        # The unresolved calls (in flight or held): key → (action id, when it is forgotten).
        self._retries: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        # PantherClaw's own bounded threads for the async paths, never the
        # event loop's default executor; waits have their own pool, so a
        # long wait never delays a new decision.
        self._decisions = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pantherclaw-decide")
        self._waits = ThreadPoolExecutor(max_workers=32, thread_name_prefix="pantherclaw-wait")

    # The steps of a decision.

    def _begin(self, tool: Any, args: Any, call_id: Any, parameters: Collection[str] | None) -> _Call | Verdict:
        """The call, with the action id of an identical unresolved call or a
        new one, now in flight; or a refusal without a request."""
        if not isinstance(tool, str) or not tool or not isinstance(args, dict):
            return Verdict(code="wrapper_error")
        if parameters is not None and any(k not in parameters for k in args):
            return Verdict(code="undecided_args")
        key = json.dumps([tool, args], sort_keys=True, ensure_ascii=False)
        now = time.monotonic()
        with self._lock:
            for k in [k for k, (_, exp) in self._retries.items() if exp < now]:
                del self._retries[k]
            if key in self._retries:
                action_id = self._retries[key][0]
            else:
                action_id = new_action_id()
                if len(self._retries) >= _MAX_RETRIES:
                    self._retries.pop(next(iter(self._retries)))
            self._retries[key] = (action_id, now + self._wait)
        use_id = call_id if isinstance(call_id, str) and _CALL_ID.match(call_id) else "pc-" + secrets.token_hex(16)
        return _Call(tool, args, use_id, action_id, key)

    def _forget(self, c: _Call) -> None:
        with self._lock:
            self._retries.pop(c.key, None)

    def _held(self, c: _Call, res: Result) -> None:
        with self._lock:
            self._retries[c.key] = (c.action_id, _expires(res.answer, self._wait))

    def _authorize(self, c: _Call, first_hash: str = "") -> Result:
        return self._client.authorize(self._connection, f"mcp__{self._connection}__{c.tool}", c.args, c.call_id, c.action_id,
                                      server=self._connection, first_hash=first_hash)

    def _resume(self, c: _Call, first: Result, cancelled: threading.Event | None = None) -> Verdict:
        res = self._client.resume(
            self._connection, f"mcp__{self._connection}__{c.tool}", c.args, c.call_id, c.action_id, first, server=self._connection,
            deadline=self._wait, cancelled=cancelled.is_set if cancelled else None,
        )
        if res.outcome == "allow":
            return self._conclude(c, res)
        txn = _transaction(res.answer) or _transaction(first.answer)
        if res.outcome == "deny":
            return self._held_denied(c, res, txn)
        # Still held in PantherClaw as far as the wrapper knows: an identical retry keeps the action id.
        return Verdict(code="hold_timeout", transaction=txn)

    def _held_denied(self, c: _Call, res: Result, txn: str) -> Verdict:
        """A resumed hold that ended in a deny (M14 D79): hold_declined, except
        duplicate_action (another call ran the action), reported verbatim."""
        self._forget(c)
        if res.answer.get("code") == "duplicate_action":
            return Verdict(code="duplicate_action", transaction=txn)
        return Verdict(code="hold_declined", transaction=txn)

    def _conclude(self, c: _Call, res: Result) -> Verdict:
        """The Verdict of an answer that is not a hold: final, so the call's
        action id is forgotten."""
        self._forget(c)
        txn = _transaction(res.answer)
        if res.outcome == "allow":
            if res.send is not None:
                if self._on_dispatch is None:
                    return Verdict(code="dispatch_required", transaction=txn)
                return Verdict(send=res.send, call_id=c.call_id, transaction=txn)
            return Verdict(run=True, call_id=c.call_id, transaction=txn)
        if res.outcome == "deny":
            code = res.answer.get("code")
            if code == "unknown_tool" and self._observe_unmapped:
                return Verdict(run=True, call_id=c.call_id)
            return Verdict(code=code if isinstance(code, str) and code else "denied", transaction=txn)
        # observe is only ever a built-in's answer, and a wrapped tool is never one.
        return Verdict(code="cannot_decide")

    def _first(self, tool: Any, args: Any, call_id: Any, parameters: Collection[str] | None) -> tuple[_Call, Result] | Verdict:
        c = self._begin(tool, args, call_id, parameters)
        if isinstance(c, Verdict):
            return c
        try:
            res = self._authorize(c)
        except BaseException:
            self._forget(c)
            raise
        if res.outcome != "hold":
            return self._conclude(c, res)
        self._held(c, res)
        return c, res

    def _again(self, c: _Call, held: Result) -> tuple[Verdict | None, Result]:
        """After an interrupt resumed: the identical call resubmitted, a
        Verdict unless it is still held."""
        res = self._authorize(c, first_hash=str(held.answer.get("action_hash", "")))
        if res.outcome == "deny":
            return self._held_denied(c, res, _transaction(res.answer) or _transaction(held.answer)), res
        if res.outcome != "hold":
            return self._conclude(c, res), res
        self._held(c, res)
        return None, res

    def _interrupt_value(self, c: _Call, held: Result) -> dict[str, Any]:
        wait = held.answer.get("wait") or {}
        return {"pantherclaw": {"transaction_id": _transaction(held.answer), "action_id": c.action_id, "deadline": wait.get("deadline", "")}}

    def decide(self, tool: str, args: Any, call_id: Any = None, interrupt: Callable[[dict[str, Any]], Any] | None = None,
               parameters: Collection[str] | None = None, propagate: tuple[type[BaseException], ...] = ()) -> Verdict:
        """Decides one call, blocking; never raises: any failure is a
        wrapper_error refusal, except an exception of ``propagate``, which the
        framework uses to pause the run (LangGraph's GraphInterrupt).
        ``parameters`` are the names the tool's schema takes: other
        arguments are refused (undecided_args). ``interrupt`` is the
        framework's interrupt for ``on_hold="interrupt"``: each time the run
        resumes the identical call is resubmitted, and while it is still held
        the run is interrupted again."""
        try:
            out = self._first(tool, args, call_id, parameters)
            if isinstance(out, Verdict):
                return out
            c, held = out
            if self.on_hold == "interrupt" and interrupt is not None:
                for _ in range(_MAX_INTERRUPTS):
                    interrupt(self._interrupt_value(c, held))
                    v, held = self._again(c, held)
                    if v is not None:
                        return v
                return Verdict(code="hold_timeout", transaction=_transaction(held.answer))
            return self._resume(c, held)
        except propagate:
            raise
        except Exception:  # noqa: BLE001 - any failure refuses (HR-328)
            return Verdict(code="wrapper_error")

    async def adecide(self, tool: str, args: Any, call_id: Any = None, interrupt: Callable[[dict[str, Any]], Any] | None = None,
                      parameters: Collection[str] | None = None, propagate: tuple[type[BaseException], ...] = ()) -> Verdict:
        """decide for the async paths: the blocking client runs on
        PantherClaw's own threads; a cancelled wait never resubmits."""
        loop = asyncio.get_running_loop()
        cancelled = threading.Event()
        try:
            out = await loop.run_in_executor(self._decisions, self._first, tool, args, call_id, parameters)
            if isinstance(out, Verdict):
                return out
            c, held = out
            if self.on_hold == "interrupt" and interrupt is not None:
                for _ in range(_MAX_INTERRUPTS):
                    interrupt(self._interrupt_value(c, held))
                    v, held = await loop.run_in_executor(self._decisions, self._again, c, held)
                    if v is not None:
                        return v
                return Verdict(code="hold_timeout", transaction=_transaction(held.answer))
            return await loop.run_in_executor(self._waits, self._resume, c, held, cancelled)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        except propagate:
            raise
        except Exception:  # noqa: BLE001 - any failure refuses
            cancelled.set()
            return Verdict(code="wrapper_error")

    # Running a call: the tool, PantherClaw's request, or the refusal.

    def _refuse(self, v: Verdict) -> str:
        if self.raise_on_refusal:
            raise PantherClawRefused(v.code, v.transaction)
        return v.refusal

    def finish(self, v: Verdict, run: Callable[[], Any]) -> Any:
        """The call's result: the tool's own (``run``), the on_dispatch
        handler's for PantherClaw's own request, or the refusal (raised with
        raise_on_refusal). A sync call cannot await an async handler, so its
        request is never sent: wrapper_error."""
        if v.run:
            return run()
        if v.send is not None and self._on_dispatch is not None:
            out = self._on_dispatch(v.call_id, v.send)
            if not inspect.isawaitable(out):
                return out
            if inspect.iscoroutine(out):
                out.close()
            return self._refuse(Verdict(code="wrapper_error", transaction=v.transaction))
        return self._refuse(v)

    async def afinish(self, v: Verdict, run: Callable[[], Awaitable[Any]]) -> Any:
        if v.run:
            return await run()
        if v.send is not None and self._on_dispatch is not None:
            out = self._on_dispatch(v.call_id, v.send)
            return await out if inspect.isawaitable(out) else out
        return self._refuse(v)
