# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The decision every PantherClaw framework wrapper makes before a tool runs
(M14 PN-016.3; HR-328, HR-329; sdk/conformance/wrappers.json).

Each wrapper package carries this module byte for byte (its tests check
that): a wrapped tool's call goes to the gateway's /sdk face of the
connection, as the MCP tool ``mcp__<connection>__<tool>`` of the server
named after it, so the connection's package maps ``<tool>``. Only an allow
runs the tool; a hold is waited on (or, in LangGraph, interrupts the graph)
and the identical call resubmitted; an identical retry of a held call reuses
its action id; anything else returns a refusal to the model without running
the tool, or raises with ``raise_on_refusal``. Every decision is
cooperative and labeled PARTIAL: the agent's process runs the tool with its
own access (HR-024).
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pantherclaw.client import Client, Outbound, Result, new_action_id

__all__ = ["ON_HOLD", "Guard", "PantherClawRefused", "Verdict", "refusal"]

# What a hold does: "wait" in PantherClaw (the default), or "interrupt",
# which hands the hold to the framework (LangGraph's interrupt) and waits
# once the graph resumes.
ON_HOLD = ("wait", "interrupt")
_CALL_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}\Z")
# How many held calls' action ids one wrapper remembers for their retries.
_MAX_RETRIES = 10_000


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
    ``code``. ``hold`` is set while a hold waits for the framework
    (``on_hold="interrupt"``)."""

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
    retries. ``client`` is the core client and ``connection`` the http or mcp
    connection whose package maps the tools (an agent_held or
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
        self._retries: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()
        # PantherClaw's own bounded threads for the async paths, never the
        # event loop's default executor; waits have their own pool, so a
        # long wait never delays a new decision.
        self._decisions = ThreadPoolExecutor(max_workers=8, thread_name_prefix="pantherclaw-decide")
        self._waits = ThreadPoolExecutor(max_workers=32, thread_name_prefix="pantherclaw-wait")

    # The decision, in two halves: the first request, then (for a hold) the
    # wait and resubmission. A framework interrupt goes between them.

    def _start(self, tool: str, args: Any, call_id: Any) -> tuple[_Call, Result] | Verdict:
        if not isinstance(tool, str) or not tool:
            return Verdict(code="wrapper_error")
        if not isinstance(args, dict):
            return Verdict(code="wrapper_error")
        key = json.dumps([tool, args], sort_keys=True, ensure_ascii=False)
        now = time.monotonic()
        with self._lock:
            for k in [k for k, (_, exp) in self._retries.items() if exp < now]:
                del self._retries[k]
            action_id = self._retries[key][0] if key in self._retries else new_action_id()
        use_id = call_id if isinstance(call_id, str) and _CALL_ID.match(call_id) else "pc-" + secrets.token_hex(16)
        c = _Call(tool, args, use_id, action_id, key)
        res = self._client.authorize(self._connection, f"mcp__{self._connection}__{tool}", args, use_id, action_id, server=self._connection)
        return c, res

    def _held_again(self, c: _Call, res: Result) -> None:
        with self._lock:
            if len(self._retries) >= _MAX_RETRIES and c.key not in self._retries:
                self._retries.pop(next(iter(self._retries)))
            self._retries[c.key] = (c.action_id, _expires(res.answer, self._wait))

    def _resume(self, c: _Call, first: Result, cancelled: threading.Event | None = None) -> Verdict:
        res = self._client.resume(
            self._connection, f"mcp__{self._connection}__{c.tool}", c.args, c.call_id, c.action_id, first, server=self._connection,
            deadline=self._wait, cancelled=cancelled.is_set if cancelled else None,
        )
        if res.outcome == "allow":
            return self._conclude(c, res)
        code = "hold_declined" if res.outcome == "deny" else "hold_timeout"
        return Verdict(code=code, transaction=_transaction(res.answer) or _transaction(first.answer))

    def _conclude(self, c: _Call, res: Result) -> Verdict:
        """A Verdict from an answer that is not a hold."""
        txn = _transaction(res.answer)
        if res.outcome == "allow":
            with self._lock:
                self._retries.pop(c.key, None)
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

    def _first(self, tool: str, args: Any, call_id: Any) -> tuple[_Call, Result] | Verdict:
        out = self._start(tool, args, call_id)
        if isinstance(out, Verdict):
            return out
        c, res = out
        if res.outcome != "hold":
            return self._conclude(c, res)
        self._held_again(c, res)
        return c, res

    def decide(self, tool: str, args: Any, call_id: Any = None, interrupt: Callable[[dict[str, Any]], Any] | None = None) -> Verdict:
        """Decides one call, blocking; never raises: any failure is a
        wrapper_error refusal. ``interrupt`` is the framework's interrupt for
        ``on_hold="interrupt"``; an exception it raises to pause the run
        (LangGraph's GraphInterrupt) propagates."""
        try:
            out = self._first(tool, args, call_id)
        except Exception:  # noqa: BLE001 - any failure refuses (HR-328)
            return Verdict(code="wrapper_error")
        if isinstance(out, Verdict):
            return out
        c, held = out
        if self.on_hold == "interrupt" and interrupt is not None:
            interrupt(self._interrupt_value(c, held))
        try:
            return self._resume(c, held)
        except Exception:  # noqa: BLE001 - any failure refuses
            return Verdict(code="wrapper_error")

    async def adecide(self, tool: str, args: Any, call_id: Any = None, interrupt: Callable[[dict[str, Any]], Any] | None = None) -> Verdict:
        """decide for the async paths: the blocking client runs on
        PantherClaw's own threads; a cancelled wait never resubmits."""
        loop = asyncio.get_running_loop()
        try:
            out = await loop.run_in_executor(self._decisions, self._first, tool, args, call_id)
        except Exception:  # noqa: BLE001 - any failure refuses
            return Verdict(code="wrapper_error")
        if isinstance(out, Verdict):
            return out
        c, held = out
        if self.on_hold == "interrupt" and interrupt is not None:
            interrupt(self._interrupt_value(c, held))
        cancelled = threading.Event()
        try:
            return await loop.run_in_executor(self._waits, self._resume, c, held, cancelled)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        except Exception:  # noqa: BLE001 - any failure refuses
            cancelled.set()
            return Verdict(code="wrapper_error")

    def _interrupt_value(self, c: _Call, held: Result) -> dict[str, Any]:
        wait = held.answer.get("wait") or {}
        return {"pantherclaw": {"transaction_id": _transaction(held.answer), "action_id": c.action_id, "deadline": wait.get("deadline", "")}}

    # Running a call: the tool, PantherClaw's request, or the refusal.

    def finish(self, v: Verdict, run: Callable[[], Any]) -> Any:
        """The call's result: the tool's own (``run``), the on_dispatch
        handler's for PantherClaw's own request, or the refusal (raised with
        raise_on_refusal)."""
        if v.run:
            return run()
        if v.send is not None and self._on_dispatch is not None:
            return self._on_dispatch(v.call_id, v.send)
        if self.raise_on_refusal:
            raise PantherClawRefused(v.code, v.transaction)
        return v.refusal

    async def afinish(self, v: Verdict, run: Callable[[], Awaitable[Any]]) -> Any:
        if v.run:
            return await run()
        if v.send is not None and self._on_dispatch is not None:
            out = self._on_dispatch(v.call_id, v.send)
            return await out if asyncio.iscoroutine(out) else out
        if self.raise_on_refusal:
            raise PantherClawRefused(v.code, v.transaction)
        return v.refusal
