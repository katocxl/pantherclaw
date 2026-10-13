# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""ActionIR v1 (PAP/1 §6), with the structural checks PantherClaw makes
(HR-100..103, actionir.json); the 8 KiB cap on material parameters depends
on the definition and is PantherClaw's alone. SDKs never build or send
ActionIR (HR-201): they parse the action a gateway returns, to check it and
its hash."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from . import jcs

__all__ = ["ActionError", "ParsedAction", "parse_action"]


class ActionError(ValueError):
    """ActionIR that PantherClaw would refuse."""


@dataclass(frozen=True)
class ParsedAction:
    action: dict[str, Any]
    canonical: str
    hash: str


_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_OPERATION = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}\Z")
_ROUTE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\Z")
_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}\Z")
_VERSION = re.compile(r"^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_PRINTABLE = re.compile(r"^[\x21-\x7e]+\Z")
_MEMBERS = {
    "": {"v", "org", "env", "run_id", "action_id", "agent_instance", "operation", "definition", "channel", "route", "connection", "target",
         "params", "destinations", "dedupe_key"},
    "definition": {"package", "version", "digest"},
    "target": {"type", "id", "account"},
    "destination": {"kind", "id"},
}


def _fail(why: str) -> None:
    raise ActionError(f"invalid ActionIR: {why}")


def _scan(v: Any, depth: int, pointer: str) -> None:
    if isinstance(v, (dict, list)) and depth > 16:
        _fail("nested deeper than 16")
    if isinstance(v, bool) or v is None:
        return
    if isinstance(v, float):
        if pointer != "/v":
            _fail(f"a JSON number at {pointer}")
    elif isinstance(v, str):
        if len(v.encode("utf-8")) > 64 << 10:
            _fail("a string longer than 64 KiB")
    elif isinstance(v, list):
        for i, x in enumerate(v):
            _scan(x, depth + 1, f"{pointer}/{i}")
    elif isinstance(v, dict):
        for k, x in v.items():
            if len(k.encode("utf-8")) > 64 << 10:
                _fail("a member name longer than 64 KiB")
            _scan(x, depth + 1, f"{pointer}/{k}")


def _object(v: Any, name: str) -> dict[str, Any]:
    if not isinstance(v, dict):
        _fail(f"{name or 'the action'} must be an object")
    unknown = set(v) - _MEMBERS[name]
    if unknown:
        _fail(f"unknown members {sorted(unknown)} in {name or 'the action'}")
    return v


def _str(o: dict[str, Any], k: str, required: bool = True) -> str:
    v = o.get(k)
    if v is None and not required:
        return ""
    if not isinstance(v, str):
        _fail(f"{k} must be a string")
    return v


def _identifier(name: str, v: str, required: bool) -> None:
    if v == "":
        if required:
            _fail(f"{name} is required")
        return
    if len(v) > 8 << 10 or not _PRINTABLE.match(v):
        _fail(f"{name} must be printable ASCII")


def parse_action(raw: str | bytes) -> ParsedAction:
    """Parses ActionIR strictly and returns it with its canonical form and hash."""
    data = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    if not data or len(data) > 1 << 20:
        _fail("size")
    numbers: list[str] = []
    try:
        v = jcs.parse(data, numbers)
    except jcs.JCSError as e:
        raise ActionError(f"invalid ActionIR: {e}") from e
    _scan(v, 1, "")
    a = _object(v, "")
    # The only number is the version, written exactly 1 (not 1.0 or 1e0).
    if a.get("v") != 1.0 or isinstance(a.get("v"), bool) or any(n != "1" for n in numbers):
        _fail("version")
    for k in ("org", "env", "run_id", "action_id", "agent_instance"):
        if not _UUID.match(_str(a, k)):
            _fail(f"{k} is not a UUID")
    if not _OPERATION.match(_str(a, "operation")):
        _fail("operation")
    d = _object(a.get("definition"), "definition")
    if not (_PACKAGE.match(_str(d, "package")) and _VERSION.match(_str(d, "version")) and _DIGEST.match(_str(d, "digest"))):
        _fail("definition")
    if _str(a, "channel") not in ("mcp", "http", "sdk", "hook"):
        _fail("channel")
    if not _ROUTE.match(_str(a, "route")):
        _fail("route")
    conn = _str(a, "connection", required=False)
    if conn and not _UUID.match(conn):
        _fail("connection")
    t = _object(a.get("target"), "target")
    _identifier("target.type", _str(t, "type", required=False), True)
    _identifier("target.id", _str(t, "id", required=False), True)
    _identifier("target.account", _str(t, "account", required=False), False)
    if not isinstance(a.get("params"), dict):
        _fail("params must be an object")
    dests = a.get("destinations")
    if not isinstance(dests, list):
        _fail("destinations must be present")
    for x in dests:
        o = _object(x, "destination")
        if _str(o, "kind") not in ("internal", "external"):
            _fail("destination kind")
        _identifier("destination id", _str(o, "id", required=False), True)
    _identifier("dedupe_key", _str(a, "dedupe_key", required=False), False)
    canonical = jcs.serialize(v)
    return ParsedAction(action=a, canonical=canonical, hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest())
