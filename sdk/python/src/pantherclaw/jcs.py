# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""RFC 8785 JSON Canonicalization Scheme, checked against the shared
conformance vectors (sdk/conformance/jcs.json).

Duplicate member names, lone surrogates, invalid UTF-8 and non-finite
numbers are refused; numbers are written as ECMAScript does and members are
sorted by UTF-16 code units.
"""

from __future__ import annotations

import json
import math
from typing import Any

__all__ = ["JCSError", "canonicalize", "parse", "serialize"]


class JCSError(ValueError):
    """Input that is not exactly one strict JSON value."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise JCSError(f"duplicate member name {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise JCSError(f"{name} is not JSON")


def _check_strings(v: Any) -> None:
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError as e:
            raise JCSError("a lone surrogate is not a Unicode scalar value") from e
    elif isinstance(v, list):
        for x in v:
            _check_strings(x)
    elif isinstance(v, dict):
        for k, x in v.items():
            _check_strings(k)
            _check_strings(x)


def _float(literal: str) -> float:
    f = float(literal)
    if math.isinf(f):
        raise JCSError("number out of range")
    return f


def parse(data: str | bytes) -> Any:
    """Parses exactly one strict JSON value from text or UTF-8 bytes."""
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError as e:
            raise JCSError("invalid UTF-8") from e
    else:
        text = data
    _check_strings(text)
    try:
        v = json.loads(text, object_pairs_hook=_pairs, parse_constant=_reject_constant, parse_int=_float, parse_float=_float)
    except json.JSONDecodeError as e:
        raise JCSError(f"not JSON: {e}") from e
    _check_strings(v)
    return v


def _number(x: float) -> str:
    """ECMAScript Number::toString for a finite double."""
    if math.isnan(x) or math.isinf(x):
        raise JCSError("numbers must be finite")
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    mantissa, _, exp = repr(abs(x)).partition("e")
    whole, _, frac = mantissa.partition(".")
    digits = whole + frac
    point = len(whole) + (int(exp) if exp else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    s = stripped.rstrip("0")
    k, n = len(s), point
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * -n + s
    else:
        e = n - 1
        out = (s if k == 1 else s[0] + "." + s[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def serialize(v: Any) -> str:
    """Serializes a JSON-like Python value canonically."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _number(float(v))
    if isinstance(v, str):
        _check_strings(v)
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(serialize(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(serialize(k) + ":" + serialize(x) for k, x in items) + "}"
    raise JCSError(f"cannot serialize {type(v).__name__}")


def canonicalize(data: str | bytes) -> str:
    """Returns the canonical form of JSON text or UTF-8 bytes."""
    return serialize(parse(data))
