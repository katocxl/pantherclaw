# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Proof checks as PantherClaw makes them (PAP/1 §4, steps 2–5), for fake
gateways in tests and for services that verify PAP/1 themselves."""

from __future__ import annotations

import re
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, pap

__all__ = ["check_proof"]

_NONCE = re.compile(r"^[A-Za-z0-9_-]{22,64}\Z")
_PRINTABLE = re.compile(r"^[\x21-\x7e]+\Z")


def _same_htu(claimed: str, want: str) -> bool:
    """htu matches when scheme and host are equal without case and the
    escaped paths exactly, as PantherClaw compares them."""
    if "?" in claimed + want or "#" in claimed + want:
        return False
    try:
        a, b = pap.split_url(claimed), pap.split_url(want)
    except ValueError:
        return False
    return a[0] == b[0] and a[1].lower() == b[1].lower() and a[2] == b[2]


def check_proof(proof: str, method: str, url: str, body: bytes | str, token: str = "", now: int | None = None) -> str:
    """Checks a PAP-Proof against its request at ``now`` (Unix seconds,
    default the clock) and returns "ok" or the PAP-Error code PantherClaw
    answers: the header (alg EdDSA, typ, a public Ed25519 jwk and nothing
    else) and signature, the key binding to the token's cnf.jkt, htm, htu,
    ath, bh, iat, jti and the nonce's shape. The token itself is not
    verified here, and neither is whether the nonce is current or the jti
    new: "ok" is not the whole check. The caller checks the nonce against
    the ones it issued and spends the jti once, or it accepts replays."""
    if now is None:
        now = int(time.time())
    parts = proof.split(".")
    if len(proof) > 8 << 10 or re.search(r"\s", proof) or len(parts) != 3:
        return "invalid_proof"
    try:
        h: Any = jcs.parse(pap.from_b64url(parts[0]))
        c: Any = jcs.parse(pap.from_b64url(parts[1]))
        sig = pap.from_b64url(parts[2])
        if not isinstance(h, dict) or set(h) != {"alg", "jwk", "typ"} or not isinstance(h["jwk"], dict) or set(h["jwk"]) != {"crv", "kty", "x"}:
            return "invalid_proof"
        if h["alg"] != "EdDSA" or h["typ"] != pap.TYPE_PROOF or h["jwk"]["kty"] != "OKP" or h["jwk"]["crv"] != "Ed25519":
            return "invalid_proof"
        x = pap.from_b64url(h["jwk"]["x"])
        Ed25519PublicKey.from_public_bytes(x).verify(sig, (parts[0] + "." + parts[1]).encode("ascii"))
    except (ValueError, TypeError, InvalidSignature, jcs.JCSError):
        return "invalid_proof"
    if not isinstance(c, dict):
        return "invalid_proof"
    if token:
        try:
            if pap.thumbprint(x) != pap.parse_token_claims(token)["cnf"]["jkt"]:
                return "key_mismatch"
        except ValueError:
            return "invalid_token"
    if not method or c.get("htm") != method or not isinstance(c.get("htu"), str) or not _same_htu(c["htu"], url):
        return "invalid_proof"
    if (token and c.get("ath") != pap.ath(token)) or (not token and c.get("ath", "") != ""):
        return "invalid_proof"
    if c.get("bh") != pap.body_hash(body):
        return "body_hash_mismatch"
    iat = c.get("iat")
    if not isinstance(iat, float) or not iat.is_integer() or abs(iat) > 2**53 or iat > now + 60 or iat < now - 360:
        return "invalid_proof"
    jti = c.get("jti")
    if not isinstance(jti, str) or not 22 <= len(jti) <= 128 or not _PRINTABLE.match(jti):
        return "invalid_proof"
    if not isinstance(c.get("nonce"), str) or not _NONCE.match(c["nonce"]):
        return "use_nonce"
    return "ok"
