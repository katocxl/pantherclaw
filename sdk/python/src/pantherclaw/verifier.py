# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Target-side verification of PantherClaw action tokens (PAP/1 §10,
HR-202): a service PantherClaw reaches through a target-enforced connection
runs a request only when its PAP-Action token was minted for exactly that
request, is unexpired and was never used before by any replica that shares
the replay store."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs, pap

__all__ = ["MAX_LIFETIME", "SKEW", "MemoryStore", "Refusal", "ReplayStore", "Spend", "Verifier", "action_token_kid"]

TYPE_ACTION_TOKEN = "pap-action+jwt"
MAX_LIFETIME = 60
SKEW = 5


class Refusal(Exception):
    """A refused request; it must not run. ``code`` names why: missing,
    bad_signature, wrong_issuer, wrong_audience, expired, body_mismatch,
    operation_mismatch, replayed or store_unavailable."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"action token refused: {code}: {detail}")
        self.code = code

    @property
    def status(self) -> int:
        """409 for a replay, 503 when keys or store are unreachable, 401 otherwise."""
        return 409 if self.code == "replayed" else 503 if self.code == "store_unavailable" else 401


@dataclass(frozen=True)
class Spend:
    """One token id to record as used until ``until`` (Unix seconds)."""

    id: str
    issued_at: int
    now: int
    until: int


class ReplayStore(Protocol):
    """Spends action token ids. ``use`` returns True on the first use and
    False on a replay; it must raise, never return True, when it cannot
    record. ``shared`` says whether every replica uses the same store."""

    shared: bool

    def use(self, spend: Spend) -> bool: ...


class MemoryStore:
    """A replay store for one replica. It never evicts an id early; when full
    it refuses. ``started`` (Unix seconds) is when it began recording:
    tokens issued before it may have been spent before a restart."""

    shared = False

    def __init__(self, capacity: int = 100_000, started: int = 0) -> None:
        self._capacity, self._started = capacity, started
        self._seen: dict[str, int] = {}
        self._lock = threading.Lock()

    def use(self, spend: Spend) -> bool:
        if spend.issued_at < self._started - SKEW:
            raise RuntimeError("the store began recording after the token was issued")
        with self._lock:
            if spend.id in self._seen:
                return False
            if len(self._seen) >= self._capacity:
                for k in [k for k, until in self._seen.items() if spend.now > until]:
                    del self._seen[k]
                if len(self._seen) >= self._capacity:
                    raise RuntimeError("the replay store is full")
            self._seen[spend.id] = spend.until
            return True


def action_token_kid(public_key: bytes) -> str:
    """The kid of an action-tokens key: "action-tokens-" and 22 characters of its thumbprint."""
    return "action-tokens-" + pap.thumbprint(public_key)[:22]


class Verifier:
    """Verifies action tokens against PantherClaw's JWKS for one target."""

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: str,
        store: ReplayStore,
        now: Callable[[], int] | None = None,
        fetch: Callable[[str], bytes] | None = None,
    ) -> None:
        if not (jwks_url and issuer and audience and store is not None):
            raise ValueError("jwks_url, issuer, audience and store are required")
        self._url, self._issuer, self._audience, self._store = jwks_url, issuer, audience, store
        self._now = now or (lambda: int(time.time()))
        self._fetch = fetch or _fetch
        self._keys: dict[str, bytes] | None = None
        self._fetched = 0
        self._tried = float("-inf")
        self._lock = threading.Lock()

    @property
    def single_replica(self) -> bool:
        """A verifier on a store for one replica cannot back an enforced claim for more (HR-024)."""
        return not self._store.shared

    def verify(self, token: str | None, body: bytes | str, match: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
        """Verifies the token of a request whose exact body is ``body`` and
        spends it; ``match`` says whether the claims' operation and target are
        what the request does. Raises Refusal."""
        if not token:
            raise Refusal("missing", "no PAP-Action header")
        c = self._signed(token)
        now = self._now()
        data = body.encode("utf-8") if isinstance(body, str) else body
        iat, exp = c.get("iat"), c.get("exp")
        if c.get("iss") != self._issuer:
            raise Refusal("wrong_issuer", str(c.get("iss")))
        if c.get("aud") != self._audience:
            raise Refusal("wrong_audience", str(c.get("aud")))
        if not (isinstance(iat, float) and isinstance(exp, float)) or exp <= iat or exp - iat > MAX_LIFETIME or now >= exp + SKEW or iat > now + SKEW:
            raise Refusal("expired", f"iat {iat} exp {exp}")
        p = c.get("pap")
        if not isinstance(p, dict) or p.get("v") != 1 or not isinstance(c.get("jti"), str) or not c["jti"] or len(c["jti"]) > 128:
            raise Refusal("bad_signature", "not a version 1 action token")
        if p.get("bh") != hashlib.sha256(data).hexdigest():
            raise Refusal("body_mismatch", "the body is not the one the token binds")
        if not match(c):
            raise Refusal("operation_mismatch", f"{p.get('op')} on {p.get('target')}")
        try:
            first = self._store.use(Spend(id=c["jti"], issued_at=int(iat), now=now, until=int(exp) + SKEW))
        except Exception as e:  # noqa: BLE001 - any store failure refuses
            raise Refusal("store_unavailable", str(e)) from e
        if not first:
            raise Refusal("replayed", c["jti"])
        return c

    def _signed(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(token) > 8 << 10 or len(parts) != 3:
            raise Refusal("bad_signature", "malformed")
        try:
            h = jcs.parse(pap.from_b64url(parts[0]))
            payload, sig = pap.from_b64url(parts[1]), pap.from_b64url(parts[2])
        except (ValueError, jcs.JCSError) as e:
            raise Refusal("bad_signature", "malformed") from e
        if not isinstance(h, dict) or set(h) != {"alg", "kid", "typ"} or h["alg"] not in ("EdDSA", "Ed25519") or h["typ"] != TYPE_ACTION_TOKEN:
            raise Refusal("bad_signature", "header")
        key = self._key(str(h["kid"]))
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(sig, (parts[0] + "." + parts[1]).encode("ascii"))
            c = jcs.parse(payload)
        except (InvalidSignature, ValueError, jcs.JCSError) as e:
            raise Refusal("bad_signature", "signature") from e
        if not isinstance(c, dict):
            raise Refusal("bad_signature", "claims")
        return c

    def _key(self, kid: str) -> bytes:
        """The JWKS is cached at most 15 minutes and refetched at most once a minute for an unknown kid."""
        with self._lock:
            now = self._now()
            stale = self._keys is None or now - self._fetched >= 900
            if (stale or kid not in (self._keys or {})) and (stale or now - self._tried >= 60):
                self._tried = now
                try:
                    self._keys, self._fetched = _keys(self._fetch(self._url)), now
                except Exception as e:  # noqa: BLE001 - an unreadable JWKS refuses
                    if stale:
                        self._keys = None
                        raise Refusal("store_unavailable", f"JWKS: {e}") from e
            key = (self._keys or {}).get(kid)
            if key is None:
                raise Refusal("bad_signature", f"unknown key {kid}")
            return key


def _keys(raw: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for k in json.loads(raw).get("keys", []):
        try:
            x = pap.from_b64url(str(k.get("x")))
        except ValueError:
            continue
        if k.get("kty") != "OKP" or k.get("crv") != "Ed25519" or k.get("alg", "EdDSA") not in ("EdDSA", "Ed25519") or len(x) != 32:
            continue
        if k.get("kid") == action_token_kid(x):
            out[k["kid"]] = x
    return out


def _fetch(url: str) -> bytes:
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1"):
        raise ValueError("the JWKS is fetched over TLS")
    with urllib.request.urlopen(url, timeout=5) as res:  # noqa: S310 - a configured https URL
        return res.read(64 << 10)
