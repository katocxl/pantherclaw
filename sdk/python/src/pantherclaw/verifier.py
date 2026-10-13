# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Target-side verification of PantherClaw action tokens (PAP/1 §10,
HR-202): a service PantherClaw reaches through a target-enforced connection
runs a request only when its PAP-Action token was minted for exactly that
request, is unexpired and was never used before by any replica that shares
the replay store."""

from __future__ import annotations

import hashlib
import ipaddress
import threading
import time
import urllib.parse
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
    """One token to record as used until ``until`` (Unix seconds): its
    audience (the target's connection id) and id; a store keys by both."""

    audience: str
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
    it refuses. ``started`` (Unix seconds, default now) is when it began
    recording: a process that restarted has lost the ids it recorded, so
    tokens issued before it started plus the skew are refused (one issued
    up to SKEW after the start, by the Authority's clock, may have been
    spent before). The store fails closed for those few seconds."""

    shared = False

    def __init__(self, capacity: int = 100_000, started: int | None = None) -> None:
        self._capacity = capacity
        self._started = int(time.time()) if started is None else started
        self._seen: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def use(self, spend: Spend) -> bool:
        if spend.issued_at < self._started + SKEW:
            raise RuntimeError("the store began recording after the token was issued")
        key = (spend.audience, spend.id)
        with self._lock:
            if key in self._seen:
                return False
            if len(self._seen) >= self._capacity:
                for k in [k for k, until in self._seen.items() if spend.now > until]:
                    del self._seen[k]
                if len(self._seen) >= self._capacity:
                    raise RuntimeError("the replay store is full")
            self._seen[key] = spend.until
            return True


def _secure(url: str) -> bool:
    """Whether a URL is https, or http to a loopback address, without user information."""
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


def _integer(v: Any) -> bool:
    return isinstance(v, float) and v.is_integer() and abs(v) <= 2**53


def _well_formed(c: Any) -> bool:
    """Whether parsed claims have the shape of an action token's; anything
    else is bad_signature, as Go's decoding refuses it."""
    if not isinstance(c, dict) or not all(isinstance(c.get(k), str) for k in ("iss", "aud", "jti")):
        return False
    p = c.get("pap")
    return (
        _integer(c.get("iat"))
        and _integer(c.get("exp"))
        and isinstance(p, dict)
        and isinstance(p.get("bh"), str)
        and isinstance(p.get("op"), str)
        and isinstance(p.get("target"), dict)
    )


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
        if not _secure(jwks_url):
            raise ValueError("the JWKS URL must use https (http only on a loopback address)")
        self._url, self._issuer, self._audience, self._store = jwks_url, issuer, audience, store
        self._now = now or (lambda: int(time.time()))
        self._fetch = fetch or _fetch
        self._keys: dict[str, bytes] | None = None
        self._fetched = 0
        self._tried = float("-inf")
        self._lock = threading.Lock()
        # The JWKS fetch in flight, which every verification needing it
        # waits for, and the last fetch's error.
        self._flight: threading.Event | None = None
        self._fetch_error: Exception | None = None

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
        if exp <= iat or exp - iat > MAX_LIFETIME or now >= exp + SKEW or iat > now + SKEW:
            raise Refusal("expired", f"iat {iat} exp {exp}")
        p = c.get("pap")
        # pap.v is the number 1 (the parser gives floats), never true, which equals 1 in Python.
        if not isinstance(p, dict) or not isinstance(p.get("v"), float) or p["v"] != 1 or not isinstance(c.get("jti"), str) or not c["jti"] or len(c["jti"]) > 128:
            raise Refusal("bad_signature", "not a version 1 action token")
        if p.get("bh") != hashlib.sha256(data).hexdigest():
            raise Refusal("body_mismatch", "the body is not the one the token binds")
        if not match(c):
            raise Refusal("operation_mismatch", f"{p.get('op')} on {p.get('target')}")
        try:
            first = self._store.use(Spend(audience=c["aud"], id=c["jti"], issued_at=int(iat), now=now, until=int(exp) + SKEW))
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
        if not _well_formed(c):
            raise Refusal("bad_signature", "claims")
        return c

    def _key(self, kid: str) -> bytes:
        """The JWKS is cached at most 15 minutes and refetched at most once a
        minute for an unknown kid. One fetch runs at a time, outside the
        lock: verifications that need it wait for it, the others go on."""
        leader = False
        with self._lock:
            now = self._now()
            stale = self._keys is None or now - self._fetched >= 900
            flight = None
            if (stale or kid not in (self._keys or {})) and (stale or now - self._tried >= 60 or self._flight is not None):
                if self._flight is None:
                    self._flight, self._tried, leader = threading.Event(), now, True
                flight = self._flight
        if flight is not None and leader:
            keys: dict[str, bytes] | None = None
            error: Exception | None = None
            try:
                keys = _keys(self._fetch(self._url))
            except Exception as e:  # noqa: BLE001 - an unreadable JWKS refuses
                error = e
            with self._lock:
                if keys is not None:
                    self._keys, self._fetched = keys, now
                elif stale:
                    self._keys = None
                self._fetch_error, self._flight = error, None
            flight.set()
        elif flight is not None and not flight.wait(timeout=15):
            raise Refusal("store_unavailable", "JWKS: the fetch did not end")
        with self._lock:
            if self._keys is None or self._now() - self._fetched >= 900:
                raise Refusal("store_unavailable", f"JWKS: {self._fetch_error}")
            key = self._keys.get(kid)
        if key is None:
            raise Refusal("bad_signature", f"unknown key {kid}")
        return key


def _keys(raw: bytes) -> dict[str, bytes]:
    """The action-tokens keys of a JWKS, parsed strictly (a duplicate member
    fails the fetch)."""
    out: dict[str, bytes] = {}
    jwks = jcs.parse(raw)
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
        raise ValueError("not a JWKS")
    for k in jwks["keys"]:
        if not isinstance(k, dict):
            continue
        try:
            x = pap.from_b64url(str(k.get("x")))
        except ValueError:
            continue
        if k.get("kty") != "OKP" or k.get("crv") != "Ed25519" or k.get("alg", "EdDSA") not in ("EdDSA", "Ed25519") or len(x) != 32:
            continue
        if k.get("kid") == action_token_kid(x):
            out[k["kid"]] = x
    return out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _fetch(url: str) -> bytes:
    """Fetches the JWKS, following no redirect: one could hand the keys to
    anyone on the way (HR-202)."""
    if not _secure(url):
        raise ValueError("the JWKS is fetched over TLS")
    with urllib.request.build_opener(_NoRedirect).open(url, timeout=5) as res:  # noqa: S310 - a configured https URL
        raw = res.read((64 << 10) + 1)
    if len(raw) > 64 << 10:
        raise ValueError("the JWKS is too large")
    return raw
