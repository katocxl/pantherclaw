# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PAP/1 primitives: the workload key file, request proofs, key thumbprints,
workload token claims and action hashes (docs/protocol/PAP-1.md §3–§4, §6),
checked against sdk/conformance."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import jcs
from .action import parse_action

VERSION = 1
HEADER_PROOF = "PAP-Proof"
HEADER_NONCE = "PAP-Nonce"
HEADER_ERROR = "PAP-Error"
HEADER_ACTION = "PAP-Action"
TYPE_PROOF = "pap-proof+jwt"
TOKEN_AUDIENCE = "pantherclaw-gateway"

_B64URL = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url(data: bytes) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(s: str) -> bytes:
    """Strict base64url decoding: the alphabet only, no padding."""
    if not _B64URL.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url without padding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sha256(data: bytes | str) -> bytes:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).digest()


def body_hash(body: bytes | str) -> str:
    """bh: base64url(SHA-256(body))."""
    return b64url(sha256(body))


def ath(token: str) -> str:
    """ath: base64url(SHA-256(token))."""
    return b64url(sha256(token))


def thumbprint(public_key: bytes) -> str:
    """The RFC 7638 thumbprint (jkt) of an Ed25519 public key."""
    return b64url(sha256('{"crv":"Ed25519","kty":"OKP","x":"' + b64url(public_key) + '"}'))


class WorkloadKey:
    """An Ed25519 workload key derived from its 32-byte seed."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.jkt = thumbprint(self.public_key)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


@dataclass
class KeyFile:
    """The workload key file (PAP/1 §3.1). Keep it owner-only; never log it."""

    private_key: str
    identifier: str = ""
    server: str = ""
    run_id: str = ""

    def key(self) -> WorkloadKey:
        if len(self.private_key) != 43:
            raise ValueError("key file: private_key must be a base64url Ed25519 seed")
        return WorkloadKey(from_b64url(self.private_key))

    def marshal(self) -> str:
        """The file's text as PantherClaw writes it."""
        members = {k: getattr(self, k) for k in ("private_key", "identifier", "server", "run_id") if getattr(self, k)}
        return json.dumps(members, separators=(",", ":"), ensure_ascii=False) + "\n"

    @classmethod
    def new(cls) -> KeyFile:
        return cls(private_key=b64url(secrets.token_bytes(32)))

    @classmethod
    def parse(cls, data: str | bytes) -> KeyFile:
        """Parses a key file strictly: unknown or duplicate members are refused."""
        v = jcs.parse(data)
        if not isinstance(v, dict) or any(not isinstance(x, str) for x in v.values()):
            raise ValueError("key file: a JSON object of strings")
        unknown = set(v) - {"private_key", "identifier", "server", "run_id"}
        if unknown or "private_key" not in v:
            raise ValueError(f"key file: unexpected or missing members {sorted(unknown)}")
        kf = cls(**v)
        kf.key()
        return kf

    @classmethod
    def read(cls, path: str) -> KeyFile:
        with open(path, "rb") as f:
            return cls.parse(f.read())

    def write(self, path: str) -> None:
        """Writes a new owner-only file; an existing file is never replaced."""
        self.key()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(self.marshal())


def htu(url: str) -> str:
    """htu: scheme, host and path of a request URL."""
    u = urlsplit(url)
    if u.scheme not in ("https", "http") or not u.netloc or "@" in u.netloc:
        raise ValueError("the request URL must be an absolute http(s) URL without user information")
    return f"{u.scheme}://{u.netloc}{u.path}"


def sign_proof(
    key: WorkloadKey,
    method: str,
    url: str,
    body: bytes | str = b"",
    token: str = "",
    nonce: str = "",
    iat: int | None = None,
    jti: str = "",
) -> str:
    """Signs a PAP-Proof JWS (PAP/1 §4) byte for byte as PantherClaw does."""
    header = '{"alg":"EdDSA","jwk":{"crv":"Ed25519","kty":"OKP","x":"' + b64url(key.public_key) + '"},"typ":"' + TYPE_PROOF + '"}'
    claims: dict[str, Any] = {
        "htm": method,
        "htu": htu(url),
        "iat": int(time.time()) if iat is None else iat,
        "jti": jti or b64url(secrets.token_bytes(16)),
    }
    if token:
        claims["ath"] = ath(token)
    claims["bh"] = body_hash(body)
    if nonce:
        claims["nonce"] = nonce
    signing_input = b64url(header.encode()) + "." + b64url(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    return signing_input + "." + b64url(key.sign(signing_input.encode("ascii")))


def parse_token_claims(token: str) -> dict[str, Any]:
    """Reads a workload token's claims without verifying it, to know when to
    renew it and which key it is bound to. PantherClaw verifies the token."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a compact JWS")
    c = json.loads(from_b64url(parts[1]))
    if (
        not isinstance(c, dict)
        or c.get("pap", {}).get("v") != VERSION
        or c.get("aud") != TOKEN_AUDIENCE
        or not isinstance(c.get("exp"), int)
        or not c.get("cnf", {}).get("jkt")
    ):
        raise ValueError("not a PAP/1 workload token")
    return c


def action_hash(action: str | bytes) -> str:
    """The action hash of ActionIR, checked as strictly as PantherClaw does (PAP/1 §6)."""
    return parse_action(action).hash
