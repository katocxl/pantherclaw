# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import hashlib
import json
import time
import unittest
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pantherclaw import pap
from pantherclaw.a2a import OPERATION, peer_run
from pantherclaw.verifier import MemoryStore, Refusal, Verifier, action_token_kid

ISSUER = "https://pc.example.test"
AUDIENCE = "https://gw.example.test/a2a/peer"
RUN = "0190f3b4-7c2e-7aaa-8bbb-000000000042"


class Minter:
    def __init__(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.kid = action_token_kid(pub)
        self.jwks = json.dumps({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": pap.b64url(pub), "kid": self.kid, "alg": "EdDSA"}]}).encode()
        self.n = 0

    def token(self, body: bytes, op: str = OPERATION, run: str | None = RUN) -> str:
        self.n += 1
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": ISSUER, "aud": AUDIENCE, "jti": f"jti-{self.n}", "iat": now, "exp": now + 30,
            "pap": {"v": 1, "txn": "t", "act": "a", "bh": hashlib.sha256(body).hexdigest(), "op": op,
                    "target": {"type": "a2a.agent", "id": "peer"}},
        }
        if run is not None:
            claims["pc_peer_run"] = run
        h = pap.b64url(json.dumps({"alg": "EdDSA", "kid": self.kid, "typ": "pap-action+jwt"}, separators=(",", ":")).encode())
        p = pap.b64url(json.dumps(claims, separators=(",", ":")).encode())
        sig = self.key.sign(f"{h}.{p}".encode("ascii"))
        return f"{h}.{p}.{pap.b64url(sig)}"

    def verifier(self) -> Verifier:
        return Verifier("https://pc.example.test/.well-known/pantherclaw/jwks.json", ISSUER, AUDIENCE,
                        MemoryStore(started=int(time.time()) - 3600), fetch=lambda _url: self.jwks)


class PeerRunTest(unittest.TestCase):
    def test_HR325_peer_run_from_the_gateways_token(self) -> None:
        m = Minter()
        v = m.verifier()
        body = b'{"jsonrpc":"2.0","id":"t","method":"SendMessage","params":{}}'
        headers = {"pap-action": m.token(body)}
        self.assertEqual(peer_run(headers, body, v), RUN)
        cases = {
            "replayed": (headers, body),
            "missing": ({}, body),
            "body_mismatch": ({"PAP-Action": m.token(body)}, body + b" "),
            "operation_mismatch": ({"PAP-Action": m.token(body, op="payments.refund.create")}, body),
            "peer_run_missing": ({"PAP-Action": m.token(b"{}", run=None)}, b"{}"),
        }
        for code, (h, b) in cases.items():
            with self.subTest(code):
                with self.assertRaises(Refusal) as e:
                    peer_run(h, b, v)
                self.assertEqual(e.exception.code, code)


if __name__ == "__main__":
    unittest.main()
