# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest

from pantherclaw import pap
from pantherclaw.check import check_proof


class PapTest(unittest.TestCase):
    def test_htu_keeps_scheme_host_and_path(self) -> None:
        self.assertEqual(pap.htu("https://gateway.example.test/sdk/local?debug=1#x"), "https://gateway.example.test/sdk/local")
        for bad in ("https://user:pw@gateway.example.test/", "ftp://gateway.example.test/", "/sdk/local"):
            with self.subTest(bad), self.assertRaises(ValueError):
                pap.htu(bad)

    def test_a_fresh_proof_checks_out_once_a_nonce_is_in_it(self) -> None:
        key = pap.KeyFile.new().key()
        now = int(time.time())
        url, body = "https://gateway.example.test/sdk/local", b'{"tool":"Read"}'
        proof = pap.sign_proof(key, "POST", url + "?q=1", body, nonce="Y29uZm9ybWFuY2Utbm9uY2UtMjAyNi0xMC0xMQ", iat=now)
        self.assertEqual(check_proof(proof, "POST", url, body, now=now), "ok")
        self.assertEqual(check_proof(proof, "POST", url, b"{}", now=now), "body_hash_mismatch")
        self.assertEqual(check_proof(pap.sign_proof(key, "POST", url, body, iat=now), "POST", url, body, now=now), "use_nonce")

    def test_a_new_key_file_is_owner_only_and_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "key.json")
            kf = pap.KeyFile.new()
            kf.identifier = "pc:org/x/agent/y/inst/z"
            kf.write(path)
            self.assertEqual(pap.KeyFile.read(path), kf)
            with self.assertRaises(FileExistsError):
                kf.write(path)
            if sys.platform != "win32":
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()


class Strictness(unittest.TestCase):
    def test_a_key_file_never_prints_its_seed(self) -> None:
        kf = pap.KeyFile.new()
        kf.identifier = "pc:org/o/agent/a/inst/i"
        for out in (repr(kf), str(kf), f"{kf}", f"{kf!r}"):
            self.assertNotIn(kf.private_key, out)
            self.assertIn(kf.identifier, out)

    def test_token_claims_of_the_wrong_shape_are_value_errors(self) -> None:
        for claims in ({"pap": [], "cnf": {"jkt": "x"}}, {"pap": {"v": 1}, "cnf": "x"}, {"pap": {"v": 1}, "cnf": {"jkt": 7}}):
            body = {"aud": "pantherclaw-gateway", "exp": 1, **claims}
            token = pap.b64url(b'{"alg":"EdDSA"}') + "." + pap.b64url(json.dumps(body).encode()) + "." + pap.b64url(b"sig")
            with self.assertRaises(ValueError):
                pap.parse_token_claims(token)

    def test_a_proof_with_a_fractional_iat_is_invalid(self) -> None:
        key = pap.KeyFile.new().key()
        url = "https://gateway.example.test/sdk/payments"
        header = '{"alg":"EdDSA","jwk":{"crv":"Ed25519","kty":"OKP","x":"' + pap.b64url(key.public_key) + '"},"typ":"pap-proof+jwt"}'
        for iat in ("1791201600.5", "9007199254740993"):
            claims = '{"htm":"POST","htu":"' + url + '","iat":' + iat + ',"jti":"abcdefghijklmnopqrstuvwx","bh":"' + pap.body_hash(b"") + '","nonce":"abcdefghijklmnopqrstuvwx"}'
            signing = pap.b64url(header.encode()) + "." + pap.b64url(claims.encode())
            proof = signing + "." + pap.b64url(key.sign(signing.encode()))
            self.assertEqual(check_proof(proof, "POST", url, b"", now=1791201600), "invalid_proof", iat)

    def test_a_token_check_never_raises(self) -> None:
        key = pap.KeyFile.new().key()
        url = "https://gateway.example.test/sdk/payments"
        header = '{"alg":"EdDSA","jwk":{"crv":"Ed25519","kty":"OKP","x":"' + pap.b64url(key.public_key) + '"},"typ":"pap-proof+jwt"}'
        claims = '{"htm":"POST","htu":"' + url + '","iat":1791201600,"jti":"abcdefghijklmnopqrstuvwx","bh":"' + pap.body_hash(b"") + '","nonce":"abcdefghijklmnopqrstuvwx"}'
        signing = pap.b64url(header.encode()) + "." + pap.b64url(claims.encode())
        proof = signing + "." + pap.b64url(key.sign(signing.encode()))
        for payload in (b"[" * 100000, b'{"exp":1,"exp":2}', b"[" * 2000 + b"]" * 2000):
            token = pap.b64url(b'{"alg":"EdDSA"}') + "." + pap.b64url(payload) + "." + pap.b64url(b"sig")
            self.assertEqual(check_proof(proof, "POST", url, b"", token=token, now=1791201600), "invalid_token")

