# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The conformance runner over sdk/conformance: key files, workload tokens
and proofs."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from pantherclaw import pap
from pantherclaw.check import check_proof
from vectors import load


class Identity(unittest.TestCase):
    def test_key_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for i, c in enumerate(load("key_files.json")["cases"]):
                with self.subTest(c["name"]):
                    path = os.path.join(tmp, f"key{i}.json")
                    Path(path).write_bytes(c["file"].encode("utf-8"))
                    if c.get("reject"):
                        with self.assertRaises(ValueError):
                            pap.KeyFile.read(path)
                        continue
                    kf = pap.KeyFile.read(path)
                    key = kf.key()
                    self.assertEqual(pap.b64url(key.public_key), c["public_x"])
                    self.assertEqual(key.jkt, c["jkt"])
                    self.assertEqual(kf.marshal(), c["file"])
                    self.assertEqual(kf.identifier, c.get("identifier", ""))
                    with self.assertRaises(FileExistsError):
                        kf.write(path)

    def test_workload_tokens(self) -> None:
        f = load("workload_tokens.json")
        key = pap.WorkloadKey(pap.from_b64url(f["workload_key"]["seed"]))
        for c in f["cases"]:
            with self.subTest(c["name"]):
                if c.get("reject"):
                    with self.assertRaises(ValueError):
                        pap.parse_token_claims(c["token"])
                    continue
                claims = pap.parse_token_claims(c["token"])
                self.assertEqual(claims["cnf"]["jkt"], key.jkt)
                self.assertEqual(pap.ath(c["token"]), c["ath"])
                self.assertGreater(claims["exp"], c["valid_at"])

    def test_proofs(self) -> None:
        f = load("proofs.json")
        key = pap.WorkloadKey(pap.from_b64url(f["key"]["seed"]))
        for c in f["proofs"]:
            with self.subTest(c["name"]):
                got = pap.sign_proof(
                    key, c["method"], c["url"], c["body"], token=c.get("token", ""), nonce=c.get("nonce", ""), iat=c["iat"], jti=c["jti"]
                )
                self.assertEqual(got, c["proof"])
        for c in f["checks"]:
            with self.subTest(c["name"]):
                got = check_proof(c["proof"], c["method"], c["url"], c["body"], token=c.get("token", ""), now=c["now"])
                self.assertEqual(got, c["answer"])


if __name__ == "__main__":
    unittest.main()
