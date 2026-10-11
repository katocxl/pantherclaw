# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

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
