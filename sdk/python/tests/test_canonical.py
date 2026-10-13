# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The conformance runner over sdk/conformance: canonical JSON, ActionIR and
approval bindings."""

from __future__ import annotations

import base64
import hashlib
import unittest

from pantherclaw import jcs
from pantherclaw.action import ActionError, parse_action
from vectors import load


class Canonical(unittest.TestCase):
    def test_jcs(self) -> None:
        for c in load("jcs.json")["cases"]:
            with self.subTest(c["name"]):
                data: str | bytes = bytes.fromhex(c["input_hex"]) if c.get("input_hex") else c["input"]
                if c.get("reject"):
                    with self.assertRaises(jcs.JCSError):
                        jcs.canonicalize(data)
                    continue
                got = jcs.canonicalize(data)
                self.assertEqual(got, c["canonical"])
                self.assertEqual(hashlib.sha256(got.encode("utf-8")).hexdigest(), c["sha256"])

    def test_actionir(self) -> None:
        for c in load("actionir.json")["cases"]:
            with self.subTest(c["name"]):
                data: str | bytes = bytes.fromhex(c["input_hex"]) if c.get("input_hex") else c["input"]
                if c.get("reject"):
                    with self.assertRaises(ActionError):
                        parse_action(data)
                    continue
                p = parse_action(data)
                self.assertEqual(p.canonical, c["canonical"])
                self.assertEqual(p.hash, c["action_hash"])

    def test_approval_bindings(self) -> None:
        for c in load("approval_bindings.json")["cases"]:
            with self.subTest(c["name"]):
                got = jcs.serialize(c["input"])
                self.assertEqual(got, c["canonical"])
                self.assertEqual(base64.urlsafe_b64encode(hashlib.sha256(got.encode("utf-8")).digest()).rstrip(b"=").decode(), c["binding"])


if __name__ == "__main__":
    unittest.main()
