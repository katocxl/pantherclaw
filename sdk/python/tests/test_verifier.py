# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import json
import unittest
from typing import Any

from pantherclaw.verifier import MemoryStore, Refusal, Spend, Verifier
from vectors import load


class Failing:
    shared = True

    def use(self, spend: Spend) -> bool:
        raise ConnectionError("unreachable")


class VerifierTest(unittest.TestCase):
    def test_HR202_conformance_action_tokens(self) -> None:
        f = load("action_tokens.json")
        jwks = json.dumps(f["jwks"]).encode()
        for c in f["cases"]:
            with self.subTest(c["name"]):
                v = Verifier(
                    "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json",
                    c["issuer"],
                    c["audience"],
                    Failing() if c.get("store") == "unavailable" else MemoryStore(),
                    now=lambda c=c: c["now"],
                    fetch=lambda _url: jwks,
                )

                def match(cl: dict[str, Any], c: dict[str, Any] = c) -> bool:
                    t = cl["pap"]["target"]
                    return cl["pap"]["op"] == c["operation"] and t["type"] == c["target_type"] and t["id"] == c["target_id"]

                got = "ok"
                try:
                    v.verify(c["token"], c["body"], match)
                    if c.get("twice"):
                        v.verify(c["token"], c["body"], match)
                except Refusal as e:
                    got = e.code
                self.assertEqual(got, c["expect"])

    def test_HR024_a_memory_store_declares_the_verifier_single_replica(self) -> None:
        self.assertTrue(Verifier("https://x.test/jwks.json", "i", "a", MemoryStore()).single_replica)
        self.assertFalse(Verifier("https://x.test/jwks.json", "i", "a", Failing()).single_replica)

    def test_HR202_a_full_or_restarted_memory_store_refuses(self) -> None:
        full = MemoryStore(capacity=1, started=1000)
        self.assertTrue(full.use(Spend("a", 1000, 1000, 1065)))
        with self.assertRaises(RuntimeError):
            full.use(Spend("b", 1000, 1065, 1130))
        self.assertTrue(full.use(Spend("b", 1000, 1066, 1131)))
        with self.assertRaises(RuntimeError):
            MemoryStore(started=2000).use(Spend("c", 1900, 2000, 1965))

    def test_HR202_an_unknown_kid_refetches_at_most_once_a_minute_and_an_unreachable_jwks_refuses(self) -> None:
        f = load("action_tokens.json")
        stranger = next(c for c in f["cases"] if "not in the JWKS" in c["name"])
        jwks = json.dumps(f["jwks"]).encode()
        fetches: list[int] = []
        now = [stranger["now"]]

        def fetch(_url: str) -> bytes:
            fetches.append(1)
            return jwks

        v = Verifier("https://x.test/jwks.json", stranger["issuer"], stranger["audience"], MemoryStore(), now=lambda: now[0], fetch=fetch)
        for _ in range(5):
            with self.assertRaises(Refusal):
                v.verify(stranger["token"], stranger["body"], lambda _c: True)
        self.assertEqual(len(fetches), 1)
        now[0] += 61
        with self.assertRaises(Refusal):
            v.verify(stranger["token"], stranger["body"], lambda _c: True)
        self.assertEqual(len(fetches), 2)

        def down(_url: str) -> bytes:
            raise ConnectionError("unreachable")

        good = f["cases"][0]
        dv = Verifier("https://x.test/jwks.json", good["issuer"], good["audience"], MemoryStore(), now=lambda: good["now"], fetch=down)
        with self.assertRaises(Refusal) as e:
            dv.verify(good["token"], good["body"], lambda _c: True)
        self.assertEqual((e.exception.code, e.exception.status), ("store_unavailable", 503))


if __name__ == "__main__":
    unittest.main()
