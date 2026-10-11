# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
        valid = f["cases"][0]
        for c in f["cases"]:
            with self.subTest(c["name"]):
                v = Verifier(
                    "https://pantherclaw.example.test/.well-known/pantherclaw/jwks.json",
                    c["issuer"],
                    c["audience"],
                    # A store that began recording before any vector's token.
                    Failing() if c.get("store") == "unavailable" else MemoryStore(started=c["now"] - 3600),
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
                if c.get("then_valid"):
                    # Verify before insert: the refusal left the token unspent.
                    v.verify(c["token"], valid["body"], lambda cl, w=valid: match(cl, w))

    def test_HR024_a_memory_store_declares_the_verifier_single_replica(self) -> None:
        self.assertTrue(Verifier("https://x.test/jwks.json", "i", "a", MemoryStore()).single_replica)
        self.assertFalse(Verifier("https://x.test/jwks.json", "i", "a", Failing()).single_replica)

    def test_HR202_a_full_or_restarted_memory_store_refuses(self) -> None:
        full = MemoryStore(capacity=1, started=900)
        self.assertTrue(full.use(Spend("a", "a", 1000, 1000, 1065)))
        with self.assertRaises(RuntimeError):
            full.use(Spend("a", "b", 1000, 1065, 1130))
        self.assertTrue(full.use(Spend("a", "b", 1000, 1066, 1131)))
        # A token issued before the start plus the skew may have been spent before a restart.
        restarted = MemoryStore(started=2000)
        for issued_at in (1900, 1995, 2000, 2004):
            with self.assertRaises(RuntimeError):
                restarted.use(Spend("a", f"c{issued_at}", issued_at, 2010, issued_at + 65))
        self.assertTrue(restarted.use(Spend("a", "c2005", 2005, 2010, 2070)))
        now = int(time.time())
        with self.assertRaises(RuntimeError):
            MemoryStore().use(Spend("a", "d", now - 1, now, now + 60))

    def test_HR202_the_memory_store_keys_by_audience_and_id(self) -> None:
        m = MemoryStore(started=0)
        self.assertEqual([m.use(Spend(aud, "jti", 100, 100, 160)) for aud in ("a", "b", "a")], [True, True, False])

    def test_HR202_the_jwks_comes_over_tls_without_redirects(self) -> None:
        for u in ("http://pantherclaw.example.test/jwks.json", "http://127.0.0.1.attacker.example/jwks.json", "http://127.0.0.1@attacker.example/jwks.json",
                  "http://10.0.0.1/jwks.json"):
            with self.assertRaises(ValueError):
                Verifier(u, "i", "a", Failing())
        f = load("action_tokens.json")
        good = f["cases"][0]
        reached: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                reached.append(self.path)
                if self.path == "/jwks.json":
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere.json")
                    self.end_headers()
                    return
                b = json.dumps(f["jwks"]).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            v = Verifier(f"http://127.0.0.1:{srv.server_address[1]}/jwks.json", good["issuer"], good["audience"], MemoryStore(started=0),
                         now=lambda: good["now"])
            with self.assertRaises(Refusal) as e:
                v.verify(good["token"], good["body"], lambda _c: True)
            self.assertEqual((e.exception.code, reached), ("store_unavailable", ["/jwks.json"]))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_HR202_one_jwks_fetch_at_a_time(self) -> None:
        f = load("action_tokens.json")
        good = f["cases"][0]
        jwks = json.dumps(f["jwks"]).encode()
        fetches: list[int] = []

        def slow(_url: str) -> bytes:
            fetches.append(1)
            time.sleep(0.1)
            return jwks

        v = Verifier("https://x.test/jwks.json", good["issuer"], good["audience"], MemoryStore(started=0), now=lambda: good["now"], fetch=slow)
        codes: list[str] = []

        def one() -> None:
            try:
                v.verify(good["token"], good["body"], lambda _c: False)
            except Refusal as e:
                codes.append(e.code)

        threads = [threading.Thread(target=one) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual((codes, len(fetches)), (["operation_mismatch"] * 8, 1))
        dup = Verifier("https://x.test/jwks.json", good["issuer"], good["audience"], MemoryStore(started=0), now=lambda: good["now"],
                       fetch=lambda _u: b'{"keys":[],' + jwks[1:])
        with self.assertRaises(Refusal) as e:
            dup.verify(good["token"], good["body"], lambda _c: True)
        self.assertEqual(e.exception.code, "store_unavailable")

    def test_HR202_an_unknown_kid_refetches_at_most_once_a_minute_and_an_unreachable_jwks_refuses(self) -> None:
        f = load("action_tokens.json")
        stranger = next(c for c in f["cases"] if "not in the JWKS" in c["name"])
        jwks = json.dumps(f["jwks"]).encode()
        fetches: list[int] = []
        now = [stranger["now"]]

        def fetch(_url: str) -> bytes:
            fetches.append(1)
            return jwks

        v = Verifier("https://x.test/jwks.json", stranger["issuer"], stranger["audience"], MemoryStore(started=0), now=lambda: now[0], fetch=fetch)
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
        dv = Verifier("https://x.test/jwks.json", good["issuer"], good["audience"], MemoryStore(started=0), now=lambda: good["now"], fetch=down)
        with self.assertRaises(Refusal) as e:
            dv.verify(good["token"], good["body"], lambda _c: True)
        self.assertEqual((e.exception.code, e.exception.status), ("store_unavailable", 503))


if __name__ == "__main__":
    unittest.main()
