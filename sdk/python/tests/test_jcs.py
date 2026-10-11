# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

from __future__ import annotations

import math
import unittest

from pantherclaw import jcs


class JCSTest(unittest.TestCase):
    def test_python_values_serialize_canonically(self) -> None:
        self.assertEqual(jcs.serialize({"b": 1, "a": [True, None, -0.0, "x", False]}), '{"a":[true,null,0,"x",false],"b":1}')
        for bad in (math.nan, math.inf, object()):
            with self.assertRaises(jcs.JCSError):
                jcs.serialize(bad)

    def test_numbers_are_written_as_ecmascript_writes_them(self) -> None:
        cases = {1e21: "1e+21", 1e20: "100000000000000000000", 1e-7: "1e-7", 0.000001: "0.000001", 5e-324: "5e-324", 1.5: "1.5", 100: "100"}
        for value, want in cases.items():
            with self.subTest(value):
                self.assertEqual(jcs.serialize(value), want)

    def test_text_and_bytes_parse_alike_and_refuse_alike(self) -> None:
        self.assertEqual(jcs.canonicalize('{"b":1,"a":2}'), jcs.canonicalize(b'{"b":1,"a":2}'))
        for bad in ('{"a":NaN}', '{"a":Infinity}', "[1e400]", b'{"a":"\xff"}'):
            with self.subTest(bad), self.assertRaises(jcs.JCSError):
                jcs.canonicalize(bad)


if __name__ == "__main__":
    unittest.main()
