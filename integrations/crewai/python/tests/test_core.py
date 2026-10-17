# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""pantherclaw-crewai's decision core on every supported Python, 3.14
included, where CrewAI itself is not installed (T-150)."""

from __future__ import annotations

import unittest

import conformance  # noqa: F401 - puts the repository sources on the path
from conformance import core_adapter, replay, same_copies

from pantherclaw_crewai._guard import Guard, PantherClawRefused


class CoreTest(unittest.TestCase):
    def test_HR328_every_wrapper_case_replays_through_the_decision_core(self) -> None:
        replay(self, core_adapter(Guard), PantherClawRefused)

    def test_the_shared_files_are_identical_in_every_wrapper(self) -> None:
        same_copies(self, "src/{pkg}/_guard.py")
        same_copies(self, "tests/conformance.py")


if __name__ == "__main__":
    unittest.main()
