# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""Loads the shared conformance vectors in sdk/conformance
(PANTHERCLAW_CONFORMANCE_DIR overrides the directory)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

DIR = Path(os.environ.get("PANTHERCLAW_CONFORMANCE_DIR") or Path(__file__).resolve().parents[2] / "conformance")


def load(name: str) -> Any:
    f = json.loads((DIR / name).read_text(encoding="utf-8"))
    assert f["format"] == "pantherclaw.conformance/v1", name
    return f
