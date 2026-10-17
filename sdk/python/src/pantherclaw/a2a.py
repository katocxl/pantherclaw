# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""The receiving side of a PantherClaw peer agent call (G0 M14 D33,
HR-325): an enrolled agent that serves A2A takes a message only when the
gateway sent it for a requester whose grant allows it, and then acts in the
delegated run PantherClaw created for it.

Every message the gateway sends carries a PAP-Action token minted for
exactly that request (its body, operation ``a2a.message.send``, target type
``a2a.agent``) with the claim ``pc_peer_run`` naming the child run.
:func:`peer_run` verifies the token with the target verifier (signature,
issuer, audience, lifetime, body, single use) and returns the run id, which
the agent then sends as its PAP-Run-Id. A message without a valid token,
one sent directly to the agent, is refused."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from .verifier import Refusal, Verifier

__all__ = ["OPERATION", "TARGET_TYPE", "peer_run"]

OPERATION = "a2a.message.send"
TARGET_TYPE = "a2a.agent"
HEADER_ACTION = "PAP-Action"

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def peer_run(headers: Mapping[str, str], body: bytes | str, verifier: Verifier) -> str:
    """Verifies the PAP-Action token of an A2A request (its headers and exact
    body), spends it, and returns the peer run it names. Raises Refusal:
    ``missing`` for a message the gateway did not send, ``peer_run_missing``
    for a token that names no peer run (the connection has no peer agent),
    and the verifier's codes otherwise."""

    def match(c: dict[str, Any]) -> bool:
        p = c["pap"]
        return p.get("op") == OPERATION and isinstance(p.get("target"), dict) and p["target"].get("type") == TARGET_TYPE

    claims = verifier.verify(_header(headers, HEADER_ACTION), body, match)
    run = claims.get("pc_peer_run")
    if not isinstance(run, str) or not _UUID.match(run):
        raise Refusal("peer_run_missing", "the action token names no peer run")
    return run
