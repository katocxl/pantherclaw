# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Joshua Kato

"""PantherClawToolNode: LangGraph's ToolNode over guarded tools."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from langgraph.prebuilt import ToolNode

from pantherclaw.client import Client, Outbound

from . import guard_tools


class PantherClawToolNode(ToolNode):
    """A ToolNode whose every tool is guarded (see guard_tools). With
    ``on_hold="interrupt"`` a held call interrupts the graph with
    ``{"pantherclaw": {"transaction_id", "action_id", "deadline"}}``: once an
    eligible person approved it in PantherClaw, resume the graph (any resume
    value, with a checkpointer) and the identical call is resubmitted with
    the same action id, running only on PantherClaw's allow. Other keyword
    arguments go to ToolNode."""

    def __init__(
        self,
        tools: Sequence[Any],
        client: Client,
        connection: str,
        *,
        on_hold: str = "wait",
        wait: float = 300.0,
        observe_unmapped: bool = False,
        raise_on_refusal: bool = False,
        on_dispatch: Callable[[str, Outbound], Any] | None = None,
        **kwargs: Any,
    ) -> None:
        guarded = guard_tools(tools, client, connection, on_hold=on_hold, wait=wait, observe_unmapped=observe_unmapped,
                              raise_on_refusal=raise_on_refusal, on_dispatch=on_dispatch)
        super().__init__(guarded, **kwargs)
