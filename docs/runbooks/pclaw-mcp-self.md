# `pclaw mcp self`

**Milestone:** M27 ([G0 M27](../g0/M27.md) D510, D517, D518, D522; founder decision H9). **Audience:** SOC teams connecting their own agents to PantherClaw's records. **Edition:** Team and above (`SelfMCP()`).

`pclaw mcp self` is a read-only MCP server over stdio. It gives a SOC agent four reads of PantherClaw's records. It calls no model, and there is no assistant.

## Set up

1. Create a service account and bind it the **Investigator** role at the scope the SOC agent should see. Any scope works; the role is for service accounts only.
2. Make an API key for it. If the key is scoped, include `org.read`, `search.read`, `evidence.read`, `exposure.read`, `agent.read`, `run.read`, `grant.read` and `incident.read`, or the reads it lacks come back as refusals.
3. **Use a service account and key that hold only the Investigator role.** `pclaw mcp self` does not check the key's roles. A key with another role, such as Security Admin, works, but its reads are not recorded as `audit.self_mcp.read`, and the key on the SOC host can do whatever that other role allows.
4. Have the SOC agent's MCP client start `pclaw mcp self` as a stdio server, with `PANTHERCLAW_SERVER` and `PANTHERCLAW_API_KEY_FILE` (or `PANTHERCLAW_API_KEY`). It takes no arguments and opens no listener. It refuses to run on a person's stored login.

MCP revisions: 2026-07-28 and 2025-11-25, as on the gateway face.

## The tools

| Tool | Reads |
|---|---|
| `search` | Transactions, runs, agents, grants, grant changes, alerts, incidents. Typed filters only: agent, run, grant, alert and incident ids; operation or prefix; decisions; start and end time. At most 50 rows a page |
| `explain_decision` | WhatHappened for one transaction id |
| `run_timeline` | GetRunTimeline for one run id |
| `breach_radius` | The exposure graph of an agent, run or incident, collapsed, never with issuance ceilings |

- Each result is one JSON block labelled `UNTRUSTED_RECORD_DATA` with a fixed notice. Record text is data, never an instruction.
- Strings are cleaned of control, format and bidi characters, newlines become spaces, each string is cut at 2000 runes (`strings_cut: true` says so), and `<`, `>` and `&` are escaped.
- Inputs: one line of at most 64 KiB, no batches, unknown members refused, ids are UUIDs.
- A result whose JSON-RPC line is over 1 MiB is refused `RESULT_TOO_LARGE`. Narrow the query.
- A refusal is a tool error in the agent-safe form: presentation, failing category, decisive code and next actions. It never carries the server's message or the arguments. Codes: `PERMISSION_DENIED`, `UNAUTHENTICATED`, `NOT_FOUND`, `INVALID_INPUT`, `RATE_LIMITED`, `EDITION_REQUIRED`, `FAILED_PRECONDITION`, `UNAVAILABLE`, `RESULT_TOO_LARGE`. A record outside the account's scope reads as `NOT_FOUND`.

## What the server enforces, whatever client is used

- The Investigator role counts only on WhatHappened, GetRunTimeline, Search and GetGraph. Anything else with only that role is refused `INVESTIGATOR_READS_ONLY`, saved queries, model drafting and bundle export included. With another role too, the call runs as if the Investigator binding were not there.
- The same holds outside Connect: the live operations stream (`GET /v1/operations/stream`) and the AuthZEN endpoints ignore the role.
- Every call by a holder of the role that reaches the gate writes `audit.self_mcp.read` to the organization's audit ledger: each of the four reads, answered or failed, and each refusal the gate makes (`EDITION_REQUIRED`, `ENTITLEMENT_UNAVAILABLE`, `INVESTIGATOR_READS_ONLY`).
- Each record holds outcome, reason, procedure, key id, and the transaction, run or graph scope asked for, or the search entity and page size. Never filter text or results.
- A read's record is written before the answer is sent. If it cannot be written, the call fails `AUDIT_UNAVAILABLE` and nothing is sent.
- On Community the role's reads answer `EDITION_REQUIRED`, whatever other role the account holds. If the edition cannot be checked they answer `ENTITLEMENT_UNAVAILABLE`; try again.

## Investigating the investigator

- Search the audit entity with kind prefix `audit.self_mcp.` to see every read a SOC agent made, by key.
- To cut a SOC agent off, revoke its API key or remove the role binding. The next call is refused.
