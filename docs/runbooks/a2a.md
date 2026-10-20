# Peer agents over A2A

**Milestone:** M14 ([G0 M14](../g0/M14.md) D30–D33; [ADR-0029](../adr/0029-peer-agent-calls-a2a.md)). **Audience:** a Gateway Admin (`connection.manage`) connecting agents that talk to other agents over the A2A protocol (1.0.0), and owners of agents that receive such calls. Command flags below follow the brief; the M14 exit status records any change.

PantherClaw mediates A2A calls through the gateway: the requesting agent talks to `/a2a/{connection}` on the gateway, each call is decided under the requester's grant, and the gateway rebuilds what is sent. There are two kinds of peer:
- **Enrolled peer** (an agent of your organization, named on the connection): the peer works in a **child run of the requester's run** with a delegated grant no wider than the requester's grant and the connection's peer scope (HR-324..326). The requester's limits carry over.
- **External peer** (anything else): only the outgoing message is governed; what the remote agent does afterwards is under its own authority, and the route is labelled `PARTIAL` (R-41).

## 1. Create the connection

You need the peer's agent card URL (`https://…/.well-known/agent-card.json`). Creating the connection fetches the card and stores the pin as proposed; the connection cannot dispatch until a person holding `connection.manage` (Gateway Admin) (Org Admin does not hold that permission) opens the confirmation page it prints, checks the card, interface and skills, and confirms with a security key; the page re-reads the card and refuses if its digest is no longer the proposed one:

```bash
pclaw connection create helpdesk-agent --kind a2a --gateway <gateway id> --package pc.a2a \
  --access pantherclaw_held --config a2a.json --default-mode enforce
```

`A2AConfig` fields:

| Field | Meaning |
|---|---|
| `card_url` | HTTPS URL of the agent card (loopback only in dev) |
| `interface` | One interface the card declares: `JSONRPC` or `HTTP+JSON` and its URL (gRPC is refused) |
| `card_keys` | Optional pinned JWKS (at most 64 KiB); if the card is signed, a signature must verify against it (the pinned card itself is at most 256 KiB) |
| `skills` | The skill ids agents may use (a subset of the card's; at most 64, each at most 128 characters) |
| `peer_agent_id` | Optional: the enrolled agent of this organization that serves this endpoint |
| `peer_scope` | Bounds and limits the peer may use for requests from this route (required with `peer_agent_id`) |
| `max_answer_bytes`, `max_stream_seconds` | Defaults 1 MiB and 300 s; at most 8 MiB and 3600 s |

If the remote agent needs its own credential (bearer or API key per its card's security scheme), seal it with `pclaw seal --connection <id>`.

The gateway re-reads the card every 10 minutes and on configuration load. If its digest changes, or its signatures no longer verify, the gateway refuses the connection at once (`A2A_CARD_DRIFT`, nothing sent) and reports drift; the server **quarantines** the connection (reason `a2a_card_drift`) (HR-322). Review the new card and re-pin it: the re-pin is proposed until confirmed on the confirmation page with a security key, the old pin serving meanwhile, and the confirmed re-pin lifts the quarantine. `pclaw connection restore` alone does not accept a changed card.

## 2. What agents can call

Agents point their A2A client at `https://<gateway>/a2a/<connection>/.well-known/agent-card.json` (the gateway serves the pinned card with its own URL) and sign every request with PAP/1.

| Operation | A2A methods | Notes |
|---|---|---|
| `a2a.message.send` | `SendMessage`, `SendStreamingMessage` (`POST /message:send`, `/message:stream`) | irreversible request to another actor; `skill` from the allowed list; `text` (a `content` parameter) under disclosure limits, at most 32 KiB |
| `a2a.task.read` | `GetTask`, `ListTasks`, `SubscribeToTask` | read |
| `a2a.task.cancel` | `CancelTask` | write |

Refused: file, raw, url and data parts (`A2A_PART_UNSUPPORTED`); push-notification configuration and `GetExtendedAgentCard` (`PUSH_NOT_SUPPORTED`); task or context ids of tasks this run did not create through this connection. Streams are relayed event by event up to the size and time caps. Remote answers are data, never instructions (HR-327). A message's effect is checked through `GetTask`: `COMPLETED` is CONFIRMED; `FAILED`, `CANCELED`, `REJECTED` are NONE_CONFIRMED; within 600 s.

## 3. Enrolled peers: the peer side

For an enrolled peer, the requester's grant must allow delegation, checked when the call is decided (otherwise DENY `DELEGATION_NOT_ALLOWED`: no delegation, depth or fan-out caps reached, or organization caps). When the message is dispatched, PantherClaw creates (or reuses for the same requester run, connection and context) a child run for the peer agent. The run lasts at most 60 minutes and never beyond the requester's run, and its grant is the intersection of the requester's grant and `peer_scope`, with shared budgets and the requester's represented principal. Revoking the requester's run or grant revokes it. The run and grant are created through the same services as any child run and delegation, with the same checks.

The request reaches the peer with a PAP/1 action token (header `PAP-Action`) carrying the child run id in its `pc_peer_run` claim; the run id is never put in message metadata. In the peer agent, use the receiver helper before acting:

- Go: `sdk/go/a2a`
- Python: `pantherclaw.a2a.peer_run(headers, verifier)`
- TypeScript: `peerRun(headers, verifier)` from `@pantherclaw/sdk` (`a2a.ts`)

It verifies the token and returns the run id, which the peer uses as its `PAP-Run-Id` for its own calls. It refuses a message without a valid token (HR-325). The run binds to the first instance of the peer that uses it.

People with `a2a.peer_run.read` (Org Admin, Security Admin, Auditor) can list peer runs; they also appear in run lineage like any child run.

## 4. Development

`pantherclaw-sim a2a` is an A2A 1.0 agent with both bindings, an optionally signed card, tasks and states, SSE streaming, and faults: card drift, slow streams, oversized answers, `AUTH_REQUIRED`, and an optional `PAP-Action` requirement. `TestE2E_M14_PeerAgents` and range scenarios RT-049 (confused deputy), RT-050 (card swap) and RT-051 (task-id hijack) run against it.

## 5. Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| Connection quarantined, calls refused `A2A_CARD_DRIFT` | The card's digest changed or its signatures no longer verify | Review the card; re-pin it and confirm the re-pin on the confirmation page if expected |
| `DELEGATION_NOT_ALLOWED` | The requester's grant does not allow delegation to the peer | Issue the grant with delegation (depth and fan-out) |
| `A2A_PART_UNSUPPORTED` | The agent sent a non-text part | Send text only |
| The peer refuses the message | No or invalid action token (a direct call that skipped the gateway) | Route the requester through the gateway connection |
| The peer's action denied above a limit | The requester's limits carried over | Expected; widen the requester's grant if appropriate |
| Connection cannot dispatch after create | The pin is still proposed | Confirm it on the confirmation page with a security key |
