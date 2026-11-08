# ADR-0063 — Telemetry and approval reach

**Status:** Proposed (2026-11-05; the [G0 M36](../g0/M36.md) brief records the coordinator decisions D1060–D1069). A stub: it is completed when M36's code is tested.

**Context.** Teams already watch their agents in an OpenTelemetry backend, but a trace stopped at PantherClaw: the gateway read no trace header and only the operator saw PantherClaw's own spans. Approvals reached people only as immediate notices to the deciders, with no view of how tired a decider was, no cover for an absence, no digest or quiet hours, and nothing on the phone except chat apps. Developers saw coverage and waiting approvals only in the console or the CLI.

**Decision.**
1. **Trace context, never a decision input** (HR-785; D1060). The gateway reads a strict W3C `traceparent` on every face and stores it on the transaction, outside the ActionIR, digests and bindings. Invalid input is ignored.
2. **Spans to each org's own collector** (HR-786..788; FQ36-1, FQ36-2). An org adds an OTLP/HTTP destination that a person activates with a security key, as for SIEM export. A per-org exporter sends metadata-only GenAI spans (`pantherclaw.decide`, `execute_tool`, `chat`) with idempotent ids. Operator telemetry and its allow-list stay as they were.
3. **Fatigue changes routing, never eligibility** (HR-789, HR-791). Fatigue is measured per decider; a flagged decider is routed last and an alert-only detection fires.
4. **Deputies route only** (HR-790; FQ36-3). A deputy is notified for an absent person only when already eligible for the request.
5. **Digests and quiet hours delay only that person** (HR-792); approval groups are read only.
6. **Web Push with link-only payloads** (HR-793), encrypted to the subscription, from a deployment VAPID key.
7. **A read-only editor** (HR-794; FQ36-4). The VS Code extension reads through the signed-in `pclaw` and holds no token; it opens the console to decide.
8. **No new approve path** (HR-789): nothing added in M36 approves, declines or releases a hold.

**Consequences.**
- GenAI attribute names may change as the conventions settle (R-89).
- Push services see when a notice is sent and to which subscription (R-90).
- A trace id in a collector is the agent's claim; PantherClaw's own ids stay authoritative.
- Marketplace and Open VSX publishing of the extension is a founder step.

**Alternatives.**
- Adding org spans to the operator's telemetry (FQ36-1 chose each org's own collector).
- Spans with prompts, arguments or answers (FQ36-2 chose metadata only).
- Deputies who become eligible (FQ36-3 chose routing and notifications only).
- An extension with its own token or an approve button (FQ36-4 chose read only through `pclaw`).
- Auto-approving or auto-declining when a decider is fatigued or a hold times out (rejected: holds stay held, then expire).
