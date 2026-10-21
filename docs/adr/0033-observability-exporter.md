# ADR-0033 — Observability exporter

**Status:** Accepted (2026-10-21; G0 M13 founder decision F5 and coordinator decisions D30, D31; the [G0 M13 brief](../g0/M13.md) records them). Answers the exporter question that G0 M1 deviation 4 left open on 2026-10-10. Operating procedure: [observability.md](../runbooks/observability.md).

**Context.** Since M1, OpenTelemetry has been API-only: the server starts spans, but no SDK or exporter is wired, so nothing is exported. The upstream OTLP/HTTP trace exporter still brings in gRPC and grpc-gateway as dependencies. The dependency policy avoids them for a security product whose server has no gRPC surface. A hosted deployment needs:
- traces;
- metrics;
- logs that can be joined to the traces;
- a way to profile the server;
- an operator who learns, after a restore, which revocations happened after the dump (D20).

All of this has to run on a free monitoring plan.

**Decision** (F5, D30, D31).
1. **The official SDK, our own exporter.**
   - The SDK is `go.opentelemetry.io/otel/sdk` and `sdk/metric`.
   - The exporter is our own. The OTLP `.proto` message files (opentelemetry-proto, Apache-2.0) are vendored under `proto/third_party/otlp` and generated as messages only, with no gRPC or Connect stubs.
   - It sends gzip-compressed `application/x-protobuf` with POST to `<endpoint>/v1/traces` and `<endpoint>/v1/metrics`, with the headers read from `telemetry.otlp.headers_file` and a 10 s timeout.
   - Configuration is `telemetry.otlp.{endpoint, headers_file, sample_ratio, service_name}`. The default sample ratio is 0.1, and errors are always sampled.
   - An empty endpoint turns telemetry off. Grafana Cloud's free plan is the staging backend. Since the exporter speaks plain OTLP, the backend is a configuration choice.
2. **Fixed attributes (HR-380).**
   - One allow-list governs span and metric attributes: procedure, code, organization id, decision outcome, durations and sizes.
   - A single filter applies it, and a test walks every attribute key used.
   - Payloads, secrets, emails, tokens and SQL arguments are never exported (SB-4, T-041).
3. **Never blocking (HR-381).**
   - The queue is bounded: 2048 spans, batches of 512, flushed every 5 s.
   - On overflow or an export error, data is dropped and counted; a request never waits for telemetry.
4. **What is measured.**
   - The pgx tracer opens one span per query, named by the sqlc query name only.
   - Metrics have fixed names with the `pc_` prefix:
     - RPC duration by procedure and code;
     - decisions by outcome;
     - database pool in use, idle and waiting;
     - River jobs by kind and state;
     - rate-limit refusals by scope;
     - a maintenance-hold gauge.
   - Log lines carry `trace_id` and `span_id`.
5. **A private admin listener (HR-382).** `admin.addr` serves pprof and `/metrics` as text. It is off by default and refuses any address that is not loopback.
6. **Security events as log lines (HR-383, HR-384).**
   - After commit, the evidence chainer emits one structured `security_event` line for every ledger entry whose kind is in a closed security set: revocations, disablements, suspensions, the kill switch, containment and quarantine, organization and account deletions (D41), and their restore counterparts.
   - Each line has the fields {ts, org, ledger_seq, kind, direction, object{type,id}, actor{type,id}}, with no secrets and no free text.
   - Shipped off the host with the other logs, these lines are what `pantherclaw-server restore reapply --from <ndjson> --confirm` re-applies after a restore. It applies only tightening events, idempotently, one organization per transaction, audited, and only under the maintenance hold.
7. **Local use.** A compose `observability` profile runs grafana/otel-lgtm.

**Consequences.**
- We own a small exporter and its tests instead of a large transitive dependency tree. The vendored message definitions follow upstream releases under the dependency policy's cooldown.
- Sampling and the dropping queue mean traces are incomplete by design. Security evidence never depends on telemetry; it lives in the ledger.
- The security-event lines turn the restore procedure (D20, R-61) from a manual reconstruction into a replay, bounded by what the shipped logs hold.

**Alternatives.**
- The upstream OTLP/HTTP exporter: it brings in gRPC.
- Exporting through logs only: the trace structure is lost.
- A Connect-based OTLP client: more surface than the protobuf-over-HTTP subset needs.
- A Prometheus pull endpoint on the public listener: it would expose operational detail.
