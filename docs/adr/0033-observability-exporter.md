# ADR-0033 — Observability exporter

**Status:** Accepted (2026-10-21; G0 M13 founder decision F5; the [G0 M13 brief](../g0/M13.md) records it). Answers the exporter question left open by G0 M1 deviation 4 (2026-10-10). The detailed design is added with wave 2.

**Context.** Since M1, OpenTelemetry is API-only: the server starts spans, no SDK or exporter is wired and nothing is exported. The upstream OTLP/HTTP trace exporter still pulls in gRPC and grpc-gateway as dependencies, which the dependency policy avoids for a security product whose server has no gRPC surface. A hosted deployment needs traces, logs that can be joined to them, and a way to profile the server, on a free monitoring plan.

**Decision** (F5).
1. **Our own small OTLP/HTTP exporter** that sends OTLP protobuf over HTTP, using only the generated OTLP message types; no gRPC and no grpc-gateway in the dependency graph.
2. **Trace ids in logs:** the structured JSON logs carry the trace and span ids, so a log line and its trace are joined in the backend.
3. **A private profiling port:** Go's profiling handlers on a separate listener that is never public (loopback or a private address only).
4. **Backend:** Grafana Cloud's free plan for staging; the exporter speaks plain OTLP, so the backend is configuration.
5. What is exported follows SB-4 and T-041: no secrets, credentials, payloads or untrusted text beyond the existing redaction types.

**Consequences.**
- A few hundred lines of exporter code to own and test, instead of a large transitive dependency tree.
- Metrics, the pgx tracer and the compose observability profile are decided with the wave 2 design (ARCHITECTURE §14).

**Alternatives.** The upstream OTLP/HTTP exporter (pulls in gRPC); export through logs only (loses trace structure); a Connect-based OTLP client (still more surface than the protobuf-over-HTTP subset needs).
