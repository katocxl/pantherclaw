# Send GenAI spans to your own OTLP collector

PantherClaw can continue your agents' traces into your own OpenTelemetry backend: each decision, tool dispatch and model call becomes a span in the org's own OTLP collector (G0 M36; [ADR-0063](../adr/0063-telemetry-and-approval-reach.md); HR-785..788). Spans carry metadata only, never prompts, tool arguments, answers or approval text (founder decision FQ36-2). OTLP destinations are in the Business edition, like SIEM export.

This is separate from the operator's own telemetry ([observability.md](observability.md)), which is unchanged and keeps its allow-list (HR-380).

## 1. Let your agents' traces continue

PantherClaw reads a W3C `traceparent` header (and `tracestate`, up to 512 bytes) on every face, and `params._meta.traceparent` on MCP calls. Only the strict form is read: version `00`, a 32-hex trace id that is not all zero, a 16-hex span id and flags. Anything else is ignored and never refuses a call.

- **Python SDK:** forwards the current span's context when `opentelemetry` is importable.
- **Go and TypeScript SDKs:** pass the caller's `traceparent` through the client option.
- **Hooks, MCP and HTTP clients:** send the `traceparent` header (or `_meta.traceparent`) yourself.

The trace context is stored on the transaction. It is never part of the action, a digest, a binding or a decision, so a wrong or forged header changes only how spans are linked in your collector (T-355). It is not forwarded to a model provider unless the provider route already allowed that header.

Without a `traceparent`, PantherClaw uses one trace per run (SHA-256 of the run id).

## 2. Add a destination

A destination is an OTLP/HTTP traces endpoint (for example `https://otel.example.com/v1/traces`) with optional headers such as an API key. Use `OTLPDestinationService` (permission `otlp.manage`):

1. **Create** it with a name, the URL and its headers. The headers are sealed and never shown again. It starts PENDING and exports nothing.
2. **Activate** it with your security key (a fresh WebAuthn step-up, as for SIEM destinations).
3. **Test** it: one test request through the egress client, which reports the collector's answer.

The URL must pass the same checks as SIEM destinations: https, a public host, no redirects (HR-786).

## 3. What you get

Every 30 seconds each ACTIVE destination receives the new finalized records from its own cursor, as OTLP/HTTP protobuf, gzip, with a 10-second timeout. Resource attributes: `service.name=pantherclaw`, `pantherclaw.org_id`.

| Span | When | Attributes |
|---|---|---|
| `pantherclaw.decide` | The decision's time window | `pantherclaw.decision`, `pantherclaw.reason_code` (first code), `pantherclaw.transaction_id`, `pantherclaw.run_id`, `pantherclaw.agent_id`, `pantherclaw.operation`, `pantherclaw.channel`, `pantherclaw.coverage`, `pantherclaw.console_url` |
| `execute_tool <operation>` | Tool dispatch, for its dispatch time | `gen_ai.operation.name=execute_tool`, `gen_ai.tool.name`, `pantherclaw.outcome`; on MCP also `mcp.method.name=tools/call` |
| `chat <model>` | A model call | `gen_ai.operation.name=chat`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens` |

Effects are `pantherclaw.effect` span events with their state. Target ids that could be personal data are never sent, only the operation and the target type.

Span ids are derived from the transaction id and the span kind, so a re-export sends the same spans and the collector can deduplicate them (HR-788).

The GenAI semantic conventions are still in development, so attribute names may change in a later release (R-89).

## 4. Failures

A failing destination backs off. After 24 hours of failures it becomes DISABLED and the change is audited; fix the collector, then activate it again with your security key. Disable a destination at any time with Disable.
