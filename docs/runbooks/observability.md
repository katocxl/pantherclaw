# Runbook — Observability: traces, metrics, profiling and security events

**Milestone:** M13 wave 2 ([G0 M13](../g0/M13.md) D30, D31; [ADR-0033](../adr/0033-observability-exporter.md); HR-380..384, T-041, T-173). **Audience:** the operator of a hosted or self-hosted server. Configuration keys and commands follow the brief; the M13 exit status records any change.

## 1. What is exported

| Signal | Where it goes | Contents |
|---|---|---|
| Traces | OTLP/HTTP (protobuf) to `<endpoint>/v1/traces` | One span per RPC and per database query (named by the sqlc query name only). Attributes come only from a fixed allow-list: procedure, code, organization id, decision outcome, durations, sizes (HR-380) |
| Metrics | OTLP/HTTP to `<endpoint>/v1/metrics`, and as text on the admin listener | `pc_`-prefixed: RPC duration by procedure and code, decisions by outcome, database pool in use, idle and waiting, River jobs by kind and state, rate-limit refusals by scope, the maintenance-hold gauge |
| Logs | stdout as JSON (ship them with your log collector) | every line inside a request carries `trace_id` and `span_id`; security events as `security_event` lines (§4) |

Never exported: payloads, secrets, emails, tokens, SQL arguments. If you see one in a trace or metric, treat it as a security bug (HR-380).

## 2. Turn on the exporter

In the server configuration:

```json
"telemetry": {
  "otlp": {
    "endpoint": "https://otlp-gateway-<region>.grafana.net/otlp",
    "headers_file": "/srv/pantherclaw/secrets/otlp-headers",
    "sample_ratio": 0.1,
    "service_name": "pantherclaw-staging"
  }
}
```

- `headers_file` holds one `Name: value` header per line. For Grafana Cloud this is `Authorization: Basic <base64 of instance id:token>`. Keep the file readable only by the service user. It is a secret.
- `sample_ratio` defaults to 0.1. Errors are always sampled.
- An empty `endpoint` turns telemetry off; that is the default.
- The exporter never blocks requests (HR-381). When the backend is slow or down, spans are dropped and counted (§5). The server keeps serving.

## 3. Profiling and the metrics page (admin listener)

```json
"admin": { "addr": "127.0.0.1:6060" }
```

- It is off by default. It serves pprof (`/debug/pprof/`) and `/metrics` as text.
- The server refuses to start if `admin.addr` is not a loopback address (HR-382). To reach it from your machine, use an SSH tunnel: `ssh -N -L 6060:127.0.0.1:6060 <admin>@<host>`.
- A CPU profile: `go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30`.

## 4. Security events

After every committed ledger entry whose kind is in the closed security set, the server writes exactly one log line (HR-383):

```json
{"msg":"security_event","ts":"…","org":"…","ledger_seq":1234,"kind":"grant.revoked","direction":"tighten","object":{"type":"grant","id":"…"},"actor":{"type":"user","id":"…"}}
```

- **Tightening kinds:**
  - revocations: signing keys, gateways and gateway certificates, API keys, service-account keys, credentials and sealed credentials, grants, sessions, invitations, organization package-signing keys;
  - disablements: service accounts, users, identity issuers;
  - WebAuthn suspensions and removals;
  - the kill switch, containment, quarantine and agent suspension.
- **Loosening kinds:** the restore counterparts of the tightening kinds carry `direction: loosen`.
- The line never holds secrets or free text, only ids.

**Ship these lines off the host** (Grafana Cloud logs, or any store you can export as NDJSON). After a database restore they are how you re-apply what happened after the dump ([backup-restore.md](backup-restore.md) §7):

```bash
# with the server in maintenance hold (backup-restore.md §7)
pantherclaw-server restore reapply --from security-events.ndjson --since <dump time> --confirm --config <file>
```

`restore reapply` behaves as follows (HR-384):
- It applies only `direction: tighten` events.
- It is idempotent: an object that is already revoked, disabled or engaged is skipped.
- It works one organization per transaction.
- It is audited as `restore.reapplied`, with the count and the first and last sequence.
- It refuses unless the server is in maintenance hold.
- It reports kinds it does not know and never guesses.

Without `--confirm` it changes nothing.

## 5. Watch

- **Dropped spans or metrics.** The drop counter rises when the backend is unreachable or the queue overflows. Check the endpoint and the headers file; nothing else is affected.
- **Rate-limit refusals by scope.** A sustained rise for one organization is a flood (T-170); see [incident-response.md](incident-response.md).
- **Maintenance-hold gauge.** It is 1 while the hold is on. Outside a restore, it should always be 0.
- **Local stack.** `docker compose --profile observability up` starts grafana/otel-lgtm. Set the endpoint to `http://127.0.0.1:4318` in development.
