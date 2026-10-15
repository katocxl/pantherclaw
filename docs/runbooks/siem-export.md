# Runbook — SIEM export (OCSF 1.9 over Standard Webhooks)

**Milestone:** M10 · **Owner:** the org's Security Admin (`siem.manage`) · **Edition:** Business · **Status:** procedure written from the [G0 M10 brief](../g0/M10.md) (D35, D36); tested at the M10 exit.

PantherClaw sends decisions, alerts, incidents, audit, containment and coverage events to a SIEM as OCSF 1.9 batches over HTTPS, signed with Standard Webhooks. Background: [g0/M10.md](../g0/M10.md), [ADR-0026](../adr/0026-reflex-detection-containment-and-signals.md), HR-259, HR-260, HR-070..077.

## 1. Add a destination

1. Create it through the `siem.proto` API (`siem.manage`, a person) with:
   - the HTTPS URL of your collector;
   - the data classes it may receive: `decisions`, `alerts`, `incidents`, `audit`, `containment`, `coverage`. Pick only what the SIEM needs;
   - `internal: true` only if the collector is on a private or loopback address.
2. The destination is created **PENDING** and receives nothing yet. Configure its signing secret in the SIEM.
3. A person opens `/integrations/destinations/{id}/confirm` and confirms with a security key (WebAuthn step-up). The destination becomes **ACTIVE**. Marking a destination internal also needs this step-up.

The URL is refused when it is not HTTPS, resolves to a private or loopback address without `internal`, or is a cloud metadata host (always refused). The URL is checked at creation and enforced at dial time by the egress client.

## 2. Verify in the SIEM

Each POST is one batch of at most 100 events and 1 MiB.

- **Headers:** `webhook-id` (the batch id), `webhook-timestamp`, `webhook-signature` (Standard Webhooks, `v1,<base64 HMAC-SHA256>` over `id.timestamp.body`). Refuse a batch whose signature does not verify or whose timestamp is more than 5 minutes off.
- **Events:** OCSF 1.9. Decisions are API Activity (6003) with `authorizations[]`; alerts are Detection Finding (2004); incidents are Incident Finding (2005); audit is API Activity (6003) or Account Change (3001); anything else is Base Event (0). Each carries actors, the decision reason, the policy version, effects, coverage and uncertainty; never payloads or secrets.
- **Dedupe:** delivery is at-least-once (R-31). Dedupe on `metadata.uid`, the ledger entry id, which never changes.

## 3. Watch delivery health

Read the destination's health (`siem.read`):
- **Configured** versus **delivery confirmed:** a destination is confirmed only after its first 2xx.
- Last delivered sequence and time, lag, delayed and failed batches, retries.
- Retries back off from 5 seconds to 10 hours, 8 attempts per batch. The cursor never skips: it advances by compare-and-set only as batches are delivered.
- After 8 failed attempts the batch is FAILED and the destination FAILING. The same range is retried every 10 hours; `RetryDestination` (`siem.manage`) resets the attempts at once.
- Health shows the stuck sequence and the age of the oldest undelivered event.

When delivery is **FAILING**, PantherClaw raises an owned failure (owner and next step) and a `siem` signal in the operations work queue, once per episode, and sends `siem.delivery_failing`. Fix the collector (TLS, certificate, URL, signature check, size limit), then call `RetryDestination` or wait for the 10-hour retry; the backlog drains from the cursor.

## 4. Rotate the secret

1. Rotate the secret through the `siem.proto` API (`siem.manage`).
2. For 24 hours every batch carries two signatures, one per secret. Update the SIEM within that window.
3. After 24 hours only the new secret signs.

## 5. Pause or disable

A destination is PAUSED or DISABLED through the `siem.proto` API (`siem.manage`); neither receives batches. Pausing keeps the cursor, so a resumed destination continues where it stopped. Every change is audited.
