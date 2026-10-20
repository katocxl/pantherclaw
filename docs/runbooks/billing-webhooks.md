# Billing webhook failures

**Milestone:** UI ([G0 UI](../g0/UI.md) D9, D12; [ADR-0031](../adr/0031-hosted-accounts-per-org-plans-and-test-seams.md); HR-355, HR-357, HR-359). **Audience:** the operator of a hosted deployment. Provider-specific steps (signature keys, the provider's dashboard and event replay) live with the commercial distribution's own runbooks; this page covers what the core does and what to check.

In a hosted deployment an organization's plan changes when the merchant-of-record payment provider sends a signed event to the billing extension route, which verifies it and applies the plan change through the core's plan writer. The core applies each event once (by event id) and ignores events older than the last one applied (HR-355); every applied change is audited.

## What a failure looks like

- A customer paid, but the console still shows no plan, or "Activating…" does not finish.
- A customer cancelled or a payment failed, but the plan still shows active.
- Alerts or logs from the billing route: refused signatures, an unknown organization in an event, or events arriving long after the provider sent them.

**Protection is never affected** (HR-357): whatever the plan state, gateways keep enforcing, decisions keep being made, the kill switch, containment and open approvals keep working and evidence stays readable. A stale plan only affects configuration changes and new agents, instances and connections (`PLAN_REQUIRED`).

## Triage

1. **Is the route reachable?** The provider's dashboard shows delivery attempts and their HTTP status. Repeated timeouts or 5xx answers point at the deployment (ingress, the server, the database); fix those first. The provider retries on its own schedule.
2. **Are events refused?** A signature refusal means the configured webhook secret does not match the provider's, or the clock is skewed beyond the allowed window. Check the server's clock and the configured secret file (never print it); rotate it in both places if in doubt.
3. **Unknown organization?** The event names an organization this deployment does not have (a test event, another environment's event, or a deleted organization). It is audited and answered 200 so the provider stops retrying; nothing changes.
4. **Out of order or duplicate?** Older and repeated events are ignored by design; only the newest state counts. If the newest event was lost, ask the provider to resend it.
5. **Wrong environment?** Development and staging must use the provider's sandbox and production its live account; a production server refuses to start with billing off or faked (HR-359), and the commercial distribution checks key types at start-up.

## Bridging while it is fixed

If a paying customer is blocked by a stale plan and the cause will take time, grant a short complimentary plan with a reason that names the incident ([comp-plans.md](comp-plans.md)), and revoke it once the provider's events are applied again. Never edit plan rows in the database by hand: the plan writer, the complimentary-plan command and development mode are the only writers (HR-354).

## Afterwards

Record the incident (cause, affected organizations, duration) and check that every affected organization's plan in the console matches the provider's records.
