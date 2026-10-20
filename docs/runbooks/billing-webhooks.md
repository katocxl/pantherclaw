# Billing webhook failures

**Milestone:** UI ([G0 UI](../g0/UI.md) D9, D12, D36–D38, D40, D43, D45, D46; [ADR-0031](../adr/0031-hosted-accounts-per-org-plans-and-test-seams.md); HR-355, HR-357, HR-359). **Audience:** the operator of a hosted deployment. Provider-specific steps (signature keys, the provider's dashboard and event replay) live with the commercial distribution's own runbooks; this page covers what the core does and what to check.

In a hosted deployment an organization's plan changes when the merchant-of-record payment provider sends a signed event to the billing extension route, which verifies it and applies the plan change through the core's plan writer. The core applies each event once (by event id) and ignores events older than the last one applied (HR-355); every applied change is audited.

## What a failure looks like

- A customer paid, but the console still shows no plan, or "Activating…" does not finish.
- A customer cancelled or a payment failed, but the plan still shows active.
- Alerts or logs from the billing route: refused signatures, an unknown organization in an event, or events arriving long after the provider sent them.

**Protection is never affected** (HR-357): gateway and workload calls are never gated, so gateways keep enforcing and decisions keep being made in every plan state; with a lapsed or paused plan, safety actions (the kill switch, containment, revocations, deciding open approvals, settling reconciliations, exporting evidence) keep working and evidence stays readable. A stale plan affects only `change` calls: configuration changes and new agents, instances and connections (`PLAN_REQUIRED`; HR-356).

## Triage

1. **Is the route reachable?** The provider's dashboard shows delivery attempts and their HTTP status. Repeated timeouts or 5xx answers point at the deployment (ingress, the server, the database); fix those first. The provider retries on its own schedule.
2. **Are events refused?** A signature refusal means the configured webhook secret does not match the provider's, or the clock is skewed beyond the allowed window. Check the server's clock and the configured secret file (never print it); rotate it in both places if in doubt.
3. **Unknown organization?** Events carry no organization of their own. A subscription is bound to an organization only through a checkout the server recorded (`pc.billing_links`, looked up only through the audited cross-organization lister); organization hints inside an event are never trusted. An event for a subscription with no binding (for example one started outside PantherClaw's checkout; a checkout the server recorded still binds after it expired or was superseded, as long as the organization has no current subscription), or for an organization this deployment does not have (a test event, another environment's event, a deleted organization), is audited and answered 200 so the provider stops retrying; nothing changes. If a customer really paid through such a path, bridge with a complimentary plan (below) and have them check out again from the console once the old subscription is cancelled with the provider.
4. **Not the current subscription?** An organization has at most one current subscription. Events for any other subscription of that organization (an older one, or a second one created outside the console) are audited and never applied. A new checkout is refused while the organization has a current subscription (one cancelled at period end stays current until then); a new checkout supersedes a pending one, whose provider transaction is cancelled on a best-effort basis. Plan changes go through the provider's portal.
5. **Out of order or duplicate?** Repeated events (same event id) and events strictly older than the last one applied are ignored by design; an event with the same time is applied. The billing extension changes the status only from subscription lifecycle events. If the newest event was lost, ask the provider to resend it.
6. **Wrong environment?** Development and staging must use the provider's sandbox and production its live account; a production server refuses to start with billing off or faked (HR-359), and the commercial distribution checks key types at start-up.

## Refund and chargeback alerts

A full refund or a chargeback sets the organization's plan LAPSED; the billing extension cancels the subscription with the provider at once and marks it ended, and later events for it are audited and ignored. It also raises an operator alert. On the alert:

1. Check with the provider's records that the refund or chargeback is real and full (a partial refund changes nothing).
2. Confirm in the console (Settings › Plan & billing) that the organization shows no plan and that the subscription is cancelled with the provider; if the cancellation failed, cancel it in the provider's dashboard.
3. Tell the organization's admins: protection keeps working (HR-357), configuration changes and new agents or connections need a new plan, which they start with a new checkout from the console.
4. If the chargeback was a mistake on the customer's side, do not revive the old subscription; the customer checks out again, and a short complimentary plan can bridge the gap.

## Duplicate payment alerts

A duplicate payment happens when a second subscription binds for an organization that already has a different current subscription, for example after two checkouts were paid in two browser tabs. The billing extension cancels the duplicate subscription at once, refunds it in full through the provider, audits each step and raises an operator alert. The organization's current subscription and plan are unchanged. On the alert:

1. In the provider's records, check that the duplicate subscription is cancelled and that the full refund went through. If either failed, finish it in the provider's dashboard.
2. Check in the console (Settings › Plan & billing) that the organization still shows its original plan.
3. Tell the organization's admins that the second payment was refunded and that nothing else changed.

## Bridging while it is fixed

If a paying customer is blocked by a stale plan and the cause will take time, grant a short complimentary plan with a reason that names the incident ([comp-plans.md](comp-plans.md)), and revoke it once the provider's events are applied again. Never edit plan rows in the database by hand: the plan writer, the complimentary-plan command and development mode are the only writers (HR-354).

## Afterwards

Record the incident (cause, affected organizations, duration) and check that every affected organization's plan in the console matches the provider's records.
