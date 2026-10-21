# Complimentary plans: grant and revoke

**Milestone:** UI ([G0 UI](../g0/UI.md) D12; [ADR-0031](../adr/0031-hosted-accounts-per-org-plans-and-test-seams.md); HR-354, HR-358, HR-361). **Audience:** the operator of a hosted deployment. Command flags below follow the brief; the UI exit status records any change.

A complimentary plan gives one organization a plan without payment, for a limited time: the founder's own test organizations, design partners and short evaluations. It works in every deployment, production included. It is granted only by an operator on the server's command line, never through the API, the console or a browser (HR-354), and it is always visible to the organization.

## 1. Before you grant

- Complimentary plans exist only with hosted billing (`billing.mode: external`). On a self-hosted server with licence billing the command refuses with `COMP_NEEDS_HOSTED_BILLING`: self-hosted entitlements come from the licence only, and a complimentary plan never overrides it.
- Confirm the organization id (from the console's organization settings, or `WhoAmI` for a member of it) and the plan id (a plan the deployment knows).
- Decide the end date. The expiry is at most one year from now (HR-358); longer arrangements are a new grant at the time.
- Write a short reason that a later reader understands, for example `design partner pilot, agreement 2026-10`. Do not put personal data, prices or contract terms in it: the reason is stored in the evidence ledger.

## 2. Grant

```bash
pantherclaw-server org plan grant --org <org id> --plan <plan id> \
  --until 2027-01-31T00:00:00Z --reason "design partner pilot"
```

The command runs with the server's operator configuration (like `org create`). It sets the organization's plan source and status to complimentary until the given time, writes an audit event with the reason and the operator, and prints the resulting plan. The console then shows "Complimentary plan until …" in Plan & billing and in the plan banner.

Refusals: an expiry in the past or more than one year away, an unknown organization or plan, or a missing reason. A complimentary status can never arrive through the billing integration (HR-361).

## 3. Check

The grant command prints the resulting plan. A member of the organization sees it in Settings › Plan & billing, or through `EntitlementService.GetEntitlements`: status complimentary, source complimentary, and the expiry.

## 4. Revoke or let it expire

```bash
pantherclaw-server org plan revoke --org <org id> --reason "pilot ended"
```

Revoking (or reaching the expiry) returns the organization at once to its billing state, which is kept underneath the complimentary plan: payment events that arrived during the grant were applied to it, so a plan the organization paid for meanwhile is active straight away, and with no billing state the organization has no plan. Without a plan the plan gate answers `PLAN_REQUIRED` for configuration changes and new agents or connections, but **protection never turns off** (HR-357): gateways keep enforcing, decisions keep being made, the kill switch, containment and open approvals keep working, and evidence stays readable. Tell the organization's admins before you revoke.

## 5. Review

Every grant and revoke is in the evidence ledger. Review the list of active complimentary plans monthly and revoke the ones whose reason no longer holds (R-52).
