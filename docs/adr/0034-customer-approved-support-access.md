# ADR-0034 — Customer-approved support access and break-glass

**Status:** Accepted (2026-10-21; G0 M13 founder decision F3 and coordinator decisions D32, D33; the [G0 M13 brief](../g0/M13.md) records them). Operating procedure: [support-access.md](../runbooks/support-access.md).

**Context.** PN-012.4 (with F597 and F598) requires support access to a customer's organization to be:
- requested for a named task and a duration;
- approved by the customer;
- visible in scope;
- audited;
- without standing access to credentials or restricted payloads.

Today the only way in is the operator command line, with a self-asserted actor. A hosted control plane makes PantherClaw's own staff a potential insider (A7). Support access must therefore be something the customer grants, sees and ends. F594 separately asks for break-glass access inside the customer's own organization: narrow, time-limited, step-up authenticated and separately audited.

**Decision.**
1. **Who can ask.** Support staff are hosted accounts listed in `support.staff_accounts`, as issuer and subject pairs.
   - An empty list turns the feature off.
   - Support access is refused in self-hosted licence mode: it exists only on the hosted control plane, for organizations on the Enterprise plan.
2. **Request.** A staff member, in an account session with a step-up on their own security key, calls `SupportAccessService.RequestAccess` with:
   - the organization;
   - a task (plain text, at most 200 characters);
   - a scope: `READ_ONLY` (the default) or `READ_ONLY_PLUS_EVIDENCE`;
   - a duration of at most 72 hours.

   The request is stored in the organization's own scope (`pc.support_access_requests`, `pc.support_access_grants`, under forced RLS), audited in its ledger, and the org admins are notified.
3. **Approval** (HR-386).
   - An org admin approves with a step-up, or denies.
   - The requesting account can never approve its own request, even when it is also an org admin.
   - Any admin can revoke a grant at any time.
4. **No standing access** (HR-385). Only an approved, unexpired, unrevoked grant authenticates a support session, and expiry is checked at every authentication.
5. **The support session** (HR-387, HR-388).
   - `OpenSupportSession` gives a browser organization session of a new principal kind, `support`, bound to the grant, with the role `support_readonly`.
   - That role has every `.read` permission except restricted evidence, credentials and sealed material, payload captures and exports. `READ_ONLY_PLUS_EVIDENCE` adds restricted evidence only.
   - Support sessions never write.
   - Every call is audited in the customer's ledger with the actor `support/<account id>` and the grant id, and the console shows a banner.
6. **Break-glass** (HR-389; Business and above).
   - Org admins pre-designate up to three members as break-glass holders, each with an emergency role. Any existing role can serve except org admin.
   - A holder activates with a step-up and a reason, for at most 60 minutes, and every other org admin is notified at once.
   - Activations are audited with their own kinds (`breakglass.activated`, `breakglass.ended`), and every call during one carries the activation id.
   - Break-glass never waives two-person rules, approvals or invariants, and it never replaces the kill switch's own rules (HR-113).

**Consequences.**
- Support work on a hosted organization waits for the customer's approval. The customer sees every request, approval, call and revocation in its own ledger.
- New tables in migrations `00173`–`00175`, a new principal kind and a new role. New threats T-174 (rogue support staff) and T-175 (support session theft).

**Alternatives.**
- Standing operator access with after-the-fact audit: contradicts PN-012.4.
- Approval by PantherClaw staff: that is self-approval.
- Grants without a time limit.
- Support access through the operator command line with a self-asserted actor: the customer cannot see it or end it.
- Break-glass that skips approvals: it would turn an emergency path into a bypass.
