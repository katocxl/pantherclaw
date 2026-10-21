# Runbook — Support access and break-glass

**Milestone:** M13 wave 2 ([G0 M13](../g0/M13.md) D32, D33; [ADR-0034](../adr/0034-customer-approved-support-access.md); HR-385..389, T-174, T-175). **Audience:** support staff and the operator of the hosted control plane (part 1), customers' org admins (parts 2 and 3). RPC and setting names follow the brief; the M13 exit status records any change.

## 1. Support access: setup (operator, hosted only)

- Support access exists only on the hosted control plane, for organizations on the Enterprise plan. Self-hosted licence mode refuses it.
- List staff accounts in the server configuration, as issuer and subject pairs of their hosted accounts:
  ```json
  "support": { "staff_accounts": [ { "issuer": "https://…", "subject": "…" } ] }
  ```
  An empty list turns the feature off. Each staff member registers their own security key on their hosted account.
- Nobody has standing access, operators included. Every session needs a grant the customer approved (HR-385).

## 2. Requesting and using access (support staff)

1. Sign in to your hosted account and complete a step-up with your security key.
2. Request access for one task:
   - the organization;
   - the task, in plain text of at most 200 characters (for example `ticket 4821: approvals stuck in PENDING`);
   - the scope, `READ_ONLY` (the default) or `READ_ONLY_PLUS_EVIDENCE` (adds restricted evidence only);
   - a duration of at most 72 hours.

   The request is recorded in the customer's ledger, and their org admins are notified.
3. Wait for an org admin to approve. You cannot approve your own request, even if you are an org admin of that organization (HR-386).
4. Open a support session. It is a separate session of kind `support`, bound to the grant, with the role `support_readonly`. The console shows a banner. In it:
   - You can read what the organization's members can read.
   - You can never change anything.
   - You can never see credentials, sealed material, payload captures or exports.
   - You can see restricted payloads only when the scope added evidence (HR-387).
5. Every call is recorded in the customer's ledger with `support/<your account id>` and the grant (HR-388). Stay inside the task.
6. The grant ends at its expiry or when any org admin revokes it; the next call is refused. Ask again if the task needs more time.

## 3. Approving, watching and revoking (customer org admins)

- **Approve or deny** from the notification or Settings. Approval needs your step-up. Check three things before approving:
  - the task matches a support case you opened;
  - the scope is the narrowest that works (read-only unless restricted evidence is truly needed);
  - the duration is as short as possible.
- **Watch** the grant's activity in your organization's audit trail: every call shows the support account and the grant.
- **Revoke** at any time. Revocation takes effect at the support session's next call.
- **Report** a request you did not expect to your PantherClaw contact, and treat it as an incident ([incident-response.md](incident-response.md)).

## 4. Break-glass (customer org admins and holders; Business and above)

Break-glass gives a pre-designated member an emergency role for at most 60 minutes, for example when the usual admins are unreachable during an incident (F594, HR-389).

1. **Designate** up to 3 holders in Settings, each with an emergency role. Any existing role can be the emergency role except org admin.
2. **Activate** (holder): give a reason and complete a step-up. The emergency role lasts at most 60 minutes, and every other org admin is notified at once.
3. **During activation**, every call is audited with the activation id; the audit kinds are `breakglass.activated` and `breakglass.ended`.
4. **What break-glass does not do:**
   - it never waives two-person rules, approvals or invariants;
   - it never replaces the kill switch's own rules (HR-113).
5. **Afterwards**, review the activation's calls in the audit trail and record the reason in your incident notes.
