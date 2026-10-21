# Runbook — Support access and break-glass

**Milestone:** M13 wave 2 ([G0 M13](../g0/M13.md) D32, D33, D38; [ADR-0034](../adr/0034-customer-approved-support-access.md); HR-385..389, T-174, T-175). **Audience:** support staff and the operator of the hosted control plane (parts 1 and 2), customers' org admins (parts 3 and 4). Page paths, RPC and setting names follow the brief; the M13 exit status records any change.

## 1. Support access: setup (operator, hosted only)

- Support access exists only on the hosted control plane, for organizations on the Enterprise plan. Self-hosted licence mode refuses it.
- **The staff organization.** Create an organization for support staff and name it in the server configuration. Each staff member is a user of that organization, with their own registered security key, and their user is linked to their hosted account.
- **The staff list.** List each staff member's hosted account, as issuer and subject:
  ```json
  "support": {
    "staff_org": "<staff organization id>",
    "staff_accounts": [ { "issuer": "https://…", "subject": "…" } ]
  }
  ```
  An empty list turns the feature off. A user of the staff organization whose account is not listed cannot request access.
- **No standing access.** Nobody has standing access, operators included. Every support session needs a grant the customer approved (HR-385).

## 2. Requesting and using access (support staff)

1. **Sign in.** Sign in to the staff organization in your browser.
2. **Request.** Open the request page, `/support-access/request`. It is a server-rendered confirmation page; the Connect call for requesting refuses with `STEP_UP_REQUIRED`. Fill in:
   - the organization;
   - the task, as plain text of at most 200 characters (for example `ticket 4821: approvals stuck in PENDING`);
   - the scope: `READ_ONLY` (the default), or `READ_ONLY_PLUS_EVIDENCE`, which adds restricted evidence only;
   - a duration of at most 72 hours.
3. **Confirm with your own security key.** The step-up must be at most 5 minutes old. The request is recorded in the customer's ledger, and their org admins are notified.
4. **Wait for approval.** An org admin of the customer must approve. You can never approve your own request, even if you are an org admin of that organization (HR-386).
5. **Open the support session.** This also needs a fresh step-up with your own key. The session is stored as a support session bound to the grant and to your account, with its own credential prefix. It replaces your staff session cookie in that browser, and the console shows a banner. In the session:
   - you have the role `support_readonly`, which can never be bound to anyone else;
   - you can read what the organization's members can read;
   - you can never change anything;
   - you can never see credentials, sealed material, payload captures or exports;
   - you see restricted payloads only when the scope added evidence (HR-387).
6. **Stay inside the task.** Every call is recorded in the customer's ledger with `support/<your account id>` and the grant (HR-388).
7. **When it ends.** The grant ends at its expiry or when any org admin revokes it. Expiry, revocation and the grant's state are checked on every call, so the next call is refused. Request again if the task needs more time.

## 3. Approving, watching and revoking (customer org admins)

- **Approve or deny** on the approval page the notification links to: `/support-access/{id}/approve` or `/deny`. It is a server-rendered page that shows exactly what you approve, and you confirm with a step-up. The console links to it; the Connect call refuses with `STEP_UP_REQUIRED`. Before approving, check:
  - that the task matches a support case you opened;
  - that the scope is the narrowest that works: read-only unless restricted evidence is truly needed;
  - that the duration is as short as possible.
- **Watch** the grant's activity in your organization's audit trail. Every call shows the support account and the grant.
- **Revoke** at any time from Settings or the API. Revoking only removes access, so it needs no step-up. It takes effect at the support session's next call.
- **Report** any request you did not expect to your PantherClaw contact, and treat it as an incident ([incident-response.md](incident-response.md)).

## 4. Break-glass (customer org admins and holders; Business and above)

Break-glass gives a member chosen in advance an emergency role for at most 60 minutes, for example when the usual admins cannot be reached during an incident (F594, HR-389).

1. **Designate holders.** In Settings, designate up to 3 holders, each with an emergency role. Any existing role can be the emergency role except org admin.
2. **Activate (holder).** Use the activation page, `/break-glass/activate`. Give a reason and confirm with a step-up. The emergency role lasts at most 60 minutes, and every other org admin is notified at once.
3. **During activation**, every call is audited with the activation id, under the audit kinds `breakglass.activated` and `breakglass.ended`.
4. **What break-glass does not do:**
   - it never waives two-person rules, approvals or invariants;
   - it never replaces the kill switch's own rules (HR-113).
5. **Afterwards**, review the activation's calls in the audit trail and record the reason in your incident notes.
