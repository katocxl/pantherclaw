# Runbook — Governed automations

**Milestone:** M11 · **Owner:** the automation's owner, the org's automation publishers (`automation.publish`) and endpoint admins (`automation.endpoints.manage`) · **Edition:** Team (the `contain` step, latent exposure and the compromised-publisher response are Business) · **Status:** procedure written from the [G0 M11 part 2 brief](../g0/M11.md) (D5–D43); tested at the M11 exit.

An automation is a versioned definition that starts work on a schedule, a platform event, a condition, a threshold, a manual start or a signed inbound event. It acts as its own execution identity, and when it launches an agent, each execution gets a fresh grant inside an issuance ceiling that people approved with security keys. Background: [g0/M11.md](../g0/M11.md), [ADR-0027](../adr/0027-governed-automations.md), HR-270..HR-293, R-33..R-38.

## 1. Create, validate and test a version

1. Create the automation (`automation.manage`). This also creates its execution identity, a service account named `automation-<name>`. You cannot add keys or role bindings to that account; that is intended (HR-270).
2. Create a draft version, from a template (`CreateFromTemplate`) or from your own YAML or JSON definition.
3. Validate it. Fix every ERROR finding; read the WARNINGs (for example LOOP_POSSIBLE). Read the plain-language summary: it is what confirmers will approve.
4. Set its tests and run them. The required kinds are NORMAL, DENIED, TIMEOUT and DUPLICATE, plus PARTIAL or UNKNOWN when the ceiling has an irreversible operation. A passing run makes the version TESTED (HR-287).
5. Optional but recommended: run a historical simulation (up to 30 days) and read the forecasts: executions, gates and grants per day, maximum budget per day, and what was UNEVALUABLE. In Business, read the blast-radius preview.

## 2. Enable it: the security-key ceremony

1. `RequestEnable` the version with a rollout: SHADOW (needs VALIDATED or TESTED), COHORT or FULL (need TESTED).
2. Confirmers open `/changes/{id}` and confirm with a security key. A confirmer must hold `automation.publish` and every permission the version's steps need at every scope they touch (for `launch_run`: `grant.issue` and `run.start` on each ceiling agent's path), and must not be marked compromised. The requester may confirm.
3. How many: SHADOW needs one. COHORT and FULL need two distinct people with distinct keys when the org has at least two eligible people, else one (R-35).
4. On the last confirmation the version is published, the ceiling becomes ACTIVE with the confirmers as approvers, and the automation becomes ACTIVE. A SHADOW enable creates no ceiling: nothing is issued in shadow.
5. Widen in steps: SHADOW → COHORT → FULL. Each widening is a ROLLOUT change request with the same ceremony; FULL needs a verified cohort stage (at least one SUCCEEDED live execution with completion evidence, and no authority failures or open reconciliations). Narrowing (`NarrowRollout`) takes one person.
6. Any change to the definition or the ceiling is a new version and a new ceremony. Review dates: the owner is told 7 days and 1 day before `review_by`; at `review_by` the ceiling expires and the automation pauses (CEILING_EXPIRED). Enable a new version to continue.

If an approver later loses a permission or is marked compromised, the next execution fails CEILING_VOID, the ceiling is voided, the automation pauses and the owner gets an owned failure. Re-enable a version with current approvers.

## 3. Pause, resume, cancel, retire, revoke authority

| Control | Who | Effect |
|---|---|---|
| Pause | `automation.manage` | No new executions. Triggers follow the version's paused policy (DISCARD, QUEUE or EXPIRE). Active executions continue unless you set `cancel_active`. |
| Resume | `automation.manage` | Re-checks the owner, ceiling and approvers, identity, principal, edition and kill switch, then replays unexpired queued triggers. Missed irreversible work is never replayed. |
| Cancel an execution, or all active ones | `automation.manage` | CANCELLED at the next step boundary; its grants are revoked, its runs ended, pending launches and deliveries cancelled. |
| Retire | `automation.manage` | Cancels active executions, deactivates triggers, revokes the ceiling and disables the identity. Final. |
| Revoke authority | `automation.manage` | Revokes the ceiling and every grant issued under it, ends their runs and pauses the automation (AUTHORITY_REVOKED). Use it when you suspect the automation itself. |

Every control returns its verified effects (grants revoked, runs ended, launches and deliveries cancelled, executions affected). Check them; an execution with an UNKNOWN irreversible effect stays NEEDS_RECONCILIATION until M7 reconciliation resolves it.

## 4. The kill switch and containment

- Engaging the kill switch ([kill-switch.md](kill-switch.md)) pauses **every** automation (KILL_SWITCH) in the same transaction and records how many; active executions are cancelled at the next boundary.
- Restoring the kill switch resumes **nothing**. Resume each automation yourself once you know it is safe; resume revalidates everything first.
- A containment control on an automation's service account (principal scope) makes revalidation fail and pauses that automation (CONTAINED). Lift it only through restoration ([incident-response.md](incident-response.md)).
- A loop between automations is refused, raises one `automation.loop` alert per root and pauses the refused automation (LOOP). Fix the triggers, then resume.

## 5. Inbound event sources

1. Create a source (`automation.endpoints.manage`, a person) with its event types. The `whsec_` secret is shown **once**; store it in the sending system.
2. The source is PENDING. Activate it with a security-key step-up. Only ACTIVE sources accept events.
3. The sender posts to `https://<your PantherClaw>/v1/automations/events/{org}/{source}` with Standard Webhooks headers (`webhook-id`, `webhook-timestamp`, `webhook-signature`), a JSON body of at most 64 KiB and a `type` the source declares.
4. Responses: 202 accepted; 401 bad signature or a timestamp outside ±5 minutes; 404 unknown or inactive source; 409 a `webhook-id` already seen (7 days); 422 an undeclared type or invalid JSON; 429 over the rate limit. Bodies are never stored; the audit keeps the source, type, id and body digest.

**Rotation:** `RotateEventSourceSecret` (step-up). The previous secret stays valid for 24 hours; switch the sender within that window.

**Suspected leak** (R-34): rotate at once, or disable the source if the sender cannot switch quickly (DISABLED is final; create a new source). Then review the automations it triggers: executions by trigger, grants issued, and whether any parameter values look forged. Event fields never choose identity or authority, and per-day caps bound the damage.

## 6. Automation destinations

Destinations receive launches (LAUNCH), digests (DIGEST) and notices (NOTICE). They follow the same lifecycle as sources: created PENDING, activated with a step-up, HTTPS only; private and loopback hosts only when marked internal, metadata hosts never. Deliveries are signed with Standard Webhooks and retried up to 8 times (30 seconds to 1 hour). Rotate a destination's secret with a step-up; during the 24-hour overlap each delivery carries both signatures, so the receiver can switch at any time. A step that delivers succeeds only when the destination answered 2xx (DELIVERY_CONFIRMED).

## 7. A compromised publisher (Business)

If a person who confirms changes may be compromised:
1. A holder of `publisher.compromise` marks them compromised with a step-up and a `since` time. At once they can no longer confirm, approve, publish, activate or promote; their pending change requests are voided; automations whose ceiling they approved are paused (COMPROMISED_PUBLISHER); open policy rollouts they confirmed are halted (HR-293).
2. Read `ListExposed`: policy versions, package activations, org package keys (revoke them, see [key-rotation.md](key-rotation.md)), automation versions, protected changes, promotions and grants since `since`.
3. Another person reviews each item KEEP or ROLLBACK. For a paused automation: KEEP and re-enable it through a new ceremony by other confirmers, or retire it.
4. Clearing the mark is a change request that two other people confirm, and only once every item is reviewed.

## 8. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Execution FAILED `CEILING_VOID` | An approver lost a permission or was marked compromised | Enable a new version with current approvers |
| Execution FAILED `USAGE_EXCEEDED` | Per-day grant, run or budget cap reached | Wait for the next day, or enable a version with a larger ceiling |
| Execution FAILED `NOT_PROMOTED` | A production grant lists operations the agent is not promoted for | Promote the agent for those operations (`PromoteAgent`, `agent.promote` with a step-up) |
| Execution FAILED `LAUNCH_NOT_CLAIMED` | No runner or agent claimed the launch in time | Check that the agent's workload (or `pclaw automation runner`) is running and enrolled |
| Triggers REFUSED_DUPLICATE | The same dedupe key within its window | Expected for retries; check the sender's ids |
| Triggers REFUSED_LOOP | The automation is already in the trigger's ancestry | Change the triggers so automations do not feed each other |
| Execution NEEDS_RECONCILIATION | An irreversible operation's effect is UNKNOWN | Resolve the transactions through M7 reconciliation; the execution is never retried automatically |
