# Runbook — Governed automations

**Milestone:** M11 · **Owner:** the automation's owner, automation authors (`automation_author`), publishers (`automation_publisher`) and operators (`automation_operator`); fleet managers (`fleet_manager`) for promotion; the agent owner for promotions that lapse · **Edition:** Team (the `contain` step, latent exposure and the compromised-publisher response are Business) · **Status:** procedure written from the [G0 M11 part 2 brief](../g0/M11.md) (D5–D43); tested at the M11 exit.

An automation is a versioned definition that starts work on a schedule, a platform event, a condition, a threshold, a manual start or a signed inbound event. It acts as its own execution identity, and when it launches an agent, each execution gets a fresh grant inside an issuance ceiling that people approved with security keys. Background: [g0/M11.md](../g0/M11.md), [ADR-0027](../adr/0027-governed-automations.md), HR-270..HR-293, R-33..R-38.

## 0. Who does what

| Role | Permissions | Typical work |
|---|---|---|
| `automation_author` | `automation.read`, `automation.manage`, `automation.endpoints.manage` | Create automations and versions, request enabling, pause, resume, cancel, retire, revoke authority; add and rotate event sources and destinations |
| `automation_publisher` | `automation.read`, `automation.publish`, `automation.approve` | Confirm enabling and rollout ceremonies; decide gates |
| `automation_operator` | `automation.read`, `automation.run`, `automation.approve` | Start manual executions; decide gates |
| `fleet_manager` (people only) | `agent.promote`, `cohort.manage`, `agent.read` and basic reads | Promote agents for production operations; manage cohorts |
| `security_admin` | adds `publisher.compromise`, `protected_change.manage`, `automation.read` | Mark a publisher compromised; manage protected changes |

**Roles a confirmer needs per template.** Every confirmer holds `automation.publish` (`automation_publisher`) and also every permission the version's steps need at every scope they touch; one person may hold several roles. Bind these explicitly before you request enabling (D67).

| Template | Step permissions the confirmer also needs | Roles that carry them (examples) |
|---|---|---|
| `bounded_task_launch` | `grant.issue` and `run.start` at each ceiling agent's path | `grant_issuer` and `run_launcher` (or `agent_owner`) at those agents' scope |
| `approved_business_workflow` | as `bounded_task_launch`; gate deciders need `automation.approve` | as above; deciders `automation_publisher` or `automation_operator` |
| `grant_lifecycle` | `grant.revoke` at each `revocable` agent's path (org scope for `all`) | `grant_issuer`, `responder` or `security_admin` |
| `approval_routing` | none beyond `automation.publish` | `automation_publisher` |
| `new_agent_intake` | `agent.read` and coverage read at the agent's path | `automation_publisher` plus `developer` or `auditor` |
| `coverage_recovery` | `automation.publish` at org scope (pause and resume launches); coverage read | `automation_publisher` bound at the org, plus coverage read |
| `scoped_incident_containment` (Business) | `incident.respond` and `case.manage` at the org; `grant.revoke` per `revocable` | `security_admin` or `responder` at the org |
| `least_privilege_review` | the M11.1 policy draft and simulate permissions at the org | `policy_author` at the org |
| `audit_digest` | `evidence.export` at the org | `security_admin` or `auditor` |

`org_admin` gets only `automation.read`: administering the org never implies publishing or approving. No role holds both `automation.manage` and `automation.publish`, so the author of a version and its confirmers are normally different people; a person who holds both roles may confirm their own request, which is one of the confirmations, not all of them when two are required.

## 1. Create, validate and test a version

1. Create the automation (`automation.manage`). This also creates its execution identity, a service account named `automation-<name>`. You cannot add keys or role bindings to that account; that is intended (HR-270).
2. Create a draft version, from a template (`CreateFromTemplate`) or from your own YAML or JSON definition.
3. Validate it. Fix every ERROR finding; read the WARNINGs (for example LOOP_POSSIBLE). Read the plain-language summary: it is what confirmers will approve.
4. Set its tests and run them. The required kinds are NORMAL, DENIED, TIMEOUT and DUPLICATE, plus PARTIAL or UNKNOWN when the ceiling has an irreversible operation. A passing run makes the version TESTED (HR-287).
5. Optional but recommended: run a historical simulation (up to 30 days) and read the forecasts: executions, gates and grants per day, maximum budget per day, and what was UNEVALUABLE. In Business, read the blast-radius preview.

**Schedules.** Preview a schedule (`PreviewSchedule`) before enabling: it shows local and UTC times and notes DST gaps (skipped or shifted) and repeats (fired once). When a day field is stepped (for example `*/2`), day-of-month and day-of-week combine as in Vixie cron, and the preview says so; `SUN` closing a range (`MON-SUN`, `FRI-SUN`) means day 7.

## 2. Enable it: the security-key ceremony

1. `RequestEnable` the version with a rollout: SHADOW (needs VALIDATED or TESTED), COHORT or FULL (need TESTED).
2. Confirmers open `/changes/{id}` and confirm with a security key. A confirmer must hold `automation.publish` and every permission the version's steps need at every scope they touch (for `launch_run`: `grant.issue` and `run.start` on each ceiling agent's path), and must not be marked compromised. The requester may confirm.
3. How many: SHADOW needs one. COHORT and FULL need two distinct people with distinct keys when the org has at least two eligible people, else one (R-35).
4. On the last confirmation the version is published, the ceiling becomes ACTIVE with the confirmers as approvers, and the automation becomes ACTIVE. Every enable and rollout, SHADOW included, records a fresh authority row with its confirmers and review date; nothing is ever issued in shadow.
5. Widen in steps: SHADOW → COHORT → FULL. Each widening is a ROLLOUT change request with the same ceremony; FULL needs a verified cohort stage (at least one SUCCEEDED live execution with completion evidence, and no authority failures or open reconciliations). Narrowing (`NarrowRollout`) takes one person.
6. Any change to the definition or the ceiling is a new version and a new ceremony. Review dates: the owner is told 7 days and 1 day before `review_by`; at `review_by` the ceiling expires and the automation pauses (CEILING_EXPIRED). To continue, enable a new version, then Resume: enabling never un-pauses an automation, and only Resume (with its revalidation) does.

**Expired requests.** A change request that is not confirmed before its expiry (at most 24 hours; at most 72 hours for an emergency review of a protected change) is marked EXPIRED by a per-org sweep that runs every minute, which also emits `change.expired`. Nothing is applied; request again. The exception is the emergency review of a protected change: the emergency change was already applied and stays applied (nothing is undone automatically). The protected change shows review state REVIEW_EXPIRED, and the emergency publisher gets an owned failure `protected_change.review_expired` in the operations queue. A person with the category's permission can open a new review: a fresh 72-hour emergency review, with the same author and publisher exclusions.

If an approver later loses a permission or is marked compromised, the ceiling is voided, the automation pauses (CEILING_VOID) and the owner gets an owned failure. This happens at the next issuance, or within 5 minutes through the ceiling sweep, which checks every ACTIVE ceiling's approvers and review date per org. To recover, enable a new version with current approvers, then Resume.

## 3. Pause, resume, cancel, retire, revoke authority

| Control | Who | Effect |
|---|---|---|
| Pause | `automation.manage` | No new executions. Triggers follow the version's paused policy (DISCARD, QUEUE or EXPIRE). Active executions continue unless you set `cancel_active`. |
| Resume | `automation.manage` | Re-checks the owner, ceiling and approvers, identity, principal, edition and kill switch, then replays unexpired queued triggers. Missed irreversible work is never replayed. |
| Cancel an execution, or all active ones | `automation.manage` | CANCELLED at the next step boundary; its grants are revoked, its runs ended, pending launches and deliveries cancelled. |
| Retry an execution | `automation.run` | Starts a new manual execution with the original parameters, only for a FAILED, PARTIALLY_COMPLETED or CANCELLED execution with no UNKNOWN irreversible effect, under the same enabled version; it revalidates like any start. |
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
2. The source is PENDING. Activate it on its web page in PantherClaw with a security-key step-up (the API refuses with STEP_UP_REQUIRED; step-ups happen only in a browser session). Only ACTIVE sources accept events.
3. The sender posts to `https://<your PantherClaw>/v1/automations/events/{org}/{source}` with Standard Webhooks headers (`webhook-id`, `webhook-timestamp`, `webhook-signature`), a JSON body of at most 64 KiB and a `type` the source declares.
4. Responses: 202 accepted; 401 an unknown, inactive or badly signed source, or a timestamp outside ±5 minutes (the same answer for all, so senders cannot probe for sources); 409 a `webhook-id` already seen (7 days); 422 an undeclared type or invalid JSON; 429 over the rate limit. Bodies are never stored; the audit keeps the source, type, id and body digest.

**Rate limit across instances.** The per-source rate limit is held in memory by each server instance. Today the server runs as a single node, so the limit holds; with several instances the effective limit multiplies (a residual recorded under R-34, to be revisited with high availability in M13).

**Rotation:** `RotateEventSourceSecret`, with a step-up on the web page. The previous secret stays valid for 24 hours; switch the sender within that window.

**Suspected leak** (R-34): rotate at once, or disable the source if the sender cannot switch quickly (DISABLED is final; create a new source). Then review the automations it triggers: executions by trigger, grants issued, and whether any parameter values look forged. Event fields never choose identity or authority, and per-day caps bound the damage.

## 6. Automation destinations

Destinations receive launches (LAUNCH), digests (DIGEST) and notices (NOTICE). They follow the same lifecycle as sources: created PENDING, activated with a step-up, HTTPS only; private and loopback hosts only when marked internal, metadata hosts never. Deliveries are signed with Standard Webhooks and retried up to 8 times (30 seconds to 1 hour). Rotate a destination's secret with a step-up; during the 24-hour overlap each delivery carries both signatures, so the receiver can switch at any time. A step that delivers succeeds only when the destination answered 2xx (DELIVERY_CONFIRMED). A PAUSED destination returns to ACTIVE without a step-up: its URL cannot change, and the URL is checked again at every send. A delivery that has already been attempted cannot be cancelled, because it may have been sent: cancel and cleanup list it as "not verified".

## 7. A compromised publisher (Business)

If a person who confirms changes may be compromised:
1. A holder of `publisher.compromise` marks them compromised on the web page with a step-up and a `since` time. At once they can no longer confirm, approve, publish, activate or promote; pending change requests they requested or confirmed are voided, in both ceremonies (policy and change service); automations whose ceiling they approved are paused (COMPROMISED_PUBLISHER); open policy rollouts they confirmed are halted (HR-293).
2. Read `ListExposed`: policy versions, package activations, org package keys (revoke them, see [key-rotation.md](key-rotation.md)), automation versions, protected changes, promotions and grants since `since`.
3. Another person reviews each item KEEP or ROLLBACK. For a paused automation: KEEP it by enabling a new version through a ceremony with other confirmers and then resuming it, or retire it. What ROLLBACK does per item:

   | Item | ROLLBACK |
   |---|---|
   | Policy version | Rolls the policy back. If the rollback loosens the policy, it opens a change request instead and the review answers ROLLBACK_PENDING_CONFIRMATION with the request id; nothing is recorded yet. Once that request is confirmed, record ROLLBACK again: the undo is idempotent ("already rolled back" counts as success). |
   | Grant | Revokes the grant as the reviewer (reason PUBLISHER_COMPROMISED). |
   | Package activation | Quarantines the package. |
   | Org package key | Revokes the key as COMPROMISED. |
   | Automation version | Pauses the automation. |
   | Promotion | Revokes the promotion. |
   | Policy change request, protected change | KEEP_ONLY: only KEEP can be recorded (pending policy change requests were already voided at marking). |
4. Clearing the mark is a change request that two other people confirm, and only once every item is reviewed.

## 8. Promote an agent for production

In a PRODUCTION environment, a new, widened or delegated grant (issued by a person or an automation, or delegated to a child run) needs the agent promoted for each operation the grant lists (HR-290). Grants issued before the gate keep working until they expire.

1. Check readiness: `GetReadiness(agent, environment)` reports each operation's checks (OWNER, IDENTITY, TESTS, APPROVALS, COVERAGE, FAILURE_BEHAVIOUR). It never makes a global claim.
2. Promote: a `fleet_manager` with `agent.promote` runs `PromoteAgent(agent, environment, operations, failure behaviour)` with a security-key step-up. An `x.*` prefix expands to every operation currently reachable under it through the agent's connections, and each is checked and stored separately. Passing operations are promoted and failing ones are reported.
3. **How COVERAGE is checked: per serving connection.** For each operation, the serving connections are the agent's connections that serve it. Any failing coverage record on one of them refuses the promotion. A passing record (ENFORCED or PARTIAL, not lapsed) on every serving connection gives an ACTIVE promotion. Otherwise, when some serving connection has no record yet or no connection serves the operation, the promotion can only be PROVISIONAL.
4. **A new agent with no traffic yet (provisional promotion, founder decision F7).** If every other check passes and COVERAGE is missing as step 3 describes, the promotion is PROVISIONAL:
   - it lasts at most 7 days;
   - every production grant it covers, issued by a person or an automation, widened or delegated to a child run, expires no later than the promotion, so plan short tasks. The cap is worked out in the same transaction that issues the grant, from the same promotion rows the gate reads, and only PROVISIONAL promotions cap: an ACTIVE promotion never shortens a grant;
   - readiness says "coverage pending until <time>";
   - within 5 minutes of a passing coverage record (ENFORCED or PARTIAL, not lapsed) appearing on every serving connection, it becomes ACTIVE (audited);
   - if no such coverage appears, it EXPIRES and the agent owner gets an owned failure (`promotion.provisional_lapsed`). Get the agent's routes covered, then promote again; you can promote provisionally again only while no serving connection has a failing record and at least one still has none.
   - A coverage record in a failing state never gives a provisional promotion: fix the coverage first.
5. Revoke a promotion with `RevokePromotion`. Existing grants keep their own expiry; new grants for those operations are refused NOT_PROMOTED.

A new operation added later under a promoted prefix blocks new grants that use that prefix until the new operation is promoted too.

## 9. Troubleshooting

| Symptom | Likely cause | What to do |
|---|---|---|
| Execution FAILED `CEILING_VOID` | An approver lost a permission or was marked compromised | Enable a new version with current approvers, then Resume |
| Execution FAILED `USAGE_EXCEEDED` | Per-day grant, run or budget cap reached | Wait for the next day, or enable a version with a larger ceiling |
| Execution FAILED `NOT_PROMOTED` | A production grant lists operations the agent is not promoted for | Promote the agent for those operations (section 8); a new agent with no coverage yet can be promoted provisionally |
| Grants end earlier than their TTL | The agent's promotion is PROVISIONAL, and grants it covers expire with it | Get the agent's routes covered so the promotion becomes ACTIVE (section 8) |
| A manual start answers REFUSED_DUPLICATE | Another start with the same idempotency key ran at the same time; only one execution is created | Wait for the first answer, then retry: a repeat with the key returns the original execution |
| Execution FAILED `LAUNCH_NOT_CLAIMED` | No runner or agent claimed the launch in time | Check that the agent's workload (or `pclaw automation runner`) is running and enrolled |
| Triggers REFUSED_DUPLICATE | The same dedupe key within its window | Expected for retries; check the sender's ids |
| Triggers REFUSED_LOOP | The automation is already in the trigger's ancestry | Change the triggers so automations do not feed each other |
| Execution NEEDS_RECONCILIATION | An irreversible operation's effect is UNKNOWN | Resolve the transactions through M7 reconciliation; the execution is never retried automatically |
