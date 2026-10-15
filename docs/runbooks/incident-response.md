# Runbook — Incident response (alerts → incidents → cases → containment → restoration)

**Milestone:** M10 · **Owner:** the org's responders (`responder`, `security_admin`); the PantherClaw security owner for incidents in PantherClaw itself · **Status:** procedure written from the [G0 M10 brief](../g0/M10.md); tested by `TestE2E_M10_DetectInvestigateRespond` at the M10 exit.

This runbook takes a detection from the first alert to a closed case. Background: [g0/M10.md](../g0/M10.md), [ADR-0026](../adr/0026-reflex-detection-containment-and-signals.md), HR-240..HR-252, HR-002, HR-113. Editions: alerts, incidents, narrow containment, the kill switch and search are in every edition; grouping, suppression, digests, cases, breach radius and staged restoration need Team; SOAR and Shared Signals need Business. A call below the needed edition is refused `EDITION_REQUIRED`.

The last section covers a security incident in PantherClaw itself.

## 1. Triage alerts

1. Start from the work queue: `GetWorkQueue` (`operations.proto`). It ranks active incidents, unconfirmed containment, important waiting decisions and protection failures (coverage loss, stale gateways, failing export, detection overflow, owned failures). Each item lists the actions you may take.
2. Read the alert (`incidents.proto` reads, `incident.read`). Check:
   - **Basis:** OBSERVED, RULE_MATCH, INFERRED or HYPOTHESIS. Treat only OBSERVED as fact.
   - **Rule and pack:** the rule id, version, `rule_digest` and `pack_version`. A custom rule (`org.*`) is the organization's own.
   - **Subjects and evidence:** the run, agent, principal, grant, connection and ledger entries. `count`, `first_seen` and `last_seen` show repeats.
   - **ATLAS and OWASP mappings**, for the report.
3. Act on it:
   - **Acknowledge** to show someone owns it.
   - **Promote** (`PromoteAlert`) or **link** (`LinkAlert`) it to an incident. PAGE and INCIDENT-attention alerts open or join an incident by themselves. In Team, alerts with the same evidence (run, agent, principal, grant, target, connection) within 24 hours join the same incident; `possible_related` alerts are listed, not attached.
   - **Resolve** it when it is benign, with a reason.
   - **Suppress** (Team) only a known benign pattern. A suppression needs a rule, optional subject filters, a reason and an expiry of at most 30 days (HR-242). Suppressed alerts stay listed; a higher severity, a subject outside the scope, or a failed containment still reopens them.
4. When an owned failure appears (`ListFailures`), assign it (`AssignFailure`) to the owner it names, with its deadline. A detection that reports overflow or was disabled after evaluation errors means detection is partly blind (T-105): treat its area as unmonitored until the failure is resolved.

## 2. Run the incident

1. Assign an owner (`AssignIncident`). Every change is an incident event; nothing is edited in place (HR-243).
2. Open a case (Team): from the incident, an alert or a transaction. The case keeps its own record:
   - **FACT** entries need at least one evidence reference.
   - **HYPOTHESIS** entries carry a confidence and alternatives.
   - **QUESTION** entries have an owner; an **ANSWER** may mark a question UNRESOLVED.
   - **IMPACT** entries are OBSERVED or POTENTIAL.
   - To correct an entry, add one that supersedes it (HR-245).
3. Investigate:
   - `WhatHappened(txn)` (`investigations.proto`): the decision, dispatch and effect, and who launched, represented and granted it.
   - `GetRunTimeline(run)`: actions, holds, approvals, authority changes, dispatches, results, gaps; phases are `inferred` unless workflow evidence says otherwise.
   - `GetPrecedingContext` (Team): grant changes, new tools, external content, shared destinations and credentials, links from sensitive reads. It shows correlation, never cause.
   - `CompareRun` (Business): differences from typical runs, with the sample size.
   - Case lenses (`GetLens`): sequence, authority, effects, reach, related, response, all on one selection and time range.
   - Exposure (Team): the observed, effective and credential/bypass views for the agent. UNCERTAIN means PantherClaw cannot read the credential's scope; treat it as reachable.
   - Search (`search.proto`): structured filters and the built-in investigative queries. An empty result says why: NOTHING_IN_SCOPE, NO_DATA_COLLECTED or RESTRICTED (your permissions).

## 3. Contain

Contain narrow first. The kill switch ([kill-switch.md](kill-switch.md)) is for when enforcement integrity itself is in doubt.

1. Ask for options: `ProposeResponse(subject)` (`response.proto`) for a run, agent, transaction, alert or incident. It returns prefilled, narrow-first controls.
2. Choose a control:
   - **DENY_ALL:** every action in scope is denied `CONTAINED`.
   - **HOLD_WRITES:** reads continue; every non-read is held `CONTAINED_WRITES` until an `incident.respond` holder independent of the launcher and grant owner approves it.
   - **DENY_OPERATION:** one operation is denied.
3. Narrow controls (one run, or one agent's DENY_ALL or HOLD_WRITES) commit at once. A wider control (a grant with dependants, a connection, a resource, a principal, or more than one agent) needs a preview first:
   1. `PreviewContainment(scope, control)` shows targets, dependent runs, waiting actions it voids, alternative paths, unknown dependencies and reach before and after.
   2. Commit with the preview's `preview_digest`. If anything changed, the call is refused `PREVIEW_STALE`: preview again.
   3. In an emergency you may skip the preview with a reason and a step-up at most 5 minutes old; the skip is recorded (HR-252).
4. Watch the response action's paths until it is CONFIRMED (HR-249):
   - A **gateway path** is confirmed when that gateway acknowledges the new containment epoch.
   - A **bypass route** (OBSERVE_ONLY or UNKNOWN coverage) stays UNRESOLVED until a credential revoke or rotation closes it. Revoke or rotate the credential: `PreviewCredentialChange` first lists every agent, connection and workload that shares it, then `RotateCredential` or the existing revoke.
   - **In-flight work** is listed per path with its cancellation status (F134).
   - PARTIAL means at least one material path is open. `future_confirmed` says new access is stopped; `historical_open` lists earlier reads and accepted operations, which containment cannot undo.
   - FAILED always raises a `response` signal, whatever suppressions exist.
5. When every linked containment action is CONFIRMED, the case can move to CONTAINED (operational close). If no containment is needed, say why in a STATE entry.
6. SOAR (Business): an integration with the `soar_integration` role may request narrow controls (`RequestControl`, with an idempotency key). It cannot engage the kill switch or lift anything. Results are CONFIRMED, FAILED, UNSUPPORTED or UNKNOWN (PARTIAL is reported as UNKNOWN with the paths).

## 4. Restore

Closing an incident or a case never lifts a control (HR-250). Lifting is a restoration:

1. Request restoration for the control. It becomes a RESTORATION waitlist entry with computed preconditions: identity re-verified, connection health, remediation and test results, remaining grants, waiting approvals.
2. A reviewer independent of the requester, holding `agent.restore`, reviews the preconditions and decides.
3. Staged restoration (Team): restore a cohort or task scope first. Before widening, the plan's permitted and prohibited test actions run through the replay evaluator as a dry run; nothing is dispatched.
4. Denied, expired, missed irreversible and ambiguous actions are never replayed. The agent must ask again and get fresh authorization.
5. Lifting bumps the containment epoch; gateways follow within the usual revocation bound.

## 5. Close the case

1. Record the impact (CONFIRMED, EXPLICITLY_UNRESOLVED or NONE_FOUND) and a disposition (TRUE_POSITIVE, BENIGN, FALSE_POSITIVE or INCONCLUSIVE). At least one FACT is needed.
2. Open questions may stay open, but then the case needs a follow-up owner (F571). The database refuses a closure that breaks these rules (HR-246).
3. Hand off or archive with `ExportCase` (needs `evidence.export`; audited). The export carries entry hashes and evidence ids.
4. If the cause was a standing weakness, check the posture findings (Business). A finding becomes REMEDIATED only when a recomputation shows the fix reaches every affected path; resolving the alert does not close it (HR-255).

## 6. Security incident in PantherClaw itself

1. **Detect and declare:** the source (report, alert, scanner), time, affected component and version; open a security advisory as [SECURITY.md](../../SECURITY.md) describes; record G4.
2. **Contain:** engage the kill switch for affected orgs if enforcement integrity is in doubt; revoke or rotate affected keys ([key-rotation.md](key-rotation.md)); mark a compromised release as compromised and publish a notice; freeze package and licence signing if the roots are suspected.
3. **Preserve evidence:** snapshot the database, ledger checkpoints, logs and CI run logs; never modify the ledger.
4. **Eradicate and recover:** a fix with a reproducing test → two AI reviews → G1 → a patched release (G2/G3) → restoration per [kill-switch.md](kill-switch.md).
5. **Notify:** affected customers with scope, timeline and residual risk; publish the advisory or CVE when fixed.
6. **Learn:** update THREAT_MODEL, HARDENING_RULES (a new HR with a test) and FINDINGS (a closed row).
