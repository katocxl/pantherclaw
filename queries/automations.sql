-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Governed automations, core (G0 M11 part 2 D5, D7–D9, D14, D15): the
-- automations, their versions, issuance ceilings, execution identities and
-- daily usage. Every state change is a conditional UPDATE (HR-004).

-- name: InsertAutomationServiceAccount :exec
-- The execution identity (D8), inserted before its automation in the same
-- transaction (the foreign keys are deferred).
INSERT INTO pc.service_accounts (org_id, id, name, description, created_by, automation_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(description), sqlc.arg(created_by), sqlc.arg(automation_id));

-- name: DisableAutomationServiceAccount :execrows
UPDATE pc.service_accounts SET state = 'DISABLED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND automation_id = sqlc.arg(automation_id) AND state = 'ACTIVE';

-- name: ServiceAccountAutomation :one
-- The automation a service account belongs to (zero rows: an ordinary one).
SELECT automation_id::uuid AS automation_id FROM pc.service_accounts
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND automation_id IS NOT NULL;

-- name: InsertAutomation :exec
INSERT INTO pc.automations (org_id, id, name, purpose, kind, owner_user_id, service_account_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(purpose), sqlc.arg(kind), sqlc.arg(owner_user_id),
        sqlc.arg(service_account_id), sqlc.arg(created_by));

-- name: GetAutomation :one
SELECT a.org_id, a.id, a.name, a.purpose, a.kind, a.owner_user_id, a.service_account_id, a.state, a.rollout,
       a.cohort_agents, a.enabled_version_id, a.pause_reason, a.paused_at, a.created_by, a.created_at, a.updated_at,
       a.retired_at
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id);

-- name: LockAutomation :one
SELECT a.org_id, a.id, a.name, a.purpose, a.kind, a.owner_user_id, a.service_account_id, a.state, a.rollout,
       a.cohort_agents, a.enabled_version_id, a.pause_reason, a.paused_at, a.created_by, a.created_at, a.updated_at,
       a.retired_at
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(id)
FOR UPDATE;

-- name: ListAutomations :many
-- Pages by name; states filters when not empty.
SELECT a.org_id, a.id, a.name, a.purpose, a.kind, a.owner_user_id, a.service_account_id, a.state, a.rollout,
       a.cohort_agents, a.enabled_version_id, a.pause_reason, a.paused_at, a.created_by, a.created_at, a.updated_at,
       a.retired_at
FROM pc.automations a
WHERE a.org_id = sqlc.arg(org_id)
  AND (cardinality(sqlc.arg(states)::text[]) = 0 OR a.state = ANY (sqlc.arg(states)::text[]))
  AND a.name > sqlc.arg(after_name)::text
ORDER BY a.name
LIMIT sqlc.arg(max_rows)::int;

-- name: UpdateAutomationOwner :execrows
UPDATE pc.automations SET owner_user_id = sqlc.arg(owner_user_id), purpose = sqlc.arg(purpose)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RETIRED';

-- name: EnableAutomation :execrows
-- Applies an ENABLE or ROLLOUT change request (D7). A paused automation
-- stays paused (its pause has its own reason; Resume revalidates).
UPDATE pc.automations
SET state = CASE WHEN state = 'PAUSED' THEN 'PAUSED' ELSE 'ACTIVE' END, enabled_version_id = sqlc.arg(version_id),
    rollout = sqlc.arg(rollout), cohort_agents = sqlc.narg(cohort_agents)::uuid[]
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('DRAFT', 'ACTIVE', 'PAUSED');

-- name: NarrowAutomationRollout :execrows
UPDATE pc.automations SET rollout = sqlc.arg(rollout), cohort_agents = sqlc.narg(cohort_agents)::uuid[]
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('ACTIVE', 'PAUSED') AND rollout = sqlc.arg(from_rollout);

-- name: PauseAutomation :execrows
UPDATE pc.automations SET state = 'PAUSED', pause_reason = sqlc.arg(reason), paused_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: PauseActiveAutomations :many
-- Pauser (D14): every ACTIVE automation of the org (all), or those listed.
UPDATE pc.automations SET state = 'PAUSED', pause_reason = sqlc.arg(reason), paused_at = now()
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE'
  AND (sqlc.arg(all_automations)::bool OR id = ANY (sqlc.arg(ids)::uuid[]))
RETURNING id;

-- name: ResumeAutomation :execrows
UPDATE pc.automations SET state = 'ACTIVE', pause_reason = NULL, paused_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PAUSED';

-- name: RetireAutomation :execrows
UPDATE pc.automations
SET state = 'RETIRED', enabled_version_id = NULL, rollout = NULL, cohort_agents = NULL, pause_reason = NULL,
    paused_at = NULL, retired_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RETIRED';

-- name: NextAutomationVersionNumber :one
SELECT (coalesce(max(number), 0) + 1)::int AS number FROM pc.automation_versions
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id);

-- name: InsertAutomationVersion :exec
INSERT INTO pc.automation_versions (org_id, id, automation_id, number, definition, digest, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(automation_id), sqlc.arg(number), sqlc.arg(definition), sqlc.arg(digest),
        sqlc.arg(created_by));

-- name: GetAutomationVersion :one
SELECT v.org_id, v.id, v.automation_id, v.number, v.state, v.definition, v.digest, v.summary, v.findings, v.tested_run_id,
       v.created_by, v.created_at, v.updated_at, v.validated_at, v.tested_at, v.published_at, v.change_request_id
FROM pc.automation_versions v
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id);

-- name: LockAutomationVersion :one
SELECT v.org_id, v.id, v.automation_id, v.number, v.state, v.definition, v.digest, v.summary, v.findings, v.tested_run_id,
       v.created_by, v.created_at, v.updated_at, v.validated_at, v.tested_at, v.published_at, v.change_request_id
FROM pc.automation_versions v
WHERE v.org_id = sqlc.arg(org_id) AND v.id = sqlc.arg(id)
FOR UPDATE;

-- name: ListAutomationVersions :many
SELECT v.org_id, v.id, v.automation_id, v.number, v.state, v.digest, v.summary, v.tested_run_id, v.created_by,
       v.created_at, v.updated_at, v.validated_at, v.tested_at, v.published_at, v.change_request_id
FROM pc.automation_versions v
WHERE v.org_id = sqlc.arg(org_id) AND v.automation_id = sqlc.arg(automation_id) AND v.number < sqlc.arg(before_number)::int
ORDER BY v.number DESC
LIMIT sqlc.arg(max_rows)::int;

-- name: UpdateDraftAutomationVersion :execrows
-- A new definition returns an authored version to DRAFT.
UPDATE pc.automation_versions
SET definition = sqlc.arg(definition), digest = sqlc.arg(digest), state = 'DRAFT', summary = '', findings = '[]',
    validated_at = NULL, tested_at = NULL, tested_run_id = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('DRAFT', 'VALIDATED', 'TESTED')
  AND digest = sqlc.arg(base_digest);

-- name: RecordAutomationValidation :execrows
-- Stores a validation's findings and summary; passed moves it to VALIDATED.
UPDATE pc.automation_versions
SET state = CASE WHEN sqlc.arg(passed)::bool THEN 'VALIDATED' ELSE 'DRAFT' END,
    summary = sqlc.arg(summary), findings = sqlc.arg(findings),
    validated_at = CASE WHEN sqlc.arg(passed)::bool THEN now() ELSE NULL END,
    tested_at = NULL, tested_run_id = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('DRAFT', 'VALIDATED', 'TESTED')
  AND digest = sqlc.arg(digest);

-- name: MarkAutomationVersionTested :execrows
-- TestGate passed for this digest (D34).
UPDATE pc.automation_versions SET state = 'TESTED', tested_run_id = sqlc.arg(run_id), tested_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'VALIDATED' AND digest = sqlc.arg(digest);

-- name: PublishAutomationVersion :execrows
UPDATE pc.automation_versions SET state = 'PUBLISHED', change_request_id = sqlc.arg(change_request_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('VALIDATED', 'TESTED') AND digest = sqlc.arg(digest);

-- name: SupersedeAutomationVersions :execrows
UPDATE pc.automation_versions SET state = 'SUPERSEDED'
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state = 'PUBLISHED'
  AND id <> sqlc.arg(keep_id);

-- name: RetireAutomationVersions :execrows
UPDATE pc.automation_versions SET state = 'RETIRED'
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state <> 'RETIRED';

-- name: InsertAutomationCeiling :exec
INSERT INTO pc.automation_ceilings (org_id, id, automation_id, version_id, digest, approved_by, change_request_id, review_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(automation_id), sqlc.arg(version_id), sqlc.arg(digest),
        sqlc.arg(approved_by), sqlc.arg(change_request_id), sqlc.arg(review_by));

-- name: GetAutomationCeiling :one
SELECT c.org_id, c.id, c.automation_id, c.version_id, c.digest, c.approved_by, c.change_request_id, c.state, c.review_by,
       c.void_reason, c.created_at, c.ended_at, (c.review_by > now())::bool AS in_review
FROM pc.automation_ceilings c
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id);

-- name: LockAutomationCeiling :one
SELECT c.org_id, c.id, c.automation_id, c.version_id, c.digest, c.approved_by, c.change_request_id, c.state, c.review_by,
       c.void_reason, c.created_at, c.ended_at, (c.review_by > now())::bool AS in_review
FROM pc.automation_ceilings c
WHERE c.org_id = sqlc.arg(org_id) AND c.id = sqlc.arg(id)
FOR UPDATE;

-- name: GetActiveAutomationCeiling :one
SELECT c.org_id, c.id, c.automation_id, c.version_id, c.digest, c.approved_by, c.change_request_id, c.state, c.review_by,
       c.void_reason, c.created_at, c.ended_at, (c.review_by > now())::bool AS in_review
FROM pc.automation_ceilings c
WHERE c.org_id = sqlc.arg(org_id) AND c.automation_id = sqlc.arg(automation_id) AND c.state = 'ACTIVE';

-- name: EndAutomationCeiling :execrows
-- state: SUPERSEDED, EXPIRED, VOID (with a reason) or REVOKED.
UPDATE pc.automation_ceilings SET state = sqlc.arg(state), void_reason = sqlc.narg(void_reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: EndActiveAutomationCeilings :many
UPDATE pc.automation_ceilings SET state = sqlc.arg(state), void_reason = sqlc.narg(void_reason)
WHERE org_id = sqlc.arg(org_id) AND automation_id = sqlc.arg(automation_id) AND state = 'ACTIVE'
RETURNING id;

-- name: DueAutomationCeilings :many
-- Ceilings at or past their review date (D7), oldest first.
SELECT c.id, c.automation_id, c.review_by FROM pc.automation_ceilings c
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE' AND c.review_by <= now()
ORDER BY c.review_by
LIMIT sqlc.arg(max_rows)::int;

-- name: ReviewDueAutomationCeilings :many
-- Ceilings whose review date falls within the window (7-day and 1-day
-- notices).
SELECT c.id, c.automation_id, c.review_by, a.owner_user_id, a.name FROM pc.automation_ceilings c
JOIN pc.automations a ON a.org_id = c.org_id AND a.id = c.automation_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE' AND c.review_by > now()
  AND c.review_by <= now() + make_interval(secs => sqlc.arg(within_seconds)::int)
ORDER BY c.review_by
LIMIT sqlc.arg(max_rows)::int;

-- name: CeilingsApprovedBy :many
-- The ACTIVE ceilings a person approved (CeilingChecker, compromise).
SELECT c.id, c.automation_id FROM pc.automation_ceilings c
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE' AND sqlc.arg(user_id)::uuid = ANY (c.approved_by);

-- name: IncrementAutomationGrants :one
-- One more grant today (the database's UTC day), only while under the cap
-- (D9 step 8); no row: the
-- cap is reached.
INSERT INTO pc.automation_usage AS u (org_id, automation_id, day, grants)
SELECT sqlc.arg(org_id), sqlc.arg(automation_id), (now() AT TIME ZONE 'UTC')::date, 1 WHERE sqlc.arg(max_grants)::int >= 1
ON CONFLICT (org_id, automation_id, day) DO UPDATE SET grants = u.grants + 1
WHERE u.grants < sqlc.arg(max_grants)::int
RETURNING u.grants;

-- name: IncrementAutomationRuns :one
INSERT INTO pc.automation_usage AS u (org_id, automation_id, day, runs)
SELECT sqlc.arg(org_id), sqlc.arg(automation_id), (now() AT TIME ZONE 'UTC')::date, 1 WHERE sqlc.arg(max_runs)::int >= 1
ON CONFLICT (org_id, automation_id, day) DO UPDATE SET runs = u.runs + 1
WHERE u.runs < sqlc.arg(max_runs)::int
RETURNING u.runs;

-- name: ReserveAutomationBudget :one
-- Adds a positive amount to today's reserved budget in one currency (the
-- database's UTC day), only while it stays within max; no row: refused.
INSERT INTO pc.automation_budget_usage AS b (org_id, automation_id, day, currency, reserved)
SELECT sqlc.arg(org_id), sqlc.arg(automation_id), (now() AT TIME ZONE 'UTC')::date, sqlc.arg(currency)::text, sqlc.arg(amount)::numeric
WHERE sqlc.arg(amount)::numeric > 0 AND sqlc.arg(amount)::numeric <= sqlc.arg(max_amount)::numeric
ON CONFLICT (org_id, automation_id, day, currency) DO UPDATE SET reserved = b.reserved + EXCLUDED.reserved
WHERE b.reserved + EXCLUDED.reserved <= sqlc.arg(max_amount)::numeric
RETURNING b.reserved;

-- name: GetAutomationUsage :many
SELECT u.day, u.grants, u.runs FROM pc.automation_usage u
WHERE u.org_id = sqlc.arg(org_id) AND u.automation_id = sqlc.arg(automation_id) AND u.day >= sqlc.arg(since)::date
ORDER BY u.day;

-- name: GetAutomationBudgetUsage :many
SELECT b.day, b.currency, b.reserved FROM pc.automation_budget_usage b
WHERE b.org_id = sqlc.arg(org_id) AND b.automation_id = sqlc.arg(automation_id) AND b.day >= sqlc.arg(since)::date
ORDER BY b.day, b.currency;

-- name: ListAutomationIdentities :many
-- Inventory (D15): every automation with its identity, ceiling agents and
-- active grants under its ceiling.
SELECT a.id, a.service_account_id, a.name, a.owner_user_id, a.state, a.rollout, a.enabled_version_id,
       c.id AS ceiling_id, c.review_by AS ceiling_review_by,
       (SELECT count(*) FROM pc.grants g
        WHERE g.org_id = a.org_id AND g.ceiling_id = c.id AND g.state = 'ACTIVE')::int AS active_grants
FROM pc.automations a
LEFT JOIN pc.automation_ceilings c ON c.org_id = a.org_id AND c.automation_id = a.id AND c.state = 'ACTIVE'
WHERE a.org_id = sqlc.arg(org_id) AND a.state <> 'RETIRED'
ORDER BY a.name
LIMIT sqlc.arg(max_rows)::int;

-- name: ActiveGrantsOfExecution :many
-- RevokeForAutomationTx EXECUTION: the execution's own active grants.
SELECT g.id FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.automation_execution_id = sqlc.arg(execution_id) AND g.state = 'ACTIVE'
ORDER BY g.id;

-- name: ActiveGrantsOfCeiling :many
-- RevokeForAutomationTx CEILING: every active grant issued under a ceiling.
SELECT g.id FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.ceiling_id = sqlc.arg(ceiling_id) AND g.state = 'ACTIVE'
ORDER BY g.id;

-- name: ActiveRootGrantsOfAgents :many
-- RevokeForAutomationTx CEILING_AGENTS: the active root grants of the
-- ceiling's agents (revoking a root revokes its delegations).
SELECT g.id FROM pc.grants g
WHERE g.org_id = sqlc.arg(org_id) AND g.agent_id = ANY (sqlc.arg(agents)::uuid[]) AND g.state = 'ACTIVE'
  AND g.parent_id IS NULL
ORDER BY g.id
LIMIT 1000;

-- name: ActiveRunsOfGrants :many
-- RevokeAuthority: the active runs bound to revoked grants, with the
-- execution that started them.
SELECT r.id, r.automation_execution_id FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.grant_id = ANY (sqlc.arg(grants)::uuid[]) AND r.state = 'ACTIVE'
ORDER BY r.id;

-- name: LiveAutomationVersions :many
-- ACTIVE automations with their enabled version's definition (Pauser
-- selectors by agent or operation).
SELECT a.id, a.name, a.state, v.id AS version_id, v.definition
FROM pc.automations a
JOIN pc.automation_versions v ON v.org_id = a.org_id AND v.id = a.enabled_version_id
WHERE a.org_id = sqlc.arg(org_id) AND a.state = 'ACTIVE'
ORDER BY a.name
LIMIT 10000;

-- name: ActiveAutomationCeilings :many
-- Every ACTIVE ceiling with its automation and version (CeilingSweep).
SELECT c.id, c.automation_id, c.version_id, c.approved_by, c.review_by, (c.review_by <= now())::bool AS due,
       a.owner_user_id, a.name, a.state, v.definition
FROM pc.automation_ceilings c
JOIN pc.automations a ON a.org_id = c.org_id AND a.id = c.automation_id
JOIN pc.automation_versions v ON v.org_id = c.org_id AND v.id = c.version_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE'
ORDER BY c.review_by
LIMIT 10000;

-- name: ServiceAccountState :one
SELECT state FROM pc.service_accounts WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: AutomationAgentNames :many
SELECT id, name FROM pc.agents WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(ids)::uuid[]);

-- name: IdentityContained :one
-- Whether an unlifted containment control names the automation's identity
-- as a principal (D14): it then cannot act.
SELECT EXISTS (
    SELECT 1 FROM pc.containment_controls
    WHERE org_id = sqlc.arg(org_id) AND lifted_at IS NULL AND scope_type = 'principal'
      AND scope_id = 'service_account:' || sqlc.arg(service_account_id)::uuid::text
      AND (expires_at IS NULL OR expires_at > now())
)::bool AS contained;

-- name: SetAutomationOwner :execrows
-- A new owner (D68); a retired automation keeps its last one.
UPDATE pc.automations SET owner_user_id = sqlc.arg(owner_user_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RETIRED' AND owner_user_id <> sqlc.arg(owner_user_id);

-- name: ActiveGrantsOfAutomation :many
-- RevokeForAutomationTx AUTOMATION: every active grant issued under any of
-- the automation's authority rows, whatever their state (RevokeAuthority).
SELECT g.id FROM pc.grants g
JOIN pc.automation_ceilings c ON c.org_id = g.org_id AND c.id = g.ceiling_id
WHERE g.org_id = sqlc.arg(org_id) AND c.automation_id = sqlc.arg(automation_id) AND g.state = 'ACTIVE'
ORDER BY g.id;

-- name: CountActiveAutomationRuns :one
-- Without the engine's port, the automation's active runs stand for its
-- active executions (D91 K10): Retire refuses while any is live.
SELECT count(*)::int FROM pc.runs r
WHERE r.org_id = sqlc.arg(org_id) AND r.launcher_sa_id = sqlc.arg(service_account_id)
  AND r.automation_execution_id IS NOT NULL AND r.state = 'ACTIVE';

-- name: LockKillSwitch :one
-- An enabling's apply takes the org's containment row as the kill switch's
-- Engage does, so the two serialize (D91 K5).
SELECT kill_switch FROM pc.org_containment WHERE org_id = sqlc.arg(org_id) FOR UPDATE;
