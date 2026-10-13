-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approvals (G0 M5 part 2): what the decision pipeline reads about a held
-- transaction's approval request, its variants and the org's settings.

-- The latest request of the transaction for (run, action), with the open
-- evidence question and a proposed narrower action, if any.
-- name: LatestApprovalRequest :one
SELECT r.id, r.state, r.end_reason, r.binding, r.deadline_at, r.evidence_deadline_at, r.consume_by, r.display,
       coalesce((SELECT x.reason_code FROM pc.approval_responses x
         WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'REQUEST_EVIDENCE'
         ORDER BY x.created_at DESC LIMIT 1), '')::text AS question,
       (SELECT x.proposed_params FROM pc.approval_responses x
         WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'PROPOSE_NARROWER' LIMIT 1)::jsonb AS proposed
FROM pc.approval_requests r
JOIN pc.transactions t ON t.org_id = r.org_id AND t.id = r.transaction_id
WHERE r.org_id = sqlc.arg(org_id) AND t.run_id = sqlc.arg(run_id) AND t.action_id = sqlc.arg(action_id)
ORDER BY r.created_at DESC, r.id DESC
LIMIT 1;

-- Earlier requests for the same grant, operation and target (HR-037).
-- name: ApprovalVariants :many
SELECT id, created_at, state FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND variant_key = sqlc.arg(variant_key)
ORDER BY created_at DESC, id DESC
LIMIT 20;

-- Requests for the same operation and target approved in the 30 days
-- before now: context, never precedent (decision 9).
-- name: ApprovedForTarget :many
SELECT r.id, r.approved_at::timestamptz AS approved_at
FROM pc.approval_requests r
JOIN pc.transactions t ON t.org_id = r.org_id AND t.id = r.transaction_id
WHERE r.org_id = sqlc.arg(org_id) AND r.operation = sqlc.arg(operation) AND t.target_type = sqlc.arg(target_type)
  AND t.target_id = sqlc.arg(target_id) AND r.approved_at IS NOT NULL
  AND r.approved_at > sqlc.arg(now)::timestamptz - interval '30 days'
ORDER BY r.approved_at DESC, r.id DESC
LIMIT 5;

-- name: GetWaitlistSettings :one
SELECT * FROM pc.waitlist_settings WHERE org_id = sqlc.arg(org_id);

-- The launchers and principals of a run's ancestors, nearest first (runs
-- nest at most 8 deep).
-- name: RunAncestors :many
WITH RECURSIVE up (id, depth) AS (
    SELECT r.parent_run_id, 1 FROM pc.runs r WHERE r.org_id = sqlc.arg(org_id) AND r.id = sqlc.arg(id)
    UNION ALL
    SELECT p.parent_run_id, up.depth + 1 FROM up JOIN pc.runs p ON p.org_id = sqlc.arg(org_id) AND p.id = up.id
    WHERE up.depth < 9
)
SELECT p.launcher_user_id, p.launcher_sa_id, p.launcher_instance_id, p.principal_user_id, p.principal_sa_id
FROM up JOIN pc.runs p ON p.org_id = sqlc.arg(org_id) AND p.id = up.id
ORDER BY up.depth;

-- The finalization records a hold (HR-171): a new request, inserted once
-- with its binding fixed.
-- name: InsertApprovalRequest :exec
INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, transaction_id, evaluation, run_id, grant_id,
    grant_revision, variant_key, operation, previous_id, binding, binding_input, requirements, display, display_hash,
    action_ir,
    deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'ACTION', sqlc.arg(agent_id), sqlc.arg(transaction_id), sqlc.arg(evaluation),
    sqlc.arg(run_id), sqlc.arg(grant_id), sqlc.arg(grant_revision), sqlc.arg(variant_key), sqlc.arg(operation),
    sqlc.narg(previous_id), sqlc.arg(binding), sqlc.arg(binding_input), sqlc.arg(requirements), sqlc.arg(display),
    sqlc.arg(display_hash), sqlc.arg(action_ir), sqlc.arg(deadline_at));

-- A live request whose binding no longer matches is superseded, never
-- updated.
-- name: SupersedeApprovalRequest :one
UPDATE pc.approval_requests
SET state = 'SUPERSEDED', end_reason = 'BINDING_CHANGED', ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
RETURNING grant_id, run_id;

-- A live request past its deadline, evidence deadline or consume-by time
-- expires, by the database clock (HR-039).
-- name: ExpireApprovalRequest :one
UPDATE pc.approval_requests
SET state = 'EXPIRED', end_reason = 'APPROVAL_EXPIRED', ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
  AND (deadline_at <= now()
    OR (state = 'EVIDENCE_REQUESTED' AND evidence_deadline_at <= now())
    OR (state = 'APPROVED' AND consume_by <= now()))
RETURNING grant_id, run_id;

-- An approved request is consumed at most once, by the finalization that
-- issues the permit, before its deadline and its consume-by time (HR-171).
-- name: ConsumeApprovalRequest :one
UPDATE pc.approval_requests
SET state = 'CONSUMED', consumed_at = now(), permit_id = sqlc.arg(permit_id), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'APPROVED' AND binding = sqlc.arg(binding)
  AND consume_by > now() AND deadline_at > now()
RETURNING grant_id, run_id;

-- name: LockApprovalRequest :one
SELECT id, state FROM pc.approval_requests WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- An approved request a void left short returns to PENDING.
-- name: ReopenApprovalRequest :execrows
UPDATE pc.approval_requests SET state = 'PENDING', approved_at = NULL, consume_by = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'APPROVED';

-- Pending holds per grant and per run (HR-037): a slot is taken by a
-- conditional update below the cap, so concurrent holds cannot exceed it.
-- name: TakeHoldSlot :execrows
INSERT INTO pc.hold_slots (org_id, scope_kind, scope_id, pending)
VALUES (sqlc.arg(org_id), sqlc.arg(scope_kind), sqlc.arg(scope_id), 1)
ON CONFLICT (org_id, scope_kind, scope_id) DO UPDATE SET pending = pc.hold_slots.pending + 1, updated_at = now()
WHERE pc.hold_slots.pending < sqlc.arg(cap)::integer;

-- name: ReleaseHoldSlot :execrows
UPDATE pc.hold_slots SET pending = pending - 1, updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND scope_kind = sqlc.arg(scope_kind) AND scope_id = sqlc.arg(scope_id) AND pending > 0;

-- name: HoldCaps :one
SELECT coalesce(s.max_holds_per_grant, 20)::integer AS per_grant, coalesce(s.max_holds_per_run, 5)::integer AS per_run
FROM (SELECT 1) one LEFT JOIN pc.waitlist_settings s ON s.org_id = sqlc.arg(org_id);

-- Distinct held transactions of one variant key in the last 24 hours
-- (HR-037: the third raises security.variant_suspected).
-- name: CountRecentVariants :one
SELECT count(DISTINCT transaction_id)::integer FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND variant_key = sqlc.arg(variant_key) AND created_at > now() - interval '24 hours';

-- The ACTION_HOLD entry of a request (HR-177).
-- name: InsertHoldEntry :exec
INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, priority,
    deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'ACTION_HOLD', 'approval_request', sqlc.arg(request_id), sqlc.arg(agent_id),
    sqlc.arg(run_id), sqlc.arg(transaction_id), sqlc.arg(priority), sqlc.arg(deadline_at));

-- A request that returns to PENDING gets a new open entry with the priority
-- and deadline of its last one (one open entry per subject).
-- name: ReopenHoldEntry :execrows
INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, run_id, transaction_id, priority,
    deadline_at)
SELECT e.org_id, sqlc.arg(id), e.kind, e.subject_type, e.subject_id, e.agent_id, e.run_id, e.transaction_id, e.priority,
       e.deadline_at
FROM pc.waitlist_entries e
WHERE e.org_id = sqlc.arg(org_id) AND e.subject_type = 'approval_request' AND e.subject_id = sqlc.arg(request_id)
  AND e.deadline_at > now()
ORDER BY e.created_at DESC
LIMIT 1;

-- name: CloseRequestEntry :execrows
UPDATE pc.waitlist_entries
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_at = now(), decision_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND subject_type = 'approval_request' AND subject_id = sqlc.arg(request_id) AND state = 'OPEN';

-- Eligibility (HR-170): the people around a request's agent, run and
-- grant chain, read again whenever a response counts.
-- name: ApprovalEligibilityContext :one
SELECT a.owner_user_id, a.backup_owner_user_id, a.team_id, t.business_unit_id, a.environment_id,
       r.launcher_user_id, r.launcher_sa_id, r.launcher_instance_id, r.principal_user_id, r.principal_sa_id,
       ar.run_id, ar.grant_id, ar.requirements, ar.subject_kind, ar.requested_by
FROM pc.approval_requests ar
JOIN pc.agents a ON a.org_id = ar.org_id AND a.id = ar.agent_id
LEFT JOIN pc.teams t ON t.org_id = a.org_id AND t.id = a.team_id
LEFT JOIN pc.runs r ON r.org_id = ar.org_id AND r.id = ar.run_id
WHERE ar.org_id = sqlc.arg(org_id) AND ar.id = sqlc.arg(id);

-- Everyone who issued or revised a grant of the chain (decision 3).
-- name: ChainIssuers :many
SELECT g.grantor_id AS user_id FROM pc.grant_lineage l
JOIN pc.grants g ON g.org_id = l.org_id AND g.id = l.ancestor_id
WHERE l.org_id = sqlc.arg(org_id) AND l.grant_id = sqlc.arg(grant_id) AND g.grantor_kind = 'user'
UNION
SELECT substr(v.created_by, 6)::uuid FROM pc.grant_lineage l
JOIN pc.grant_revisions v ON v.org_id = l.org_id AND v.grant_id = l.ancestor_id
WHERE l.org_id = sqlc.arg(org_id) AND l.grant_id = sqlc.arg(grant_id) AND v.created_by ~ '^user:[0-9a-f-]{36}$';

-- name: EligibilityUsers :many
SELECT id, state, created_at FROM pc.users WHERE org_id = sqlc.arg(org_id) AND id = ANY (sqlc.arg(ids)::uuid[]);

-- Bindings of approval roles on the agent's scope path.
-- name: EligibilityBindings :many
SELECT user_id::uuid AS user_id, role, created_at, created_by FROM pc.role_bindings
WHERE org_id = sqlc.arg(org_id) AND user_id = ANY (sqlc.arg(ids)::uuid[]) AND role = ANY (sqlc.arg(roles)::text[])
  AND (scope_type = 'ORG'
    OR (scope_type = 'BUSINESS_UNIT' AND business_unit_id = sqlc.narg(business_unit_id)::uuid)
    OR (scope_type = 'TEAM' AND team_id = sqlc.narg(team_id)::uuid)
    OR (scope_type = 'ENVIRONMENT' AND environment_id = sqlc.narg(environment_id)::uuid));

-- name: EligibilityCredentials :many
SELECT id, user_id, created_at FROM pc.webauthn_credentials
WHERE org_id = sqlc.arg(org_id) AND user_id = ANY (sqlc.arg(ids)::uuid[]) AND state = 'ACTIVE';

-- name: ApprovalCooldowns :one
SELECT s.min_account_age_s, s.min_role_age_s, s.min_credential_age_s, s.self_grant_delay_s
FROM (SELECT 1) one LEFT JOIN pc.waitlist_settings s ON s.org_id = sqlc.arg(org_id);

-- The responses that count toward a request's requirements.
-- name: CountingResponses :many
SELECT id, user_id, credential_id::uuid AS credential_id, requirement::integer AS requirement
FROM pc.approval_responses
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id) AND kind IN ('APPROVE', 'STEP_UP')
  AND voided_at IS NULL
ORDER BY created_at, id;

-- name: VoidResponse :execrows
UPDATE pc.approval_responses SET voided_at = now(), void_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND voided_at IS NULL;

-- Responses (G0 M5 part 2 slice 207). Each use case locks the request,
-- checks the responder and changes the state by a conditional update.
-- name: GetApprovalRequestForUpdate :one
SELECT * FROM pc.approval_requests WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: GetApprovalRequest :one
SELECT * FROM pc.approval_requests WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LiveRequestOfTransaction :one
SELECT * FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id)
  AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
FOR UPDATE;

-- The first response to a request is its waitlist entry's first response
-- (SLA metrics, slice 214c).
-- name: InsertApprovalResponse :exec
WITH first_response AS (
    UPDATE pc.waitlist_entries SET first_response_at = now()
    WHERE org_id = sqlc.arg(org_id) AND subject_type = 'approval_request' AND subject_id = sqlc.arg(request_id)
      AND first_response_at IS NULL
)
INSERT INTO pc.approval_responses (org_id, id, request_id, user_id, session_id, cli_session_id, kind, requirement,
    credential_id, authenticator_data, client_data_json, signature, reason_code, alternative_code, note, proposed_params,
    batch_id)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(request_id), sqlc.arg(user_id), sqlc.narg(session_id),
    sqlc.narg(cli_session_id), sqlc.arg(kind), sqlc.narg(requirement), sqlc.narg(credential_id),
    sqlc.narg(authenticator_data), sqlc.narg(client_data_json), sqlc.narg(signature), sqlc.narg(reason_code),
    sqlc.narg(alternative_code), sqlc.arg(note), sqlc.narg(proposed_params), sqlc.narg(batch_id));

-- A decline or a narrower proposal ends a waiting request (HR-171).
-- name: DeclineApprovalRequest :one
UPDATE pc.approval_requests SET state = 'DECLINED', end_reason = sqlc.arg(end_reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'EVIDENCE_REQUESTED') AND deadline_at > now()
RETURNING grant_id, run_id;

-- name: AskForEvidence :execrows
UPDATE pc.approval_requests SET state = 'EVIDENCE_REQUESTED', evidence_deadline_at = sqlc.arg(evidence_deadline)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING'
  AND sqlc.arg(evidence_deadline)::timestamptz > now() AND sqlc.arg(evidence_deadline)::timestamptz < deadline_at;

-- name: EvidenceArrived :execrows
UPDATE pc.approval_requests SET state = 'PENDING', evidence_deadline_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'EVIDENCE_REQUESTED' AND evidence_deadline_at > now();

-- name: InsertApprovalEvidence :exec
INSERT INTO pc.approval_evidence (org_id, id, request_id, author_kind, author_user_id, author_instance_id, note)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(request_id), sqlc.arg(author_kind), sqlc.narg(author_user_id),
    sqlc.narg(author_instance_id), sqlc.arg(note)::text);

-- name: CountApprovalEvidence :one
SELECT count(*)::integer FROM pc.approval_evidence WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id);

-- When every requirement is met, the request is APPROVED with its
-- consume-by time (decision 6).
-- name: MarkApproved :execrows
UPDATE pc.approval_requests SET state = 'APPROVED', approved_at = now(), consume_by = sqlc.arg(consume_by)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING' AND deadline_at > now()
  AND sqlc.arg(consume_by)::timestamptz > now();

-- The BINDING ceremony is consumed once, in the transaction that records
-- the response (HR-033, HR-153): bound to the browser session, the user
-- and the request, within its 5 minutes.
-- name: ConsumeBindingCeremony :execrows
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND approval_request_id = sqlc.arg(request_id) AND user_id = sqlc.arg(user_id) AND session_id = sqlc.arg(session_id)
  AND consumed_at IS NULL AND expires_at > now();

-- name: ConsumeWindow :one
SELECT s.consume_window_s FROM (SELECT 1) one LEFT JOIN pc.waitlist_settings s ON s.org_id = sqlc.arg(org_id);

-- name: RunInstance :one
SELECT instance_id FROM pc.runs WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- The approvals janitor (G0 M5 part 2 slice 207b) keeps the queue honest;
-- correctness never depends on it, because expiry is checked at use and a
-- material change gives a new binding.
-- name: OverdueApprovalRequests :many
SELECT id FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
  AND (deadline_at <= now()
    OR (state = 'EVIDENCE_REQUESTED' AND evidence_deadline_at <= now())
    OR (state = 'APPROVED' AND consume_by <= now()))
ORDER BY deadline_at
LIMIT 500;

-- Live action requests made moot by a change of containment, agent, run,
-- grant chain or definition, with the reason (decision 6, F153).
-- name: MootApprovalRequests :many
SELECT r.id, coalesce(CASE
    WHEN c.kill_switch THEN 'KILL_SWITCH_ENGAGED'
    WHEN a.state = 'SUSPENDED' THEN 'AGENT_SUSPENDED'
    WHEN a.state = 'RETIRED' THEN 'AGENT_RETIRED'
    WHEN run.state <> 'ACTIVE' OR run.expires_at <= now() THEN 'RUN_ENDED'
    WHEN EXISTS (SELECT 1 FROM pc.grant_lineage l JOIN pc.grants x ON x.org_id = l.org_id AND x.id = l.ancestor_id
                 WHERE l.org_id = r.org_id AND l.grant_id = r.grant_id AND x.state <> 'ACTIVE') THEN 'GRANT_REVOKED'
    WHEN g.current_revision <> r.grant_revision THEN 'GRANT_REVISED'
    WHEN pv.state IS DISTINCT FROM 'ACTIVE' THEN 'DEFINITION_CHANGED'
    END, '')::text AS reason
FROM pc.approval_requests r
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
JOIN pc.runs run ON run.org_id = r.org_id AND run.id = r.run_id
JOIN pc.grants g ON g.org_id = r.org_id AND g.id = r.grant_id
LEFT JOIN pc.org_containment c ON c.org_id = r.org_id
LEFT JOIN pc.tool_packages tp ON tp.org_id = r.org_id
    AND tp.name = convert_from(r.action_ir, 'UTF8')::jsonb #>> '{definition,package}'
LEFT JOIN pc.package_versions pv ON pv.org_id = tp.org_id AND pv.package_id = tp.id
    AND pv.version = convert_from(r.action_ir, 'UTF8')::jsonb #>> '{definition,version}'
WHERE r.org_id = sqlc.arg(org_id) AND r.subject_kind = 'ACTION' AND r.action_ir IS NOT NULL
  AND r.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
ORDER BY r.created_at
LIMIT 500;

-- name: InvalidateApprovalRequest :one
UPDATE pc.approval_requests SET state = 'INVALIDATED', end_reason = sqlc.arg(end_reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
RETURNING grant_id, run_id;

-- Live requests with responses that count: their people are checked again.
-- name: RequestsWithResponses :many
SELECT DISTINCT r.id FROM pc.approval_requests r
JOIN pc.approval_responses x ON x.org_id = r.org_id AND x.request_id = r.id
WHERE r.org_id = sqlc.arg(org_id) AND r.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
  AND x.kind IN ('APPROVE', 'STEP_UP') AND x.voided_at IS NULL
LIMIT 500;

-- The approval page (G0 M5 part 2 slice 209). The list reads the most
-- urgent waiting requests, by their entry's priority and then deadline;
-- eligibility is checked per request in Go (HR-170).
-- name: WaitingApprovalRequests :many
SELECT r.*, coalesce(e.priority, 4)::integer AS priority
FROM pc.approval_requests r
LEFT JOIN pc.waitlist_entries e
  ON e.org_id = r.org_id AND e.subject_type = 'approval_request' AND e.subject_id = r.id AND e.state = 'OPEN'
WHERE r.org_id = sqlc.arg(org_id) AND r.state IN ('PENDING', 'EVIDENCE_REQUESTED') AND r.deadline_at > now()
  AND (r.evidence_deadline_at IS NULL OR r.evidence_deadline_at > now())
ORDER BY priority, r.deadline_at, r.id
LIMIT sqlc.arg(lim);

-- name: RespondedRequests :many
SELECT DISTINCT request_id FROM pc.approval_responses
WHERE org_id = sqlc.arg(org_id) AND user_id = sqlc.arg(user_id) AND voided_at IS NULL AND kind IN ('APPROVE', 'STEP_UP')
  AND request_id = ANY(sqlc.arg(request_ids)::uuid[]);

-- name: RecentResponsesBy :many
SELECT p.request_id, p.kind, p.created_at, (p.voided_at IS NOT NULL)::boolean AS voided, r.operation, r.state
FROM pc.approval_responses p
JOIN pc.approval_requests r ON r.org_id = p.org_id AND r.id = p.request_id
WHERE p.org_id = sqlc.arg(org_id) AND p.user_id = sqlc.arg(user_id)
ORDER BY p.created_at DESC, p.id
LIMIT sqlc.arg(lim);

-- name: RequestResponses :many
SELECT id, user_id, kind, requirement, reason_code, alternative_code, note, proposed_params, created_at, voided_at, credential_id, batch_id,
       void_reason
FROM pc.approval_responses
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id)
ORDER BY created_at, id;

-- name: RequestEvidence :many
SELECT id, author_kind, author_user_id, author_instance_id, coalesce(note, '')::text AS note, created_at
FROM pc.approval_evidence
WHERE org_id = sqlc.arg(org_id) AND request_id = sqlc.arg(request_id)
ORDER BY created_at, id;

-- Restorations (G0 M5 part 2 slice 210, decision 11): an approval request
-- with subject kind RESTORATION, at most one live per agent.
-- name: InsertRestorationRequest :exec
INSERT INTO pc.approval_requests (org_id, id, subject_kind, agent_id, requested_by, operation, binding, binding_input,
    requirements, display, display_hash, deadline_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), 'RESTORATION', sqlc.arg(agent_id), sqlc.arg(requested_by), 'agent.restore',
    sqlc.arg(binding), sqlc.arg(binding_input), sqlc.arg(requirements), sqlc.arg(display), sqlc.arg(display_hash),
    sqlc.arg(deadline_at));

-- name: LiveRestoration :one
SELECT id FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND subject_kind = 'RESTORATION'
  AND state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED');

-- An agent's recorded changes: a restoration binds their count, so any
-- later change to the agent gives a different binding.
-- name: AgentChangeCount :one
SELECT count(*)::bigint FROM pc.agent_changes WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id);

-- name: AgentSuspendedAt :one
SELECT coalesce(max(created_at), now())::timestamptz FROM pc.agent_changes
WHERE org_id = sqlc.arg(org_id) AND agent_id = sqlc.arg(agent_id) AND kind = 'agent.suspended';

-- An approved restoration is used at once, in its approval's transaction.
-- name: ConsumeRestoration :execrows
UPDATE pc.approval_requests SET state = 'CONSUMED', consumed_at = now(), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND subject_kind = 'RESTORATION' AND state = 'APPROVED';

-- Live restorations made moot: the agent left SUSPENDED (it was retired)
-- or changed since the request was made.
-- name: MootRestorations :many
SELECT r.id, (CASE WHEN a.state = 'RETIRED' THEN 'AGENT_RETIRED'
                   WHEN a.state <> 'SUSPENDED' THEN 'AGENT_NOT_SUSPENDED'
                   ELSE 'AGENT_CHANGED' END)::text AS reason
FROM pc.approval_requests r
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
WHERE r.org_id = sqlc.arg(org_id) AND r.subject_kind = 'RESTORATION'
  AND r.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED')
  AND (a.state <> 'SUSPENDED'
       OR (convert_from(r.binding_input, 'UTF8')::jsonb ->> 'agent_change_seq')::bigint
          <> (SELECT count(*) FROM pc.agent_changes c WHERE c.org_id = r.org_id AND c.agent_id = r.agent_id))
ORDER BY r.created_at
LIMIT 500;

-- The people told a request's outcome (slice 211): those it was routed to,
-- and the person who asked for it (the run's launcher, or a restoration's
-- requester).
-- name: RequestRecipients :many
SELECT DISTINCT x.user_id::uuid AS user_id FROM (
    SELECT r.user_id FROM pc.waitlist_routes r
    JOIN pc.waitlist_entries e ON e.org_id = r.org_id AND e.id = r.entry_id
    WHERE e.org_id = sqlc.arg(org_id) AND e.subject_type = 'approval_request' AND e.subject_id = sqlc.arg(request_id)
    UNION
    SELECT run.launcher_user_id FROM pc.approval_requests a
    JOIN pc.runs run ON run.org_id = a.org_id AND run.id = a.run_id
    WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(request_id)
    UNION
    SELECT a.requested_by FROM pc.approval_requests a WHERE a.org_id = sqlc.arg(org_id) AND a.id = sqlc.arg(request_id)
) x
WHERE x.user_id IS NOT NULL
LIMIT 100;

-- Wait handles (slice 212, HR-174): the latest request of a transaction
-- whose run is bound to the waiting instance (and is run_id, when given),
-- with the open evidence question and a proposed narrower action.
-- name: WaitRequest :one
SELECT r.id, r.state, r.end_reason, r.deadline_at, r.evidence_deadline_at, r.consume_by,
       coalesce((SELECT x.reason_code FROM pc.approval_responses x
         WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'REQUEST_EVIDENCE'
         ORDER BY x.created_at DESC LIMIT 1), '')::text AS question,
       (SELECT x.proposed_params FROM pc.approval_responses x
         WHERE x.org_id = r.org_id AND x.request_id = r.id AND x.kind = 'PROPOSE_NARROWER' LIMIT 1)::jsonb AS proposed,
       now()::timestamptz AS now
FROM pc.approval_requests r
JOIN pc.transactions t ON t.org_id = r.org_id AND t.id = r.transaction_id
JOIN pc.runs run ON run.org_id = t.org_id AND run.id = t.run_id
WHERE r.org_id = sqlc.arg(org_id) AND r.transaction_id = sqlc.arg(transaction_id) AND run.instance_id = sqlc.arg(instance_id)
  AND (sqlc.narg(run_id)::uuid IS NULL OR t.run_id = sqlc.narg(run_id)::uuid)
ORDER BY r.created_at DESC, r.id DESC
LIMIT 1;

-- The org's approval requests, newest first (slice 213), by state and
-- optionally agent and run; each is checked for the caller in Go (T-037).
-- name: ListApprovalRequests :many
SELECT * FROM pc.approval_requests
WHERE org_id = sqlc.arg(org_id) AND state = ANY (sqlc.arg(states)::text[])
  AND (sqlc.narg(before)::uuid IS NULL OR id < sqlc.narg(before)::uuid)
  AND (sqlc.narg(agent_id)::uuid IS NULL OR agent_id = sqlc.narg(agent_id)::uuid)
  AND (sqlc.narg(run_id)::uuid IS NULL OR run_id = sqlc.narg(run_id)::uuid)
ORDER BY id DESC
LIMIT sqlc.arg(lim);

-- Batches (slice 214, HR-175): one decider's batch of up to 25 requests.
-- name: InsertApprovalBatch :exec
INSERT INTO pc.approval_batches (org_id, id, kind, user_id, session_id, cli_session_id, batch_hash, request_ids, state,
    completed_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(kind), sqlc.arg(user_id), sqlc.narg(session_id), sqlc.narg(cli_session_id),
    sqlc.arg(batch_hash), sqlc.arg(request_ids)::uuid[], sqlc.arg(state),
    CASE WHEN sqlc.arg(state)::text = 'COMPLETED' THEN now() END);

-- A batch approval's BINDING ceremony, consumed once with its responses.
-- name: ConsumeBatchCeremony :execrows
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND batch_id = sqlc.arg(batch_id) AND user_id = sqlc.arg(user_id) AND session_id = sqlc.arg(session_id)
  AND consumed_at IS NULL AND expires_at > now();

-- name: LockApprovalBatch :one
SELECT * FROM pc.approval_batches
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND user_id = sqlc.arg(user_id) AND kind = 'APPROVE' AND state = 'PENDING'
FOR UPDATE;

-- name: CompleteApprovalBatch :execrows
UPDATE pc.approval_batches SET state = 'COMPLETED', completed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';
