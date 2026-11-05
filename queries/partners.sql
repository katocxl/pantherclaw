-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- MSSP partner links, partner sessions and rollout proposals (G0 M38
-- D1100–D1102; HR-810..816). Links and proposals are visible to both of
-- their orgs (RLS), so every query names the side it runs for. Every state
-- change is a conditional update; the guards decide the timestamps by the
-- database clock.

-- name: InsertPartnerLink :exec
INSERT INTO pc.partner_links (id, partner_org, customer_org, partner_name, scopes, duration_days, reason, renews,
                              requested_by, requested_account, request_expires_at)
VALUES (sqlc.arg(id), sqlc.arg(partner_org), sqlc.arg(customer_org), sqlc.arg(partner_name), sqlc.arg(scopes),
        sqlc.arg(duration_days), sqlc.arg(reason), sqlc.narg(renews), sqlc.arg(requested_by), sqlc.narg(requested_account),
        now() + interval '7 days');

-- name: GetPartnerLink :one
-- One link of org's, as partner or customer, with what the database clock
-- says of it.
SELECT id, partner_org, customer_org, partner_name, state, scopes, duration_days, reason, renews, requested_by,
       requested_account, requested_at, request_expires_at, decided_by, decided_credential, decided_at, starts_at,
       ends_at, revoked_by, revoked_at, end_reason,
       (state = 'REQUESTED' AND now() >= request_expires_at)::bool AS request_expired,
       (state = 'ACTIVE' AND now() >= ends_at)::bool AS window_over
FROM pc.partner_links
WHERE id = sqlc.arg(id) AND (partner_org = sqlc.arg(org)::uuid OR customer_org = sqlc.arg(org)::uuid);

-- name: ListPartnerLinks :many
SELECT id, partner_org, customer_org, partner_name, state, scopes, duration_days, reason, renews, requested_by,
       requested_account, requested_at, request_expires_at, decided_by, decided_credential, decided_at, starts_at,
       ends_at, revoked_by, revoked_at, end_reason,
       (state = 'REQUESTED' AND now() >= request_expires_at)::bool AS request_expired,
       (state = 'ACTIVE' AND now() >= ends_at)::bool AS window_over
FROM pc.partner_links
WHERE (partner_org = sqlc.arg(org)::uuid OR customer_org = sqlc.arg(org)::uuid)
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivePartnerLinksOfPartner :many
-- The partner's links in force, by the database clock.
SELECT id, customer_org, scopes, ends_at
FROM pc.partner_links
WHERE partner_org = sqlc.arg(partner_org) AND state = 'ACTIVE' AND now() >= starts_at AND now() < ends_at
ORDER BY customer_org, id
LIMIT 1000;

-- name: LivePartnerLink :one
-- The link in force between a partner and a customer, if any.
SELECT id, scopes, starts_at, ends_at
FROM pc.partner_links
WHERE partner_org = sqlc.arg(partner_org) AND customer_org = sqlc.arg(customer_org) AND state = 'ACTIVE'
  AND now() >= starts_at AND now() < ends_at
ORDER BY ends_at DESC
LIMIT 1;

-- name: DecidePartnerLink :execrows
-- A customer person decides a REQUESTED link (HR-810); the guard sets the
-- decision time and the window and refuses the requester's own account.
UPDATE pc.partner_links
SET state = sqlc.arg(state), decided_by = sqlc.arg(decided_by), decided_credential = sqlc.arg(decided_credential)
WHERE id = sqlc.arg(id) AND customer_org = sqlc.arg(customer_org) AND state = 'REQUESTED'
  AND now() < request_expires_at;

-- name: RevokePartnerLink :execrows
-- The customer ends a link, requested or in force, at any time (HR-810).
UPDATE pc.partner_links
SET state = 'REVOKED', revoked_by = sqlc.arg(revoked_by), end_reason = sqlc.narg(end_reason)
WHERE id = sqlc.arg(id) AND customer_org = sqlc.arg(customer_org) AND state IN ('REQUESTED', 'ACTIVE');

-- name: ExpirePartnerLinks :many
-- Links of org (as customer) whose window ended or whose request went
-- undecided for seven days.
UPDATE pc.partner_links
SET state = 'EXPIRED'
WHERE customer_org = sqlc.arg(customer_org)
  AND ((state = 'ACTIVE' AND now() >= ends_at) OR (state = 'REQUESTED' AND now() >= request_expires_at))
RETURNING id, partner_org;

-- name: InsertPartnerSession :one
INSERT INTO pc.partner_sessions (org_id, id, link_id, partner_org, partner_user, partner_credential, secret_hash,
                                 user_agent, client_ip, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(link_id), sqlc.arg(partner_org), sqlc.arg(partner_user),
        sqlc.arg(partner_credential), sqlc.arg(secret_hash), sqlc.arg(user_agent), sqlc.arg(client_ip),
        LEAST(sqlc.arg(link_ends_at)::timestamptz, now() + make_interval(secs => sqlc.arg(max_seconds)::int)))
RETURNING id, expires_at;

-- name: PartnerSessionBySecret :one
-- A partner session with its link's state, by the database clock (HR-811).
SELECT s.id, s.link_id, s.partner_org, s.partner_user, s.state, s.expires_at, s.last_seen_at,
       (now() < s.expires_at)::bool AS within_lifetime,
       (now() < s.last_seen_at + make_interval(secs => sqlc.arg(idle_seconds)::int))::bool AS within_idle,
       (now() >= s.last_seen_at + interval '1 minute')::bool AS touch,
       l.scopes, l.ends_at AS link_ends_at,
       (l.state = 'ACTIVE' AND l.customer_org = s.org_id AND l.partner_org = s.partner_org
        AND now() >= l.starts_at AND now() < l.ends_at)::bool AS link_live
FROM pc.partner_sessions s
JOIN pc.partner_links l ON l.id = s.link_id
WHERE s.org_id = sqlc.arg(org_id) AND s.secret_hash = sqlc.arg(secret_hash);

-- name: GetPartnerSession :one
SELECT s.id, s.link_id, s.partner_org, s.partner_user, s.state, s.created_at, s.expires_at, l.scopes,
       l.ends_at AS link_ends_at
FROM pc.partner_sessions s
JOIN pc.partner_links l ON l.id = s.link_id
WHERE s.org_id = sqlc.arg(org_id) AND s.id = sqlc.arg(id);

-- name: EndPartnerSession :execrows
UPDATE pc.partner_sessions SET state = 'ENDED', end_reason = sqlc.arg(end_reason), ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: EndPartnerSessionsOfLink :execrows
UPDATE pc.partner_sessions SET state = 'ENDED', end_reason = 'LINK_ENDED', ended_at = now()
WHERE org_id = sqlc.arg(org_id) AND link_id = sqlc.arg(link_id) AND state = 'ACTIVE';

-- name: TouchPartnerSession :exec
UPDATE pc.partner_sessions SET last_seen_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: PartnerCustomerSummary :one
-- The counts a partner sees of one customer (HR-816): run in the
-- customer's own tenant transaction, after partner.summary_read is
-- recorded there.
SELECT o.name,
       (SELECT count(*) FROM pc.approval_requests a
        WHERE a.org_id = o.id AND a.state IN ('PENDING', 'EVIDENCE_REQUESTED'))::bigint AS waiting_approvals,
       (SELECT count(*) FROM pc.alerts al WHERE al.org_id = o.id AND al.state = 'OPEN' AND NOT al.test)::bigint AS open_alerts,
       -- The epoch when no decision was recorded.
       COALESCE((SELECT max(t.created_at) FROM pc.transactions t WHERE t.org_id = o.id), 'epoch'::timestamptz)::timestamptz
           AS last_decision_at
FROM pc.orgs o
WHERE o.id = sqlc.arg(org_id);

-- name: InsertPartnerProposal :exec
INSERT INTO pc.partner_proposals (id, link_id, partner_org, customer_org, kind, title, body, template_id, proposed_by,
                                  expires_at)
VALUES (sqlc.arg(id), sqlc.arg(link_id), sqlc.arg(partner_org), sqlc.arg(customer_org), sqlc.arg(kind), sqlc.arg(title),
        sqlc.arg(body), sqlc.narg(template_id), sqlc.arg(proposed_by), now() + interval '30 days');

-- name: GetPartnerProposal :one
SELECT id, link_id, partner_org, customer_org, kind, title, body, template_id, state, proposed_by, created_at, expires_at,
       decided_by, decided_at, decline_reason, draft_ref,
       (state = 'PROPOSED' AND now() >= expires_at)::bool AS expired
FROM pc.partner_proposals
WHERE id = sqlc.arg(id) AND (partner_org = sqlc.arg(org)::uuid OR customer_org = sqlc.arg(org)::uuid);

-- name: ListPartnerProposals :many
SELECT id, link_id, partner_org, customer_org, kind, title, template_id, state, proposed_by, created_at, expires_at,
       decided_by, decided_at, decline_reason, draft_ref,
       (state = 'PROPOSED' AND now() >= expires_at)::bool AS expired
FROM pc.partner_proposals
WHERE (partner_org = sqlc.arg(org)::uuid OR customer_org = sqlc.arg(org)::uuid)
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: AcceptPartnerProposal :execrows
UPDATE pc.partner_proposals
SET state = 'ACCEPTED', decided_by = sqlc.arg(decided_by), draft_ref = sqlc.arg(draft_ref)
WHERE id = sqlc.arg(id) AND customer_org = sqlc.arg(customer_org) AND state = 'PROPOSED' AND now() < expires_at;

-- name: DeclinePartnerProposal :execrows
UPDATE pc.partner_proposals
SET state = 'DECLINED', decided_by = sqlc.arg(decided_by), decline_reason = sqlc.narg(decline_reason)
WHERE id = sqlc.arg(id) AND customer_org = sqlc.arg(customer_org) AND state = 'PROPOSED' AND now() < expires_at;

-- name: WithdrawPartnerProposal :execrows
UPDATE pc.partner_proposals
SET state = 'WITHDRAWN', decided_by = sqlc.arg(decided_by)
WHERE id = sqlc.arg(id) AND partner_org = sqlc.arg(partner_org) AND state = 'PROPOSED' AND now() < expires_at;

-- name: ExpirePartnerProposals :many
UPDATE pc.partner_proposals SET state = 'EXPIRED'
WHERE customer_org = sqlc.arg(customer_org) AND state = 'PROPOSED' AND now() >= expires_at
RETURNING id, partner_org;

-- name: PartnerOriginOfChange :one
-- The partner org whose accepted proposal made the version a PUBLISH or
-- ROLLOUT change request is about (G0 M38 D1102, HR-815); no rows when
-- the version did not come from a partner.
SELECT p.partner_org
FROM pc.partner_proposals p
WHERE p.customer_org = sqlc.arg(org_id)::uuid AND p.state = 'ACCEPTED'
  AND p.draft_ref = (CASE sqlc.arg(kind)::text
                         WHEN 'PUBLISH' THEN sqlc.arg(subject_id)::uuid
                         WHEN 'ROLLOUT' THEN (SELECT r.version_id FROM pc.policy_rollouts r
                                              WHERE r.org_id = sqlc.arg(org_id)::uuid AND r.id = sqlc.arg(subject_id)::uuid)
                     END)
LIMIT 1;
