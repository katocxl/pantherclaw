-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

-- Customer consequence rules (G0 M17 D106, D107).

-- InsertCustomerConsequenceRule proposes the next version of a rule.
-- name: InsertCustomerConsequenceRule :one
INSERT INTO pc.customer_consequence_rules (org_id, id, rule_id, version, body, digest, proposed_by)
SELECT sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(rule_id)::text, coalesce(max(r.version), 0) + 1, sqlc.arg(body), sqlc.arg(digest),
       sqlc.arg(proposed_by)
FROM pc.customer_consequence_rules r
WHERE r.org_id = sqlc.arg(org_id) AND r.rule_id = sqlc.arg(rule_id)::text
RETURNING *;

-- name: GetCustomerConsequenceRule :one
SELECT * FROM pc.customer_consequence_rules
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- GetCustomerConsequenceRuleVersion is one version of a rule, as a
-- recorded evaluation names it.
-- name: GetCustomerConsequenceRuleVersion :one
SELECT * FROM pc.customer_consequence_rules
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND version = sqlc.arg(version);

-- ActiveCustomerConsequenceRules are the rules the pipeline evaluates, in
-- rule id order.
-- name: ActiveCustomerConsequenceRules :many
SELECT * FROM pc.customer_consequence_rules
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE'
ORDER BY rule_id
LIMIT 256;

-- name: CountActiveCustomerConsequenceRules :one
SELECT count(*)::integer FROM pc.customer_consequence_rules
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND rule_id <> sqlc.arg(except_rule_id);

-- ListCustomerConsequenceRules lists every version, by rule, newest first;
-- rule_id empty lists every rule.
-- name: ListCustomerConsequenceRules :many
SELECT * FROM pc.customer_consequence_rules
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(rule_id)::text = '' OR rule_id = sqlc.arg(rule_id)::text)
ORDER BY rule_id, version DESC
LIMIT 500;

-- ActivateCustomerConsequenceRule makes a proposed version ACTIVE with its
-- approver, once the rule's ACTIVE version has been retired.
-- name: ActivateCustomerConsequenceRule :execrows
UPDATE pc.customer_consequence_rules
SET state = 'ACTIVE', approved_by = sqlc.arg(approved_by), updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PROPOSED' AND proposed_by <> sqlc.arg(approved_by);

-- RetireActiveCustomerConsequenceRule retires the ACTIVE version of a
-- rule, if there is one.
-- name: RetireActiveCustomerConsequenceRule :many
UPDATE pc.customer_consequence_rules
SET state = 'RETIRED', updated_at = now()
WHERE org_id = sqlc.arg(org_id) AND rule_id = sqlc.arg(rule_id) AND state = 'ACTIVE'
RETURNING id, version;

-- name: LockCustomerConsequenceRules :exec
-- Serializes the org's activations, so that the 256 cap holds.
SELECT pg_advisory_xact_lock(hashtextextended('customer_consequence_rules/' || sqlc.arg(org_id)::uuid::text, 0));
