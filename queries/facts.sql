-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Trusted fact providers and facts (M4 part 2, HR-160).

-- name: InsertFactProvider :exec
INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(service_account_id), sqlc.arg(created_by));

-- name: InsertFactDeclaration :exec
INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
VALUES (sqlc.arg(org_id), sqlc.arg(provider_id), sqlc.arg(name), sqlc.arg(value_type), sqlc.arg(subject_type), sqlc.arg(max_lag_s));

-- name: GetFactProviderByAccount :one
SELECT id, name, service_account_id, state FROM pc.fact_providers
WHERE org_id = sqlc.arg(org_id) AND service_account_id = sqlc.arg(service_account_id) AND state = 'ACTIVE'
ORDER BY created_at
LIMIT 1;

-- name: ListFactDeclarations :many
SELECT name, value_type, subject_type, max_lag_s FROM pc.fact_declarations
WHERE org_id = sqlc.arg(org_id) AND provider_id = sqlc.arg(provider_id) AND active
ORDER BY name;

-- name: ListActiveFactCatalog :many
SELECT d.name, d.value_type FROM pc.fact_declarations d
JOIN pc.fact_providers p ON p.org_id = d.org_id AND p.id = d.provider_id
WHERE d.org_id = sqlc.arg(org_id) AND d.active AND p.state = 'ACTIVE'
ORDER BY d.name;

-- name: DisableFactProvider :execresult
UPDATE pc.fact_providers SET state = 'DISABLED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'ACTIVE';

-- name: DeactivateFactDeclarations :exec
UPDATE pc.fact_declarations SET active = false
WHERE org_id = sqlc.arg(org_id) AND provider_id = sqlc.arg(provider_id);

-- name: GetFact :one
SELECT observed_at FROM pc.facts
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name) AND subject_type = sqlc.arg(subject_type)
  AND subject_id = sqlc.arg(subject_id);

-- PutFact records an observation; an older one never replaces a newer one.
-- name: PutFact :execresult
INSERT INTO pc.facts AS f (org_id, id, name, subject_type, subject_id, provider_id, value, observed_at, recorded_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.arg(subject_type), sqlc.arg(subject_id),
        sqlc.arg(provider_id), sqlc.arg(value), sqlc.arg(observed_at), now())
ON CONFLICT (org_id, name, subject_type, subject_id) DO UPDATE
SET provider_id = EXCLUDED.provider_id, value = EXCLUDED.value, observed_at = EXCLUDED.observed_at, recorded_at = now()
WHERE f.observed_at <= EXCLUDED.observed_at;

-- ListSubjectFacts returns the facts of active providers about one subject.
-- name: ListSubjectFacts :many
SELECT f.name, f.value, f.observed_at, f.recorded_at, f.provider_id, d.value_type
FROM pc.facts f
JOIN pc.fact_providers p ON p.org_id = f.org_id AND p.id = f.provider_id AND p.state = 'ACTIVE'
JOIN pc.fact_declarations d ON d.org_id = f.org_id AND d.provider_id = f.provider_id AND d.name = f.name AND d.active
WHERE f.org_id = sqlc.arg(org_id) AND f.subject_type = sqlc.arg(subject_type) AND f.subject_id = sqlc.arg(subject_id)
  AND f.name = ANY(sqlc.arg(names)::text[]);

-- name: ListFactProviders :many
SELECT id, name, service_account_id, state FROM pc.fact_providers
WHERE org_id = sqlc.arg(org_id) AND (sqlc.arg(include_disabled)::boolean OR state = 'ACTIVE')
ORDER BY name, id
LIMIT 500;

-- ListProviderDeclarations returns every declaration of the providers,
-- active or not (a disabled provider's declarations are inactive).
-- name: ListProviderDeclarations :many
SELECT provider_id, name, value_type, subject_type, max_lag_s FROM pc.fact_declarations
WHERE org_id = sqlc.arg(org_id) AND provider_id = ANY(sqlc.arg(provider_ids)::uuid[])
ORDER BY name;

-- ListFactsAbout returns the facts of active providers about one subject;
-- every name when names is empty.
-- name: ListFactsAbout :many
SELECT f.name, f.value, f.observed_at, f.recorded_at, f.provider_id
FROM pc.facts f
JOIN pc.fact_providers p ON p.org_id = f.org_id AND p.id = f.provider_id AND p.state = 'ACTIVE'
JOIN pc.fact_declarations d ON d.org_id = f.org_id AND d.provider_id = f.provider_id AND d.name = f.name AND d.active
WHERE f.org_id = sqlc.arg(org_id) AND f.subject_type = sqlc.arg(subject_type) AND f.subject_id = sqlc.arg(subject_id)
  AND (cardinality(sqlc.arg(names)::text[]) = 0 OR f.name = ANY(sqlc.arg(names)::text[]))
ORDER BY f.name
LIMIT 500;
