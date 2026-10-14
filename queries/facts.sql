-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Trusted fact providers and facts (M4 part 2, HR-160).

-- name: InsertFactProvider :exec
INSERT INTO pc.fact_providers (org_id, id, name, service_account_id, gateway_id, connection_id, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(name), sqlc.narg(service_account_id), sqlc.narg(gateway_id), sqlc.narg(connection_id),
        sqlc.arg(created_by));

-- name: InsertFactDeclaration :exec
INSERT INTO pc.fact_declarations (org_id, provider_id, name, value_type, subject_type, max_lag_s)
VALUES (sqlc.arg(org_id), sqlc.arg(provider_id), sqlc.arg(name), sqlc.arg(value_type), sqlc.arg(subject_type), sqlc.arg(max_lag_s));

-- name: GetFactProviderByAccount :one
SELECT id, name, service_account_id, state FROM pc.fact_providers
WHERE org_id = sqlc.arg(org_id) AND service_account_id = sqlc.arg(service_account_id)::uuid AND state = 'ACTIVE'
ORDER BY created_at
LIMIT 1;

-- GetFactProviderByConnection returns the active provider a gateway reports
-- a connection's facts as (G0 M8 decision 5), while the connection is
-- active and still served by the provider's gateway: a gateway the
-- connection moved away from reports nothing more.
-- name: GetFactProviderByConnection :one
SELECT p.id, p.name, p.gateway_id, p.connection_id, p.state FROM pc.fact_providers p
JOIN pc.connections c ON c.org_id = p.org_id AND c.id = p.connection_id
WHERE p.org_id = sqlc.arg(org_id) AND p.connection_id = sqlc.arg(connection_id)::uuid AND p.state = 'ACTIVE'
  AND c.gateway_id = p.gateway_id AND c.state = 'ACTIVE';

-- name: ListFactDeclarations :many
SELECT name, value_type, subject_type, max_lag_s FROM pc.fact_declarations
WHERE org_id = sqlc.arg(org_id) AND provider_id = sqlc.arg(provider_id) AND active
ORDER BY name;

-- name: ListActiveFactCatalog :many
SELECT d.name, d.value_type FROM pc.fact_declarations d
JOIN pc.fact_providers p ON p.org_id = d.org_id AND p.id = d.provider_id
WHERE d.org_id = sqlc.arg(org_id) AND d.active AND p.state = 'ACTIVE'
ORDER BY d.name;

-- ListActiveFactSubjects returns the subject type each active fact is
-- declared about (one active provider per fact name).
-- name: ListActiveFactSubjects :many
SELECT d.name, d.subject_type FROM pc.fact_declarations d
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
-- A gateway provider's facts count only while its gateway still serves
-- its connection and the connection is active (#299 review follow-up).
-- name: ListSubjectFacts :many
SELECT f.name, f.value, f.observed_at, f.recorded_at, f.provider_id, d.value_type
FROM pc.facts f
JOIN pc.fact_providers p ON p.org_id = f.org_id AND p.id = f.provider_id AND p.state = 'ACTIVE'
JOIN pc.fact_declarations d ON d.org_id = f.org_id AND d.provider_id = f.provider_id AND d.name = f.name AND d.active
LEFT JOIN pc.connections c ON c.org_id = p.org_id AND c.id = p.connection_id
WHERE f.org_id = sqlc.arg(org_id) AND f.subject_type = sqlc.arg(subject_type) AND f.subject_id = sqlc.arg(subject_id)
  AND f.name = ANY(sqlc.arg(names)::text[])
  AND (p.gateway_id IS NULL OR (c.gateway_id = p.gateway_id AND c.state = 'ACTIVE'));

-- LockServedConnection locks, for the fact write's transaction, the
-- connection a gateway provider reports for, while its gateway still
-- serves it and it is active; no row otherwise (#299 review follow-up).
-- name: LockServedConnection :one
SELECT c.id
FROM pc.fact_providers p
JOIN pc.connections c ON c.org_id = p.org_id AND c.id = p.connection_id AND c.gateway_id = p.gateway_id AND c.state = 'ACTIVE'
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(provider_id) AND p.state = 'ACTIVE'
FOR SHARE OF c;

-- IsGatewayProvider reports whether a provider is a gateway's.
-- name: IsGatewayProvider :one
SELECT (gateway_id IS NOT NULL)::boolean AS gateway FROM pc.fact_providers WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- DisableMovedGatewayProviders disables the active providers of a
-- connection that are bound to a gateway other than the one now serving
-- it, and their declarations (#299 review follow-up).
-- name: DisableMovedGatewayProviders :many
UPDATE pc.fact_providers SET state = 'DISABLED'
WHERE org_id = sqlc.arg(org_id) AND connection_id = sqlc.arg(connection_id) AND gateway_id IS NOT NULL
  AND gateway_id <> sqlc.arg(gateway_id) AND state = 'ACTIVE'
RETURNING id, gateway_id;

-- name: ListFactProviders :many
SELECT id, name, service_account_id, gateway_id, connection_id, state FROM pc.fact_providers
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

-- name: CurrentFactValue :one
-- The current value of a fact about a subject, locked for the write that
-- replaces it, so a change is seen once (G0 M8, HR-205).
SELECT value FROM pc.facts
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name) AND subject_type = sqlc.arg(subject_type) AND subject_id = sqlc.arg(subject_id)
FOR UPDATE;
