-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Publisher pins, bundle installs and revocations (G0 M37 D1081–D1083;
-- HR-795..800). Every state change is a conditional update.

-- name: InsertPublisherPin :exec
INSERT INTO pc.publisher_pins (org_id, id, publisher, kid, public_key, fingerprint, allowed_kinds, revocations_url, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(publisher), sqlc.arg(kid), sqlc.arg(public_key), sqlc.arg(fingerprint),
        sqlc.arg(allowed_kinds), sqlc.narg(revocations_url), sqlc.arg(created_by));

-- name: GetPublisherPin :one
SELECT id, publisher, kid, public_key, fingerprint, allowed_kinds, revocations_url, state, revoke_reason, created_by,
       created_at, activated_by, activated_at, revoked_at
FROM pc.publisher_pins
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListPublisherPins :many
SELECT id, publisher, kid, public_key, fingerprint, allowed_kinds, revocations_url, state, revoke_reason, created_by,
       created_at, activated_by, activated_at, revoked_at
FROM pc.publisher_pins
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivatePublisherPin :execrows
-- A person with a fresh step-up activates a PENDING pin (HR-795); the
-- guard sets activated_at by the database clock.
UPDATE pc.publisher_pins
SET state = 'ACTIVE', activated_by = sqlc.arg(activated_by), activated_credential = sqlc.arg(activated_credential)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: RevokePublisherPin :execrows
UPDATE pc.publisher_pins SET state = 'REVOKED', revoke_reason = sqlc.arg(reason)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'REVOKED';

-- name: ActivePublisherPins :many
-- The keys an install may verify against (D1082): ACTIVE pins only.
SELECT id, kid, public_key, allowed_kinds FROM pc.publisher_pins
WHERE org_id = sqlc.arg(org_id) AND publisher = sqlc.arg(publisher) AND state = 'ACTIVE'
ORDER BY id;

-- name: PublisherKeysEver :many
-- Every key the org has ever pinned for a publisher, in any state: the
-- keys a revocation statement may be signed by (HR-800).
SELECT id, kid, public_key, state FROM pc.publisher_pins
WHERE org_id = sqlc.arg(org_id) AND publisher = sqlc.arg(publisher)
ORDER BY id;

-- name: LivePinsOfKid :many
SELECT id FROM pc.publisher_pins
WHERE org_id = sqlc.arg(org_id) AND kid = sqlc.arg(kid) AND state <> 'REVOKED'
ORDER BY id
FOR UPDATE;

-- name: KidWithdrawn :one
-- A key revoked as compromised, or by its publisher, is never pinned again.
SELECT (EXISTS (SELECT 1 FROM pc.publisher_pins p
                WHERE p.org_id = sqlc.arg(org_id) AND p.kid = sqlc.arg(kid)
                  AND p.revoke_reason IN ('COMPROMISED', 'PUBLISHER_REVOKED'))
     OR EXISTS (SELECT 1 FROM pc.bundle_revocations r
                WHERE r.org_id = sqlc.arg(org_id) AND r.scope = 'KEY' AND r.kid = sqlc.arg(kid)))::bool AS withdrawn;

-- name: RevocationURLPins :many
-- The ACTIVE pins whose publisher publishes revocation statements.
SELECT id, publisher, revocations_url::text AS revocations_url FROM pc.publisher_pins
WHERE org_id = sqlc.arg(org_id) AND state = 'ACTIVE' AND revocations_url IS NOT NULL
ORDER BY id
LIMIT 100;

-- name: InsertBundleInstall :exec
INSERT INTO pc.bundle_installs (org_id, id, publisher, name, version, bundle_sha256, installed_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(publisher), sqlc.arg(name), sqlc.arg(version), sqlc.arg(bundle_sha256),
        sqlc.arg(installed_by));

-- name: InsertFailedBundleInstall :exec
INSERT INTO pc.bundle_installs (org_id, id, publisher, name, version, bundle_sha256, installed_by, state, finished_at,
                                failure_code)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(publisher), sqlc.arg(name), sqlc.arg(version), sqlc.arg(bundle_sha256),
        sqlc.arg(installed_by), 'FAILED', now(), sqlc.arg(failure_code));

-- name: FinishBundleInstall :execrows
UPDATE pc.bundle_installs SET state = 'INSTALLED', pin_id = sqlc.arg(pin_id)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'PENDING';

-- name: GetBundleInstall :one
SELECT id, publisher, name, version, bundle_sha256, pin_id, state, installed_by, created_at, finished_at, failure_code
FROM pc.bundle_installs
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: ListBundleInstalls :many
SELECT id, publisher, name, version, bundle_sha256, pin_id, state, installed_by, created_at, finished_at, failure_code
FROM pc.bundle_installs
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: InsertBundleItem :exec
INSERT INTO pc.bundle_items (org_id, install_id, kind, name, sha256, target_type, target_id, state)
VALUES (sqlc.arg(org_id), sqlc.arg(install_id), sqlc.arg(kind), sqlc.arg(name), sqlc.arg(sha256), sqlc.arg(target_type),
        sqlc.arg(target_id), sqlc.arg(state));

-- name: ListBundleItems :many
SELECT kind, name, sha256, target_type, target_id, state FROM pc.bundle_items
WHERE org_id = sqlc.arg(org_id) AND install_id = sqlc.arg(install_id)
ORDER BY name;

-- name: LockBundleState :one
-- Serializes installs of one bundle (ROLLBACK, EQUIVOCATION).
SELECT max_version, max_sha256 FROM pc.bundle_state
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name)
FOR UPDATE;

-- name: UpsertBundleState :exec
INSERT INTO pc.bundle_state (org_id, publisher, name, max_version, max_sha256)
VALUES (sqlc.arg(org_id), sqlc.arg(publisher), sqlc.arg(name), sqlc.arg(max_version), sqlc.arg(max_sha256))
ON CONFLICT (org_id, name) DO UPDATE SET max_version = EXCLUDED.max_version, max_sha256 = EXCLUDED.max_sha256, updated_at = now();

-- name: BundleRevokedVersions :many
-- The max_versions of the BUNDLE revocations of a bundle: install refuses
-- any version at or below one of them.
SELECT max_version::text AS max_version FROM pc.bundle_revocations
WHERE org_id = sqlc.arg(org_id) AND scope = 'BUNDLE' AND name = sqlc.arg(name);

-- name: InstalledOfName :many
SELECT id, version FROM pc.bundle_installs
WHERE org_id = sqlc.arg(org_id) AND name = sqlc.arg(name) AND state = 'INSTALLED'
ORDER BY id
FOR UPDATE;

-- name: InstalledOfKid :many
SELECT i.id FROM pc.bundle_installs i
JOIN pc.publisher_pins p ON p.org_id = i.org_id AND p.id = i.pin_id
WHERE i.org_id = sqlc.arg(org_id) AND p.kid = sqlc.arg(kid) AND i.state = 'INSTALLED'
ORDER BY i.id
FOR UPDATE OF i;

-- name: RevokeBundleInstall :execrows
UPDATE pc.bundle_installs SET state = 'REVOKED'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'INSTALLED';

-- name: RevokeBundleItems :many
UPDATE pc.bundle_items SET state = 'REVOKED'
WHERE org_id = sqlc.arg(org_id) AND install_id = sqlc.arg(install_id) AND state <> 'REVOKED'
RETURNING kind, name, target_type, target_id;

-- name: InsertBundleRevocation :execrows
INSERT INTO pc.bundle_revocations (org_id, id, publisher, statement_sha256, scope, kid, name, max_version, signed_at, source)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(publisher), sqlc.narg(statement_sha256), sqlc.arg(scope), sqlc.narg(kid),
        sqlc.narg(name), sqlc.narg(max_version), sqlc.narg(signed_at), sqlc.arg(source))
ON CONFLICT (org_id, statement_sha256) WHERE statement_sha256 IS NOT NULL DO NOTHING;

-- name: BundlePackageVersions :many
-- The org's versions of a drafted package a revocation withdraws, as the
-- org-key COMPROMISED quarantine does (D1083).
SELECT t.name AS package, v.version, v.state
FROM pc.package_versions v
JOIN pc.tool_packages t ON t.org_id = v.org_id AND t.id = v.package_id
WHERE v.org_id = sqlc.arg(org_id) AND t.name = sqlc.arg(name) AND v.version = sqlc.arg(version)
  AND v.state NOT IN ('QUARANTINED', 'RETIRED');

-- name: BundleNoticeRecipients :many
-- The org's active Org Admins and Security Admins (D1083).
SELECT DISTINCT u.id FROM pc.users u
JOIN pc.role_bindings r ON r.org_id = u.org_id AND r.user_id = u.id
WHERE u.org_id = sqlc.arg(org_id) AND u.state = 'ACTIVE' AND r.role IN ('org_admin', 'security_admin') AND r.scope_type = 'ORG'
ORDER BY u.id LIMIT 50;
