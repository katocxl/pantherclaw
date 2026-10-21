-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Billing links (G0 UI D37), in the org's tenant transaction. The org of a
-- ref is found first through the audited cross-org lister.

-- name: LockBillingRef :exec
-- Serializes every writer of one (provider, kind, ref) across orgs, so the
-- cross-org uniqueness check and the insert cannot interleave.
SELECT pg_advisory_xact_lock(hashtextextended('pc.billing_links:' || sqlc.arg(provider)::text || ':' || sqlc.arg(kind)::text || ':' || sqlc.arg(ref)::text, 0));

-- name: LockBillingOrg :exec
-- Serializes the binding of one org's subscriptions.
SELECT pg_advisory_xact_lock(hashtextextended('pc.billing_links.org:' || sqlc.arg(org_id)::uuid::text, 0));

-- name: InsertBillingLink :exec
INSERT INTO pc.billing_links (org_id, id, provider, kind, ref, customer_ref, state, checkout_id, expires_at)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(provider), sqlc.arg(kind), sqlc.arg(ref), sqlc.arg(customer_ref),
        sqlc.arg(state), sqlc.narg(checkout_id), sqlc.narg(expires_at));

-- name: GetBillingLink :one
SELECT *, (expires_at IS NOT NULL AND expires_at > now())::bool AS live
FROM pc.billing_links WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) FOR UPDATE;

-- name: BillingLinkByRef :one
SELECT *, (expires_at IS NOT NULL AND expires_at > now())::bool AS live
FROM pc.billing_links
WHERE org_id = sqlc.arg(org_id) AND provider = sqlc.arg(provider) AND kind = sqlc.arg(kind) AND ref = sqlc.arg(ref)
FOR UPDATE;

-- name: CurrentSubscription :one
SELECT * FROM pc.billing_links
WHERE org_id = sqlc.arg(org_id) AND provider = sqlc.arg(provider) AND kind = 'SUBSCRIPTION' AND state = 'CURRENT';

-- name: SetBillingLinkState :execrows
UPDATE pc.billing_links SET state = sqlc.arg(state)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = sqlc.arg(from_state);

-- name: PendingCheckout :one
SELECT * FROM pc.billing_links
WHERE org_id = sqlc.arg(org_id) AND provider = sqlc.arg(provider) AND kind = 'CHECKOUT' AND state = 'PENDING'
FOR UPDATE;

-- name: SubscriptionByCheckout :one
SELECT * FROM pc.billing_links
WHERE org_id = sqlc.arg(org_id) AND kind = 'SUBSCRIPTION' AND checkout_id = sqlc.arg(checkout_id);
