-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The Kubernetes admission webhook's issuer lookup (G0 M32 D967): an active
-- kubernetes trusted-issuer entry for (org, cluster, namespace, service
-- account). The binding is stored as {"kubernetes": {"cluster",
-- "namespace", "service_account_name", ...}} (identity app Binding), so the
-- index is on those paths. It is built concurrently, outside a transaction,
-- so writes to pc.trusted_issuers go on during the build. A build that
-- failed leaves an invalid index, which the first statement drops before
-- the next try.

-- +goose NO TRANSACTION

-- +goose Up
-- squawk: this migration runs outside a transaction (goose NO TRANSACTION
-- above), which CONCURRENTLY needs; .squawk.toml assumes every migration
-- runs in one.
-- squawk-ignore ban-concurrent-index-creation-in-transaction
DROP INDEX CONCURRENTLY IF EXISTS pc.trusted_issuers_kubernetes_lookup;
-- squawk-ignore ban-concurrent-index-creation-in-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS trusted_issuers_kubernetes_lookup ON pc.trusted_issuers (
    org_id,
    (binding #>> '{kubernetes,cluster}'),
    (binding #>> '{kubernetes,namespace}'),
    (binding #>> '{kubernetes,service_account_name}'))
    WHERE kind = 'kubernetes' AND state = 'ACTIVE';

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS pc.trusted_issuers_kubernetes_lookup;
