-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Web Push subscriptions (G0 M36 D1066; HR-793). A signed-in person
-- registers a browser's push subscription: its endpoint (https, on a push
-- service host the server allows) and its p256dh and auth keys, sealed per
-- row (HR-062). A push carries a title and a link only, never what an
-- action would do. A 404 or 410 from the push service marks the
-- subscription REMOVED.
--
-- Signing keys gain the purpose web_push: the deployment's VAPID key
-- (ECDSA P-256, RFC 8292). Deliveries gain the kind web_push, one per
-- person.

-- +goose Up
CREATE TABLE pc.push_subscriptions (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    endpoint        text        NOT NULL CHECK (char_length(endpoint) BETWEEN 9 AND 2048 AND endpoint LIKE 'https://%'),
    p256dh          bytea       NOT NULL CHECK (octet_length(p256dh) BETWEEN 1 AND 1024),
    auth            bytea       NOT NULL CHECK (octet_length(auth) BETWEEN 1 AND 1024),
    label           text        NOT NULL DEFAULT '' CHECK (char_length(label) <= 64),
    state           text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REMOVED')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_success_at timestamptz,
    failure_count   integer     NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    removed_at      timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CONSTRAINT push_subscriptions_removed CHECK ((state = 'REMOVED') = (removed_at IS NOT NULL))
);
CREATE UNIQUE INDEX push_subscriptions_live ON pc.push_subscriptions (org_id, user_id, endpoint) WHERE state = 'ACTIVE';

ALTER TABLE pc.push_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.push_subscriptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.push_subscriptions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.push_subscriptions
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
GRANT SELECT, INSERT ON pc.push_subscriptions TO pc_app;
-- The keys never change; only health and removal do.
GRANT UPDATE (state, removed_at, last_success_at, failure_count) ON pc.push_subscriptions TO pc_app;
GRANT SELECT ON pc.push_subscriptions TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.push_subscriptions TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- squawk: each CHECK only widens a value list; goose runs each migration in
-- one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.deliveries
    DROP CONSTRAINT deliveries_kind_check,
    ADD CONSTRAINT deliveries_kind_check
        CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app', 'slack_dm', 'teams_app', 'web_push')) NOT VALID,
    DROP CONSTRAINT deliveries_check1,
    ADD CONSTRAINT deliveries_check1 CHECK ((kind IN ('email', 'slack_dm', 'web_push')) = (recipient_user_id IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.deliveries VALIDATE CONSTRAINT deliveries_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.deliveries VALIDATE CONSTRAINT deliveries_check1;

ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card',
                       'mcp_tokens', 'global_log', 'receipts_pq', 'web_push')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys DROP CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_algorithm_check
    CHECK (algorithm IN ('EdDSA', 'ES256', 'ML-DSA-65') AND algorithm = CASE purpose
        WHEN 'anchors' THEN 'ES256' WHEN 'checkpoints_pq' THEN 'ML-DSA-65' WHEN 'receipts_pq' THEN 'ML-DSA-65'
        WHEN 'web_push' THEN 'ES256' ELSE 'EdDSA' END) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_algorithm_check;

-- +goose Down
DELETE FROM pc.keys WHERE purpose = 'web_push';
ALTER TABLE pc.keys DROP CONSTRAINT keys_algorithm_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_algorithm_check
    CHECK (algorithm IN ('EdDSA', 'ES256', 'ML-DSA-65') AND algorithm = CASE purpose
        WHEN 'anchors' THEN 'ES256' WHEN 'checkpoints_pq' THEN 'ML-DSA-65' WHEN 'receipts_pq' THEN 'ML-DSA-65'
        ELSE 'EdDSA' END);
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card',
                       'mcp_tokens', 'global_log', 'receipts_pq'));
DELETE FROM pc.deliveries WHERE kind = 'web_push';
ALTER TABLE pc.deliveries
    DROP CONSTRAINT deliveries_check1,
    ADD CONSTRAINT deliveries_check1 CHECK ((kind IN ('email', 'slack_dm')) = (recipient_user_id IS NOT NULL)),
    DROP CONSTRAINT deliveries_kind_check,
    ADD CONSTRAINT deliveries_kind_check
        CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app', 'slack_dm', 'teams_app'));
DROP TABLE pc.push_subscriptions;
