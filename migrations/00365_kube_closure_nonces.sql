-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Kubernetes closure nonces (G0 M32 D970): KubernetesService.
-- IssueClosureNonce mints a single-use 32-byte nonce for one instance and
-- namespace, valid 15 minutes; SubmitClosure consumes it once, only for the
-- same instance and namespace, before it expires.

-- +goose Up
CREATE TABLE pc.kube_closure_nonces (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    nonce       bytea       NOT NULL CHECK (octet_length(nonce) = 32),
    cluster     text        NOT NULL CHECK (cluster ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    namespace   text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    instance_id uuid        NOT NULL,
    issued_at   timestamptz NOT NULL DEFAULT now(),
    used_at     timestamptz,
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (org_id, nonce),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    CONSTRAINT kube_closure_nonces_expiry CHECK (expires_at = issued_at + interval '15 minutes'),
    CONSTRAINT kube_closure_nonces_used CHECK (used_at IS NULL OR used_at >= issued_at)
);
CREATE INDEX kube_closure_nonces_expiry_idx ON pc.kube_closure_nonces (org_id, expires_at);

ALTER TABLE pc.kube_closure_nonces ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.kube_closure_nonces FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.kube_closure_nonces
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.kube_closure_nonces
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.kube_closure_nonces TO pc_app;
GRANT UPDATE (used_at) ON pc.kube_closure_nonces TO pc_app;
GRANT SELECT ON pc.kube_closure_nonces TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.kube_closure_nonces TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.kube_closure_nonces;
