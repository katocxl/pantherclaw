-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- When this server last decided on a pod of a protected namespace (G0 M32
-- D967a). The admission webhook upserts the row on every decision that is
-- not a dry run, at most once a minute per (org, cluster, namespace,
-- outcome); the Kubernetes closure's admission_enforced check (D970) reads
-- it: an allow or a deny within 24 hours shows the webhook is in the path.
-- Allows are otherwise not audited.

-- +goose Up
CREATE TABLE pc.kube_admission_seen (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    cluster         text        NOT NULL CHECK (cluster ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    namespace       text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    last_allowed_at timestamptz,
    last_denied_at  timestamptz,
    PRIMARY KEY (org_id, cluster, namespace),
    CONSTRAINT kube_admission_seen_some CHECK (num_nonnulls(last_allowed_at, last_denied_at) >= 1)
);

ALTER TABLE pc.kube_admission_seen ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.kube_admission_seen FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.kube_admission_seen
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.kube_admission_seen
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.kube_admission_seen TO pc_app;
GRANT UPDATE (last_allowed_at, last_denied_at) ON pc.kube_admission_seen TO pc_app;
GRANT SELECT ON pc.kube_admission_seen TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.kube_admission_seen TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.kube_admission_seen;
