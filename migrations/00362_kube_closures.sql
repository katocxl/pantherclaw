-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Kubernetes closures (G0 M32 D970). A probe run in a protected namespace
-- (kind sandbox) or in the release namespace's control twin (kind control)
-- reports through its pod's edge, which signs the report with the pod's
-- attested workload key (D971); the server verifies it and records one row
-- here, evidence for 24 hours. The coverage closure of each mapped
-- connection then names it in coverage_closures.kube_closure_id instead of
-- a sandbox session: exactly one of the two is set, and its runtime is
-- kubernetes. Both tables are evidence (HR-055): append-only.

-- +goose Up
CREATE TABLE pc.kube_closures (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    cluster       text        NOT NULL CHECK (cluster ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    namespace     text        NOT NULL CHECK (namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    -- The instance whose key signed the report.
    instance_id   uuid        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('sandbox', 'control')),
    report_digest text        NOT NULL CHECK (report_digest ~ '^sha256:[0-9a-f]{64}$'),
    result        text        NOT NULL CHECK (result IN ('PASSED', 'FAILED')),
    evaluated_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    -- A signed report is recorded once.
    UNIQUE (org_id, report_digest),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    CONSTRAINT kube_closures_expiry CHECK (expires_at = evaluated_at + interval '24 hours')
);
CREATE INDEX kube_closures_scope ON pc.kube_closures (org_id, cluster, namespace, kind, evaluated_at DESC);

ALTER TABLE pc.kube_closures ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.kube_closures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.kube_closures
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.kube_closures
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.kube_closures TO pc_app;
GRANT SELECT ON pc.kube_closures TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.kube_closures TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- A coverage closure rests on a sandbox session or a Kubernetes closure.
-- The new column is NULL in every row and kube_closures is empty, so the
-- foreign key and the checks hold at once; every existing row has a
-- sandbox session and a runc or runsc runtime.
ALTER TABLE pc.coverage_closures
    -- squawk-ignore ban-drop-not-null
    ALTER COLUMN sandbox_session_id DROP NOT NULL,
    ADD COLUMN kube_closure_id uuid,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT coverage_closures_one_source CHECK (num_nonnulls(sandbox_session_id, kube_closure_id) = 1),
    DROP CONSTRAINT coverage_closures_runtime_check,
    -- squawk-ignore constraint-missing-not-valid
    ADD CONSTRAINT coverage_closures_runtime_check CHECK (runtime IN ('runc', 'runsc', 'kubernetes'));
-- squawk-ignore adding-foreign-key-constraint
ALTER TABLE pc.coverage_closures
    ADD CONSTRAINT coverage_closures_kube_closure_fk FOREIGN KEY (org_id, kube_closure_id)
        REFERENCES pc.kube_closures (org_id, id);

-- +goose Down
ALTER TABLE pc.coverage_closures
    DROP CONSTRAINT coverage_closures_runtime_check,
    ADD CONSTRAINT coverage_closures_runtime_check CHECK (runtime IN ('runc', 'runsc')),
    DROP CONSTRAINT coverage_closures_one_source,
    DROP CONSTRAINT coverage_closures_kube_closure_fk,
    DROP COLUMN kube_closure_id,
    ALTER COLUMN sandbox_session_id SET NOT NULL;
DROP TABLE pc.kube_closures;
