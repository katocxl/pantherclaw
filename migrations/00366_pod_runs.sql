-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Runs of Kubernetes pods (G0 M32 D973a). KubernetesService.StartPodRun
-- starts a top-level run for the pod's instance under the run grant of the
-- trusted-issuer revision the instance was attested by: its launcher is
-- the instance, its principal source trusted_issuer, and launcher_issuer_id
-- names that revision. launcher_issuer_id is set exactly for that source.
-- A top-level run may have a launcher instance only for id_jag and
-- trusted_issuer. runs_one_launcher and runs_one_principal are unchanged.

-- +goose Up
ALTER TABLE pc.runs ADD COLUMN launcher_issuer_id uuid;
-- The new column is NULL in every row, so the foreign key holds at once.
-- squawk-ignore adding-foreign-key-constraint
ALTER TABLE pc.runs
    ADD CONSTRAINT runs_launcher_issuer_fkey FOREIGN KEY (org_id, launcher_issuer_id)
        REFERENCES pc.trusted_issuers (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_launcher_issuer_fkey;
ALTER TABLE pc.runs
    DROP CONSTRAINT runs_principal_source_check,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation', 'id_jag', 'trusted_issuer')) NOT VALID,
    DROP CONSTRAINT runs_child,
    ADD CONSTRAINT runs_child CHECK (
        (parent_run_id IS NULL AND depth = 0 AND principal_source <> 'parent_run'
            AND (launcher_instance_id IS NULL) = (principal_source NOT IN ('id_jag', 'trusted_issuer')))
        OR (parent_run_id IS NOT NULL AND depth > 0 AND principal_source = 'parent_run'
            AND launcher_instance_id IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT runs_launcher_issuer
        CHECK ((launcher_issuer_id IS NOT NULL) = (principal_source = 'trusted_issuer')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_principal_source_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_child;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_launcher_issuer;

-- +goose Down
ALTER TABLE pc.runs
    DROP CONSTRAINT runs_launcher_issuer,
    DROP CONSTRAINT runs_child,
    ADD CONSTRAINT runs_child CHECK (
        (parent_run_id IS NULL AND depth = 0 AND principal_source <> 'parent_run'
            AND (launcher_instance_id IS NULL) = (principal_source <> 'id_jag'))
        OR (parent_run_id IS NOT NULL AND depth > 0 AND principal_source = 'parent_run'
            AND launcher_instance_id IS NOT NULL)),
    DROP CONSTRAINT runs_principal_source_check,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation', 'id_jag')),
    DROP CONSTRAINT runs_launcher_issuer_fkey,
    DROP COLUMN launcher_issuer_id;
