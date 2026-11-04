-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Threat map reports (G0 M28 D720, D720a; F968; HR-688). A report is an
-- evidence pack of scope threat_map. Its framework and optional environment
-- are kept on the pack's row for the build job and go into threat_map.json,
-- never as a manifest member. pc_app writes them at insert only (00074
-- grants UPDATE by column, so nothing is added to it). The environment has
-- no foreign key: CreateEvidencePack checks it exists in the org and the
-- caller holds threatmap.read on it. Permissions are Go-only: no seed here
-- (D722).

-- +goose Up
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution', 'compliance', 'threat_map')) NOT VALID,
    ADD COLUMN threat_framework   text CHECK (threat_framework IN ('atlas', 'attack-enterprise')),
    ADD COLUMN threat_environment uuid,
    ADD CONSTRAINT evidence_packs_threat_framework CHECK ((scope_kind = 'threat_map') = (threat_framework IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT evidence_packs_threat_environment CHECK (threat_environment IS NULL OR scope_kind = 'threat_map') NOT VALID;
-- squawk: both columns are new and NULL on every existing row, and no
-- existing row has scope threat_map, so each validation reads
-- pc.evidence_packs once without finding a row to fail; goose runs each
-- migration in one transaction (.squawk.toml).
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_threat_framework;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_threat_environment;

GRANT SELECT (threat_framework, threat_environment) ON pc.evidence_packs TO pc_audit_ro;

-- +goose Down
DELETE FROM pc.evidence_packs WHERE scope_kind = 'threat_map';
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_threat_environment,
    DROP CONSTRAINT evidence_packs_threat_framework,
    DROP COLUMN threat_environment,
    DROP COLUMN threat_framework,
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution', 'compliance')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;
