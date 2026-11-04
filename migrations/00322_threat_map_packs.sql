-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Threat map reports (G0 M28 D720; F968; HR-688). A report is an evidence
-- pack of scope threat_map. The framework and the environment live inside
-- threat_map.json, never as a manifest member. Permissions are Go-only: no
-- seed here (D722).

-- +goose Up
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution', 'compliance', 'threat_map')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;

-- +goose Down
DELETE FROM pc.evidence_packs WHERE scope_kind = 'threat_map';
ALTER TABLE pc.evidence_packs
    DROP CONSTRAINT evidence_packs_scope_kind_check,
    ADD CONSTRAINT evidence_packs_scope_kind_check
        CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range', 'range', 'automation_execution', 'compliance')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.evidence_packs VALIDATE CONSTRAINT evidence_packs_scope_kind_check;
