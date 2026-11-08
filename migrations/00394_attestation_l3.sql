-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M35 L3 "Infrastructure-attested" (PAP-1 §3.3, G0 M35 D1030, HR-777..779):
-- - an instance may hold attestation level 3, set at enrollment through an
--   L3 preset and in force only while attested_until is in the future;
-- - trusted-issuer entries may use the L3 presets spiffe_x509 and
--   gcp_instance;
-- - the spiffe_x509 preset accepts nine X.509-SVID algorithms (ES, RS and
--   PS families and EdDSA), so an entry may list up to nine.
-- The unnamed att_level CHECK of 00018 has the default name
-- agent_instances_att_level_check.

-- +goose Up
-- squawk: each CHECK only widens a value list; goose runs each migration in
-- one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.agent_instances DROP CONSTRAINT agent_instances_att_level_check;
ALTER TABLE pc.agent_instances ADD CONSTRAINT agent_instances_att_level_check
    CHECK (att_level IN (1, 2, 3)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agent_instances VALIDATE CONSTRAINT agent_instances_att_level_check;

ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_kind_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_kind_check
    CHECK (kind IN ('github_actions', 'kubernetes', 'gitlab_ci', 'spiffe_jwt', 'gcp_workload', 'aws_iam',
                    'azure_mi', 'entra_agent_id', 'spiffe_x509', 'gcp_instance')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_kind_check;

ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_algorithms_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_algorithms_check
    CHECK (cardinality(algorithms) BETWEEN 1 AND 9) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_algorithms_check;

-- +goose Down
-- The narrower CHECKs refuse L3 instances and entries: validating them fails
-- while one exists (whatever the row security), and the Down stops; it
-- never deletes instance or issuer rows.
-- +goose StatementBegin
DO $$
BEGIN
    ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_algorithms_check;
    ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_algorithms_check
        CHECK (cardinality(algorithms) BETWEEN 1 AND 8) NOT VALID;
    ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_algorithms_check;
    ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_kind_check;
    ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_kind_check
        CHECK (kind IN ('github_actions', 'kubernetes', 'gitlab_ci', 'spiffe_jwt', 'gcp_workload', 'aws_iam',
                        'azure_mi', 'entra_agent_id')) NOT VALID;
    ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_kind_check;
    ALTER TABLE pc.agent_instances DROP CONSTRAINT agent_instances_att_level_check;
    ALTER TABLE pc.agent_instances ADD CONSTRAINT agent_instances_att_level_check
        CHECK (att_level IN (1, 2)) NOT VALID;
    ALTER TABLE pc.agent_instances VALIDATE CONSTRAINT agent_instances_att_level_check;
EXCEPTION WHEN check_violation THEN
    RAISE EXCEPTION 'remove the M35 L3 instances and issuer entries first';
END
$$;
-- +goose StatementEnd
