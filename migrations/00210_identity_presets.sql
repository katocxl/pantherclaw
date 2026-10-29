-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M17 identity presets (PN-002.3, D121): trusted-issuer entries may use the
-- GitLab CI, SPIFFE JWT-SVID, GCP workload and AWS IAM presets. Only preset
-- kinds can be configured (HR-140); the rules of each preset live in code.
-- +goose Up
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_kind_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_kind_check
    CHECK (kind IN ('github_actions', 'kubernetes', 'gitlab_ci', 'spiffe_jwt', 'gcp_workload', 'aws_iam')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_kind_check;
-- The SPIFFE preset accepts the eight JWT-SVID algorithms PantherClaw
-- verifies (RS, PS and ES families).
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_algorithms_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_algorithms_check
    CHECK (cardinality(algorithms) BETWEEN 1 AND 8) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_algorithms_check;

-- +goose Down
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_kind_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_kind_check
    CHECK (kind IN ('github_actions', 'kubernetes')) NOT VALID;
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_algorithms_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_algorithms_check
    CHECK (cardinality(algorithms) BETWEEN 1 AND 4) NOT VALID;
