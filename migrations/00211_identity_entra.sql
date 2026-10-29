-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M17 Azure presets (PN-002.3, D129): trusted-issuer entries may use the
-- Azure managed identity and Entra Agent ID presets. Their tokens name the
-- operator-pinned Entra app (a GUID) as audience instead of
-- pantherclaw:<org>; that exception applies to these two kinds only
-- (HR-469), and every other kind keeps the org's audience (HR-140).
-- Attestations keep their one-hour bound: the server records at most one
-- hour of assurance whatever the token's lifetime (HR-143, HR-469).
-- +goose Up
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_kind_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_kind_check
    CHECK (kind IN ('github_actions', 'kubernetes', 'gitlab_ci', 'spiffe_jwt', 'gcp_workload', 'aws_iam',
                    'azure_mi', 'entra_agent_id')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_kind_check;

ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_audience;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_audience CHECK (
    audience = 'pantherclaw:' || org_id::text
    OR (kind IN ('azure_mi', 'entra_agent_id')
        AND audience ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.trusted_issuers VALIDATE CONSTRAINT trusted_issuers_audience;

-- +goose Down
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_audience;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_audience
    CHECK (audience = 'pantherclaw:' || org_id::text) NOT VALID;
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_kind_check;
ALTER TABLE pc.trusted_issuers ADD CONSTRAINT trusted_issuers_kind_check
    CHECK (kind IN ('github_actions', 'kubernetes', 'gitlab_ci', 'spiffe_jwt', 'gcp_workload', 'aws_iam')) NOT VALID;
