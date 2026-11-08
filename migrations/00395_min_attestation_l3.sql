-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M35 L3 (G0 M35 D1030): envelopes and grants may require attestation
-- level 3. The unnamed min_attestation CHECKs of 00022 have the default
-- names envelope_revisions_min_attestation_check and
-- grant_revisions_min_attestation_check.

-- +goose Up
-- squawk: each CHECK only widens a range; goose runs each migration in one
-- transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.envelope_revisions DROP CONSTRAINT envelope_revisions_min_attestation_check;
ALTER TABLE pc.envelope_revisions ADD CONSTRAINT envelope_revisions_min_attestation_check
    CHECK (min_attestation BETWEEN 0 AND 3) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.envelope_revisions VALIDATE CONSTRAINT envelope_revisions_min_attestation_check;

ALTER TABLE pc.grant_revisions DROP CONSTRAINT grant_revisions_min_attestation_check;
ALTER TABLE pc.grant_revisions ADD CONSTRAINT grant_revisions_min_attestation_check
    CHECK (min_attestation BETWEEN 0 AND 3) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grant_revisions VALIDATE CONSTRAINT grant_revisions_min_attestation_check;

-- +goose Down
-- The narrower CHECKs refuse revisions that require L3: validating them
-- fails while one exists, and the Down stops; it never changes revisions.
-- +goose StatementBegin
DO $$
BEGIN
    ALTER TABLE pc.grant_revisions DROP CONSTRAINT grant_revisions_min_attestation_check;
    ALTER TABLE pc.grant_revisions ADD CONSTRAINT grant_revisions_min_attestation_check
        CHECK (min_attestation BETWEEN 0 AND 2) NOT VALID;
    ALTER TABLE pc.grant_revisions VALIDATE CONSTRAINT grant_revisions_min_attestation_check;
    ALTER TABLE pc.envelope_revisions DROP CONSTRAINT envelope_revisions_min_attestation_check;
    ALTER TABLE pc.envelope_revisions ADD CONSTRAINT envelope_revisions_min_attestation_check
        CHECK (min_attestation BETWEEN 0 AND 2) NOT VALID;
    ALTER TABLE pc.envelope_revisions VALIDATE CONSTRAINT envelope_revisions_min_attestation_check;
EXCEPTION WHEN check_violation THEN
    RAISE EXCEPTION 'remove the revisions that require L3 first';
END
$$;
-- +goose StatementEnd
