-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- What a permit's effect is verified against (G0 M7 design decisions 2
-- and 3, HR-191). A transaction keeps only its action's hash, so the
-- finalization that issues a permit records the digest of the definition
-- the decision used and, for a verifier that compares fields, the values
-- each observed field must have, computed from the effective action the
-- permit binds. Both are fixed when the permit is issued; a verification
-- task is built from them, never from what a target or an agent says.

-- +goose Up
ALTER TABLE pc.permits
    ADD COLUMN definition_digest text  CHECK (definition_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN verify_expect     jsonb CHECK (jsonb_typeof(verify_expect) = 'object' AND octet_length(verify_expect::text) <= 4096),
    ADD CONSTRAINT permits_verify_expect CHECK (verify_expect IS NULL OR definition_digest IS NOT NULL);

-- +goose Down
ALTER TABLE pc.permits DROP CONSTRAINT permits_verify_expect, DROP COLUMN verify_expect, DROP COLUMN definition_digest;
