-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The release of an unknown outcome (G0 M7 slice A11, design decision 3,
-- HR-192). Only a person releases one, on /reconciliations/{id}, with a
-- WebAuthn assertion whose challenge is the release binding
-- SHA-256(JCS({v, reconciliation, transaction, resolution, basis_sha256,
-- evidence, expires_at})), made through M5 part 2's BINDING ceremony. A
-- BINDING ceremony therefore names exactly one of an approval request, a
-- batch and a reconciliation, and a person has at most one unconsumed
-- ceremony per reconciliation, as per request and per batch (G0 M5 part 2
-- design decision 12). The release use case consumes the ceremony in the
-- transaction that records the release, and spends it when it refuses.
-- pc_app's table-level SELECT and INSERT on webauthn_ceremonies (00030)
-- cover the new column; like the request and the batch, it never changes
-- (pc_app may update consumed_at only).

-- +goose Up
ALTER TABLE pc.webauthn_ceremonies
    ADD COLUMN reconciliation_id uuid,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id) <= 1) NOT VALID,
    ADD CONSTRAINT webauthn_ceremonies_reconciliation_fk FOREIGN KEY (org_id, reconciliation_id)
        REFERENCES pc.reconciliation_tasks (org_id, id);
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
CREATE UNIQUE INDEX webauthn_ceremonies_binding_reconciliation
    ON pc.webauthn_ceremonies (org_id, reconciliation_id, user_id)
    WHERE reconciliation_id IS NOT NULL AND consumed_at IS NULL;

-- +goose Down
DELETE FROM pc.webauthn_ceremonies WHERE reconciliation_id IS NOT NULL;
DROP INDEX pc.webauthn_ceremonies_binding_reconciliation;
ALTER TABLE pc.webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_reconciliation_fk,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    DROP COLUMN reconciliation_id,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id) <= 1) NOT VALID;
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
