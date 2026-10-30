-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Ed25519 webhook signatures (G0 M20 S20a, D251, PN-018). The `webhooks`
-- purpose is a per-org signing key: one ACTIVE key per organization (the
-- existing one-active index is on (org_id, purpose)), published in that
-- organization's JWKS with its RETIRING keys (HR-511). A destination opts
-- in per destination: `hmac` (the default) sends only the HMAC `v1,`
-- signatures, `hmac+ed25519` sends `v1a,` next to them (HR-510).
-- +goose Up
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;

ALTER TABLE pc.notification_channels
    ADD COLUMN signature_scheme text NOT NULL DEFAULT 'hmac' CHECK (signature_scheme IN ('hmac', 'hmac+ed25519'));
ALTER TABLE pc.siem_destinations
    ADD COLUMN signature_scheme text NOT NULL DEFAULT 'hmac' CHECK (signature_scheme IN ('hmac', 'hmac+ed25519'));
ALTER TABLE pc.automation_destinations
    ADD COLUMN signature_scheme text NOT NULL DEFAULT 'hmac' CHECK (signature_scheme IN ('hmac', 'hmac+ed25519'));

GRANT UPDATE (signature_scheme) ON pc.notification_channels, pc.siem_destinations, pc.automation_destinations TO pc_app;
GRANT SELECT (signature_scheme) ON pc.notification_channels, pc.siem_destinations, pc.automation_destinations
    TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.automation_destinations DROP COLUMN signature_scheme;
ALTER TABLE pc.siem_destinations DROP COLUMN signature_scheme;
ALTER TABLE pc.notification_channels DROP COLUMN signature_scheme;
-- Webhook keys belong to tenant orgs: the owner deletes them past RLS for
-- this one statement.
ALTER TABLE pc.keys NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.keys WHERE purpose = 'webhooks';
ALTER TABLE pc.keys FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq'));
