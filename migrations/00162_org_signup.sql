-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Self-serve organizations and onboarding (G0 UI D8, D15; HR-351,
-- HR-362..364). An org created by an account records its slug (a shown
-- label, not unique across orgs, so it is no existence oracle) and the
-- account that created it, and the terms of service and DPA versions the
-- person accepted, with when and from where. Acceptances are append only.
--
-- Onboarding progress has no table of its own: it is computed from the
-- org's records (security keys, invitations, gateways, agents,
-- transactions, approvals, suspension events), never from flags a client
-- sets, and simulated records never count.

-- +goose Up
ALTER TABLE pc.orgs
    ADD COLUMN slug text CHECK (slug IS NULL OR slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    ADD COLUMN created_by_account uuid;

CREATE TABLE pc.org_terms_acceptances (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    -- The accepting account (global, so no foreign key, HR-050) and its
    -- user in the org.
    account_id    uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    terms_version text        NOT NULL CHECK (terms_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    dpa_version   text        NOT NULL CHECK (dpa_version ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
    client_ip     text        NOT NULL DEFAULT '' CHECK (char_length(client_ip) <= 64),
    accepted_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);
CREATE INDEX org_terms_acceptances_user ON pc.org_terms_acceptances (org_id, user_id);

ALTER TABLE pc.org_terms_acceptances ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.org_terms_acceptances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.org_terms_acceptances
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.org_terms_acceptances TO pc_app;
GRANT SELECT ON pc.org_terms_acceptances TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.org_terms_acceptances;
ALTER TABLE pc.orgs DROP COLUMN created_by_account, DROP COLUMN slug;
