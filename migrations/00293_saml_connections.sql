-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- An org's SAML identity providers (G0 M26 D405; F921). A connection is an
-- organization identity provider: it goes ACTIVE, changes and is disabled
-- only through a two-person protected change (HR-481), and the core keeps
-- what the protocol code may trust: the entity id, where sign-in goes, and
-- the certificates that may sign an assertion. Nothing here is fetched: the
-- server reads no metadata URL.
--
-- The entity id never changes. A user is one (issuer, subject), so moving
-- it would hand existing identities to another provider. The issuer is
-- prefixed, so a SAML entity id can never equal an OpenID issuer.
-- +goose Up
CREATE TABLE pc.saml_connections (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    name          text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,25}[a-z0-9])?$'),
    idp_entity_id text        NOT NULL CHECK (char_length(idp_entity_id) BETWEEN 1 AND 500),
    issuer        text        GENERATED ALWAYS AS ('saml:' || idp_entity_id) STORED,
    sso_url       text        NOT NULL CHECK (char_length(sso_url) BETWEEN 9 AND 2048 AND sso_url LIKE 'https://%'),
    -- Base64 DER X.509 certificates, two while the provider rotates.
    certificates  text[]      NOT NULL CHECK (cardinality(certificates) BETWEEN 1 AND 4
                                              AND array_position(certificates, NULL) IS NULL),
    state         text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED', 'LAPSED')),
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    activated_at  timestamptz,
    disabled_at   timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    UNIQUE (org_id, idp_entity_id),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL))
);
CREATE INDEX saml_connections_active ON pc.saml_connections (org_id) WHERE state = 'ACTIVE';

ALTER TABLE pc.saml_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.saml_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.saml_connections
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.saml_connections
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.saml_connections TO pc_app;
GRANT UPDATE (sso_url, certificates, state, updated_at, activated_at, disabled_at) ON pc.saml_connections TO pc_app;
GRANT SELECT ON pc.saml_connections TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.saml_connections TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.saml_connections;
