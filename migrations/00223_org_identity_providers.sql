-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Organization identity providers (G0 M18 D155, G6; HR-481..484, T-207):
-- OIDC providers an organization's own admin configures, next to the
-- deployment's auth.oidc_providers. A provider is PENDING until a second
-- person confirms it (a protected change in every protect mode), then
-- ACTIVE, and DISABLED when turned off or when its activation is declined
-- or expires (D169). Only ACTIVE providers sign anyone
-- in. Its issuer can't change once it has been ACTIVE: users are
-- (org, issuer, subject), so a swapped issuer would sign in as other
-- people. The client secret is sealed with the org's DEK (purpose
-- idp_client_secret; the AAD binds org, table, column and row) and is
-- never returned.
--
-- pc.org_identity_provider_settings holds the org's "own providers only"
-- setting: with it on, the deployment's providers no longer sign anyone in
-- to the org.
-- +goose Up
CREATE TABLE pc.org_identity_providers (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    name          text        NOT NULL CHECK (name ~ '^[a-z0-9-]{1,32}$'),
    issuer        text        NOT NULL CHECK (issuer ~ '^https://[^/?#@[:space:]]+(/[^?#[:space:]]*)?$' AND char_length(issuer) <= 512),
    client_id     text        NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 256),
    client_secret bytea       NOT NULL CHECK (octet_length(client_secret) BETWEEN 16 AND 8192),
    trust_email   boolean     NOT NULL DEFAULT false,
    state         text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    created_by    uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_by    uuid        NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- The first time the provider became ACTIVE: from then on its issuer
    -- is fixed.
    activated_at  timestamptz,
    disabled_by   uuid,
    disabled_at   timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL)),
    CHECK ((disabled_by IS NULL) = (disabled_at IS NULL))
);

-- +goose StatementBegin
CREATE FUNCTION pc.org_identity_provider_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pc AS $$
BEGIN
    IF OLD.activated_at IS NOT NULL AND NEW.issuer IS DISTINCT FROM OLD.issuer THEN
        RAISE EXCEPTION 'an organization identity provider''s issuer is immutable once it has been active'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at THEN
        RAISE EXCEPTION 'activated_at is set once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER org_identity_provider_guard BEFORE UPDATE ON pc.org_identity_providers
    FOR EACH ROW EXECUTE FUNCTION pc.org_identity_provider_guard();

CREATE TABLE pc.org_identity_provider_settings (
    org_id             uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    own_providers_only boolean     NOT NULL DEFAULT false,
    updated_by         uuid        NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_identity_providers', 'org_identity_provider_settings']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.org_identity_providers, pc.org_identity_provider_settings TO pc_app;
GRANT UPDATE (name, issuer, client_id, client_secret, trust_email, state, updated_by, updated_at, activated_at,
    disabled_by, disabled_at) ON pc.org_identity_providers TO pc_app;
GRANT UPDATE (own_providers_only, updated_by, updated_at) ON pc.org_identity_provider_settings TO pc_app;
-- The audit reader sees everything but the sealed secret (HR-482).
GRANT SELECT (org_id, id, name, issuer, client_id, trust_email, state, created_by, created_at, updated_by, updated_at,
    activated_at, disabled_by, disabled_at) ON pc.org_identity_providers TO pc_audit_ro;
GRANT SELECT ON pc.org_identity_provider_settings TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.org_identity_provider_settings;
DROP TABLE pc.org_identity_providers;
DROP FUNCTION pc.org_identity_provider_guard();
