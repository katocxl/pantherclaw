-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Cross-org federation: keys, the org's endpoint and pairwise trust (G0 M35
-- D1020, D1021; HR-770..772).
--
-- pc.federation_keys holds each org's Ed25519 federation keys. The private
-- half is stored only wrapped by a KEK, with an AAD binding the org and the
-- kid, as pc.keys does (HR-062): pc_app may change only the state columns,
-- and pc_keystore only the wrapped key and its KEK (the re-wrap job). An org
-- has at most one ACTIVE key and one RETIRING key; a rotated key stays
-- RETIRING for 7 days, then is RETIRED and leaves the federation document.
--
-- pc.federation_settings is the org's federation endpoint: the base URL of
-- its gateway's federation face, which the federation document names.
--
-- pc.federation_trusts is a pairwise trust with one peer org: the peer's
-- document URL, the keys pinned from it, and the safety code both admins
-- compare. It moves PROPOSED → CONFIRMED_LOCAL → ACTIVE (when the peer
-- confirmed too), ACTIVE ↔ STALE (the peer document expired or could not
-- be fetched), and any live state → REVOKED. One live trust per peer org.

-- +goose Up
CREATE TABLE pc.federation_keys (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    kid                 text        NOT NULL CHECK (kid ~ '^fed-[A-Za-z0-9_-]{43}$'),
    public_key          bytea       NOT NULL CHECK (octet_length(public_key) = 32),
    public_jwk          jsonb       NOT NULL CHECK (jsonb_typeof(public_jwk) = 'object' AND octet_length(public_jwk::text) <= 1024),
    wrapped_private_key bytea       NOT NULL CHECK (octet_length(wrapped_private_key) BETWEEN 32 AND 1024),
    kek_id              text        NOT NULL CHECK (char_length(kek_id) BETWEEN 1 AND 64),
    state               text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RETIRING', 'RETIRED')),
    created_at          timestamptz NOT NULL DEFAULT now(),
    created_by          text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    rotated_at          timestamptz,
    retired_at          timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, kid),
    CONSTRAINT federation_keys_rotated CHECK ((state = 'ACTIVE') = (rotated_at IS NULL)),
    CONSTRAINT federation_keys_retired CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX federation_keys_one_active ON pc.federation_keys (org_id) WHERE state = 'ACTIVE';
CREATE UNIQUE INDEX federation_keys_one_retiring ON pc.federation_keys (org_id) WHERE state = 'RETIRING';

-- A key only moves ACTIVE → RETIRING → RETIRED; what it is never changes.
-- +goose StatementBegin
CREATE FUNCTION pc.federation_key_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'ACTIVE' THEN
            RAISE EXCEPTION 'a federation key is inserted ACTIVE' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.kid IS DISTINCT FROM OLD.kid OR NEW.public_key IS DISTINCT FROM OLD.public_key
            OR NEW.public_jwk IS DISTINCT FROM OLD.public_jwk OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'what a federation key is never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((OLD.state = NEW.state)
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'RETIRING')
            OR (OLD.state = 'RETIRING' AND NEW.state = 'RETIRED')) THEN
        RAISE EXCEPTION 'a federation key moves ACTIVE to RETIRING to RETIRED' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'ACTIVE' AND NEW.state = 'RETIRING' THEN
        NEW.rotated_at := now();
    ELSIF OLD.state = 'RETIRING' AND NEW.state = 'RETIRED' THEN
        NEW.retired_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER federation_keys_guard BEFORE INSERT OR UPDATE ON pc.federation_keys
    FOR EACH ROW EXECUTE FUNCTION pc.federation_key_guard();

CREATE TABLE pc.federation_settings (
    org_id         uuid        NOT NULL PRIMARY KEY REFERENCES pc.orgs (id),
    federation_url text        NOT NULL CHECK (char_length(federation_url) BETWEEN 9 AND 2048 AND federation_url ~ '^https?://'),
    updated_by     text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pc.federation_trusts (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    -- The peer org's id, as its own document states it (another deployment's
    -- id space): never a foreign key.
    peer_org_id        uuid        NOT NULL,
    -- Untrusted text from the peer document.
    peer_name          text        NOT NULL CHECK (char_length(peer_name) BETWEEN 1 AND 200),
    peer_doc_url       text        NOT NULL CHECK (char_length(peer_doc_url) BETWEEN 9 AND 2048 AND peer_doc_url ~ '^https://'),
    peer_server_url    text        NOT NULL CHECK (char_length(peer_server_url) BETWEEN 9 AND 2048 AND peer_server_url ~ '^https://'),
    peer_federation_url text       CHECK (char_length(peer_federation_url) BETWEEN 9 AND 2048 AND peer_federation_url ~ '^https://'),
    pinned_jwks        jsonb       NOT NULL CHECK (jsonb_typeof(pinned_jwks) = 'object' AND octet_length(pinned_jwks::text) <= 8192),
    pinned_keys_digest bytea       NOT NULL CHECK (octet_length(pinned_keys_digest) = 32),
    -- The last verified peer document (compact or general JWS) and its expiry.
    peer_document      bytea       NOT NULL CHECK (octet_length(peer_document) BETWEEN 2 AND 262144),
    peer_doc_expires_at timestamptz NOT NULL,
    safety_code        text        NOT NULL CHECK (safety_code ~ '^[A-Z2-7]{4}( [A-Z2-7]{4}){4}$'),
    state              text        NOT NULL DEFAULT 'PROPOSED'
                                   CHECK (state IN ('PROPOSED', 'CONFIRMED_LOCAL', 'ACTIVE', 'STALE', 'REVOKED')),
    created_by         text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at         timestamptz NOT NULL DEFAULT now(),
    confirmed_by       uuid,
    confirmed_credential uuid,
    confirmed_at       timestamptz,
    peer_confirmed_at  timestamptz,
    last_refreshed_at  timestamptz,
    revoked_by         text        CHECK (char_length(revoked_by) BETWEEN 1 AND 128),
    revoked_at         timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, confirmed_by) REFERENCES pc.users (org_id, id),
    CONSTRAINT federation_trusts_not_self CHECK (peer_org_id <> org_id),
    CONSTRAINT federation_trusts_confirmed CHECK ((confirmed_at IS NULL) = (confirmed_by IS NULL)
        AND (confirmed_by IS NULL) = (confirmed_credential IS NULL)),
    CONSTRAINT federation_trusts_confirmed_state CHECK (state IN ('PROPOSED', 'REVOKED') OR confirmed_at IS NOT NULL),
    CONSTRAINT federation_trusts_active CHECK (state NOT IN ('ACTIVE', 'STALE') OR peer_confirmed_at IS NOT NULL),
    CONSTRAINT federation_trusts_revoked CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)
        AND (revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX federation_trusts_live_peer ON pc.federation_trusts (org_id, peer_org_id) WHERE state <> 'REVOKED';
CREATE INDEX federation_trusts_refresh ON pc.federation_trusts (org_id, last_refreshed_at) WHERE state <> 'REVOKED';

-- A trust's peer and the URL it was proposed from never change; it is
-- confirmed locally once, and a REVOKED trust stays revoked.
-- +goose StatementBegin
CREATE FUNCTION pc.federation_trust_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'PROPOSED' OR NEW.confirmed_at IS NOT NULL OR NEW.peer_confirmed_at IS NOT NULL THEN
            RAISE EXCEPTION 'a federation trust is inserted PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.peer_org_id IS DISTINCT FROM OLD.peer_org_id OR NEW.peer_doc_url IS DISTINCT FROM OLD.peer_doc_url
            OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a federation trust''s peer never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'REVOKED' THEN
        RAISE EXCEPTION 'a revoked federation trust never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.confirmed_at IS NOT NULL AND (NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at
            OR NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by
            OR NEW.confirmed_credential IS DISTINCT FROM OLD.confirmed_credential) THEN
        RAISE EXCEPTION 'a federation trust is confirmed once' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((OLD.state = NEW.state)
            OR NEW.state = 'REVOKED'
            OR (OLD.state = 'PROPOSED' AND NEW.state IN ('CONFIRMED_LOCAL', 'ACTIVE'))
            OR (OLD.state = 'CONFIRMED_LOCAL' AND NEW.state = 'ACTIVE')
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'STALE')
            OR (OLD.state = 'STALE' AND NEW.state = 'ACTIVE')) THEN
        RAISE EXCEPTION 'federation trust: % to % is not a transition', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'REVOKED' AND OLD.state <> 'REVOKED' THEN
        NEW.revoked_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER federation_trusts_guard BEFORE INSERT OR UPDATE ON pc.federation_trusts
    FOR EACH ROW EXECUTE FUNCTION pc.federation_trust_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['federation_keys', 'federation_settings', 'federation_trusts'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format('GRANT SELECT ON pc.%I TO pc_audit_ro', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_keystore') THEN
        GRANT SELECT, UPDATE (wrapped_private_key, kek_id) ON pc.federation_keys TO pc_keystore;
    END IF;
END
$$;
-- +goose StatementEnd

-- pc_app never changes key material (HR-062).
GRANT SELECT, INSERT ON pc.federation_keys TO pc_app;
GRANT UPDATE (state, rotated_at, retired_at) ON pc.federation_keys TO pc_app;
GRANT SELECT, INSERT, UPDATE ON pc.federation_settings TO pc_app;
GRANT SELECT, INSERT ON pc.federation_trusts TO pc_app;
GRANT UPDATE (peer_name, peer_server_url, peer_federation_url, pinned_jwks, pinned_keys_digest, peer_document,
              peer_doc_expires_at, safety_code, state, confirmed_by, confirmed_credential, confirmed_at,
              peer_confirmed_at, last_refreshed_at, revoked_by, revoked_at) ON pc.federation_trusts TO pc_app;

-- +goose Down
DROP TABLE pc.federation_trusts;
DROP FUNCTION pc.federation_trust_guard();
DROP TABLE pc.federation_settings;
DROP TABLE pc.federation_keys;
DROP FUNCTION pc.federation_key_guard();
