-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Agent payment trust anchors (G0 M39 D1120, D1121; FQ39-1; HR-830..832;
-- Business). An anchor is where the keys of one party come from:
--
--   - MANDATE_ISSUER: who issues AP2 mandates (a JWKS);
--   - MERCHANT: who signs AP2 checkout and cart JWTs (a JWKS);
--   - AGENT_DIRECTORY: where agents' HTTP message signature keys live (a
--     Web Bot Auth directory or a key service).
--
-- An anchor holds a static JWKS or an https URL, never both. PantherClaw
-- verifies mandates and signatures with these keys and never signs; no
-- card, network token or payment credential is stored anywhere.
--
-- Agent payments run in sandbox only (D1120): sandbox is always true, and
-- the URL's host must be on the sandbox host allow-list in code, which the
-- service checks at creation, activation and every key fetch; anything
-- else is refused (PAYMENTS_LIVE_REFUSED). There is no live switch.
--
-- An anchor is created PENDING through the API by a person holding
-- payments.manage and becomes ACTIVE only when a person activates it on
-- its page with a fresh WebAuthn step-up (activated_by,
-- activated_credential). Its keys and URL never change: another key source
-- is another anchor. REVOKED is final.

-- +goose Up
CREATE TABLE pc.payment_trust_anchors (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    kind                 text        NOT NULL CHECK (kind IN ('MANDATE_ISSUER', 'MERCHANT', 'AGENT_DIRECTORY')),
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    jwks                 jsonb       CHECK (jwks IS NULL OR (jsonb_typeof(jwks) = 'object' AND octet_length(jwks::text) <= 65536)),
    url                  text        CHECK (url IS NULL OR (char_length(url) BETWEEN 9 AND 2048 AND url LIKE 'https://%')),
    sandbox              boolean     NOT NULL CHECK (sandbox),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'REVOKED')),
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    revoked_at           timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((jwks IS NULL) <> (url IS NULL)),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL))
);
-- A revoked anchor frees its name.
CREATE UNIQUE INDEX payment_trust_anchors_name ON pc.payment_trust_anchors (org_id, name) WHERE state <> 'REVOKED';
CREATE INDEX payment_trust_anchors_active ON pc.payment_trust_anchors (org_id, kind) WHERE state = 'ACTIVE';

-- The kind, keys, URL, sandbox mark and creator never change, an anchor is
-- inserted PENDING and activated once with a person and a key, nothing
-- returns to PENDING, and REVOKED is final (HR-831, HR-832).
-- +goose StatementBegin
CREATE FUNCTION pc.payment_trust_anchor_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a payment trust anchor is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.kind IS DISTINCT FROM OLD.kind OR NEW.jwks IS DISTINCT FROM OLD.jwks OR NEW.url IS DISTINCT FROM OLD.url
            OR NEW.sandbox IS DISTINCT FROM OLD.sandbox OR NEW.created_by IS DISTINCT FROM OLD.created_by
            OR NEW.name IS DISTINCT FROM OLD.name THEN
        RAISE EXCEPTION 'a payment trust anchor''s keys never change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'REVOKED' AND NEW.state IS DISTINCT FROM 'REVOKED' THEN
        RAISE EXCEPTION 'a revoked payment trust anchor stays revoked' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'a payment trust anchor cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'ACTIVE' AND OLD.state = 'PENDING' AND NEW.activated_by IS NULL THEN
        RAISE EXCEPTION 'a payment trust anchor is activated by a person with a key' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'a payment trust anchor is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    IF OLD.state IS DISTINCT FROM 'REVOKED' AND NEW.state = 'REVOKED' THEN
        NEW.revoked_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER payment_trust_anchors_guard BEFORE INSERT OR UPDATE ON pc.payment_trust_anchors
    FOR EACH ROW EXECUTE FUNCTION pc.payment_trust_anchor_guard();

ALTER TABLE pc.payment_trust_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.payment_trust_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.payment_trust_anchors
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.payment_trust_anchors TO pc_app;
GRANT UPDATE (state, activated_by, activated_credential, activated_at, revoked_at, updated_at)
    ON pc.payment_trust_anchors TO pc_app;
GRANT SELECT ON pc.payment_trust_anchors TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.payment_trust_anchors;
DROP FUNCTION pc.payment_trust_anchor_guard();
