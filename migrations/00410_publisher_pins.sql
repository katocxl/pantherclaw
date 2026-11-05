-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Publisher key pins (G0 M37 D1081; FQ37-1; HR-795). An org trusts a bundle
-- publisher's Ed25519 key only once a person holding publisher.manage pins
-- it and activates the pin on its page with a fresh WebAuthn step-up
-- (activated_by, activated_credential). The key, its kid and fingerprint,
-- the publisher and the allowed kinds never change: another key is another
-- pin. A pin moves only PENDING -> ACTIVE, PENDING -> REVOKED and ACTIVE ->
-- REVOKED; REVOKED is final. Revoked pins stay, so a publisher revocation
-- statement signed by any key the org ever pinned can still be checked
-- (D1083, HR-800).

-- +goose Up
CREATE TABLE pc.publisher_pins (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    publisher            text        NOT NULL CHECK (publisher ~ '^[a-z][a-z0-9-]{2,31}$'),
    kid                  text        NOT NULL CHECK (kid ~ '^publisher-[a-z][a-z0-9-]{2,31}-[A-Za-z0-9_-]{22}$'),
    public_key           bytea       NOT NULL CHECK (octet_length(public_key) = 32),
    fingerprint          text        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    allowed_kinds        text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_kinds) <= 6
                                         AND array_position(allowed_kinds, NULL) IS NULL
                                         AND allowed_kinds <@ ARRAY['tool_package', 'openapi_spec', 'detection_rule', 'playbook',
                                                                    'facts_declaration', 'channel_template']::text[]),
    revocations_url      text        CHECK (revocations_url IS NULL
                                            OR (char_length(revocations_url) BETWEEN 9 AND 2048 AND revocations_url LIKE 'https://%')),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'REVOKED')),
    revoke_reason        text        CHECK (revoke_reason IN ('UNPINNED', 'COMPROMISED', 'PUBLISHER_REVOKED')),
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    revoked_at           timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL)),
    CHECK ((state = 'REVOKED') = (revoke_reason IS NOT NULL)),
    CHECK (kid LIKE 'publisher-' || publisher || '-%')
);
-- One live pin per key.
CREATE UNIQUE INDEX publisher_pins_live_kid ON pc.publisher_pins (org_id, kid) WHERE state <> 'REVOKED';
CREATE INDEX publisher_pins_publisher ON pc.publisher_pins (org_id, publisher);

-- The key never changes, a pin is inserted PENDING, activated once by a
-- person with a key, and REVOKED is final (HR-795).
-- +goose StatementBegin
CREATE FUNCTION pc.publisher_pin_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a publisher pin is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF NEW.publisher IS DISTINCT FROM OLD.publisher OR NEW.kid IS DISTINCT FROM OLD.kid
            OR NEW.public_key IS DISTINCT FROM OLD.public_key OR NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
            OR NEW.allowed_kinds IS DISTINCT FROM OLD.allowed_kinds OR NEW.revocations_url IS DISTINCT FROM OLD.revocations_url
            OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
        RAISE EXCEPTION 'a publisher pin''s key never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
            (OLD.state = 'PENDING' AND NEW.state IN ('ACTIVE', 'REVOKED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'REVOKED')) THEN
        RAISE EXCEPTION 'a publisher pin cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'REVOKED' AND (NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
        RAISE EXCEPTION 'a revoked publisher pin stays as it was revoked' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'a publisher pin is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        IF OLD.state IS DISTINCT FROM 'PENDING' OR NEW.state IS DISTINCT FROM 'ACTIVE' THEN
            RAISE EXCEPTION 'only a PENDING pin is activated' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_at := now();
    END IF;
    IF OLD.state IS DISTINCT FROM 'REVOKED' AND NEW.state = 'REVOKED' THEN
        NEW.revoked_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER publisher_pins_guard BEFORE INSERT OR UPDATE ON pc.publisher_pins
    FOR EACH ROW EXECUTE FUNCTION pc.publisher_pin_guard();

ALTER TABLE pc.publisher_pins ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.publisher_pins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.publisher_pins
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.publisher_pins
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.publisher_pins TO pc_app;
GRANT UPDATE (state, revoke_reason, activated_by, activated_credential, activated_at, revoked_at) ON pc.publisher_pins TO pc_app;
GRANT SELECT ON pc.publisher_pins TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.publisher_pins TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.publisher_pins;
DROP FUNCTION pc.publisher_pin_guard();
