-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- External policy checks (G0 M16 D81, founder decision F7; HR-436..440).
-- An org's Open Policy Agent endpoint that the Authority asks, after the
-- policy rules, about the actions whose operation matches one of its glob
-- patterns. It can only restrict: deny, hold, or a passed checklist item.
--
-- - A check is inserted PENDING by a person holding
--   policy.external_check.manage and asks nothing until a person activates
--   it with a fresh security-key step-up (HR-438). DISABLED is final.
-- - Its endpoint, CA, timeout and operations never change: another target
--   is another check. The endpoint is https; the server's
--   external_checks.allowed_prefixes is checked by the application at
--   creation and again at activation.
-- - At most three checks are ACTIVE per org, so the latency they add is
--   bounded (T-193).

-- +goose Up
CREATE TABLE pc.external_policy_checks (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    endpoint             text        NOT NULL CHECK (char_length(endpoint) BETWEEN 9 AND 2048 AND endpoint LIKE 'https://%'),
    ca_pem               text        CHECK (ca_pem IS NULL OR char_length(ca_pem) BETWEEN 1 AND 16384),
    timeout_ms           integer     NOT NULL DEFAULT 250 CHECK (timeout_ms BETWEEN 50 AND 1000),
    operations           text[]      NOT NULL CHECK (cardinality(operations) BETWEEN 1 AND 32
                                                     AND array_position(operations, NULL) IS NULL),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL)
);

CREATE UNIQUE INDEX external_policy_checks_name ON pc.external_policy_checks (org_id, name) WHERE state <> 'DISABLED';
CREATE INDEX external_policy_checks_active ON pc.external_policy_checks (org_id) WHERE state = 'ACTIVE';

-- Inserted PENDING; the target never changes; activated once, by a person
-- with a key; DISABLED is final; at most three ACTIVE per org.
-- +goose StatementBegin
CREATE FUNCTION pc.external_policy_check_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL THEN
            RAISE EXCEPTION 'an external policy check is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id OR NEW.name IS DISTINCT FROM OLD.name
            OR NEW.endpoint IS DISTINCT FROM OLD.endpoint OR NEW.ca_pem IS DISTINCT FROM OLD.ca_pem
            OR NEW.timeout_ms IS DISTINCT FROM OLD.timeout_ms OR NEW.operations IS DISTINCT FROM OLD.operations
            OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'an external policy check''s target never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'DISABLED' AND NEW.state IS DISTINCT FROM 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled external policy check stays disabled' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'an external policy check cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'an external policy check is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    IF NEW.state = 'ACTIVE' AND OLD.state IS DISTINCT FROM 'ACTIVE' THEN
        -- Two activations in one org take turns, so both cannot pass.
        PERFORM pg_advisory_xact_lock(hashtextextended('external_policy_checks:' || NEW.org_id::text, 0));
        IF (SELECT count(*) FROM pc.external_policy_checks c
            WHERE c.org_id = NEW.org_id AND c.state = 'ACTIVE' AND c.id <> NEW.id) >= 3 THEN
            RAISE EXCEPTION 'at most three external policy checks are active' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER external_policy_checks_guard BEFORE INSERT OR UPDATE ON pc.external_policy_checks
    FOR EACH ROW EXECUTE FUNCTION pc.external_policy_check_guard();

ALTER TABLE pc.external_policy_checks ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.external_policy_checks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.external_policy_checks
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.external_policy_checks TO pc_app;
GRANT UPDATE (state, activated_by, activated_credential, activated_at, updated_at) ON pc.external_policy_checks TO pc_app;
GRANT SELECT (org_id, id, name, endpoint, timeout_ms, operations, state, created_by, activated_by, activated_at, created_at,
    updated_at) ON pc.external_policy_checks TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.external_policy_checks;
DROP FUNCTION pc.external_policy_check_guard();
