-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Break-glass access (G0 M13 D33, D38; HR-389; Business edition and
-- above). Org admins designate at most three members as break-glass
-- holders, each with one emergency role (a default role bindable at the
-- org, never org_admin). A holder activates it with a security-key step-up
-- and a reason for at most 60 minutes: while the activation is in force
-- the role applies to them at the org, every other org admin is notified,
-- and every call they make is audited with the activation. It never
-- waives a two-person rule, an approval or an invariant: it only adds one
-- role's permissions for an hour.

-- +goose Up

CREATE TABLE pc.breakglass_holders (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    user_id       uuid        NOT NULL,
    role          text        NOT NULL CHECK (role ~ '^[a-z][a-z_]{0,62}$' AND role <> 'org_admin'),
    designated_by uuid        NOT NULL,
    designated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, designated_by) REFERENCES pc.users (org_id, id)
);

-- At most three holders per org.
-- +goose StatementBegin
CREATE FUNCTION pc.breakglass_holders_limit() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF (SELECT count(*) FROM pc.breakglass_holders WHERE org_id = NEW.org_id) > 3 THEN
        RAISE EXCEPTION 'an organization has at most three break-glass holders' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER breakglass_holders_limit AFTER INSERT OR UPDATE ON pc.breakglass_holders
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION pc.breakglass_holders_limit();

CREATE TABLE pc.breakglass_activations (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    user_id         uuid        NOT NULL,
    role            text        NOT NULL CHECK (role ~ '^[a-z][a-z_]{0,62}$' AND role <> 'org_admin'),
    reason          text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'),
    credential      uuid        NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    ended_by_type   text        CHECK (ended_by_type IS NULL OR char_length(ended_by_type) BETWEEN 1 AND 32),
    ended_by_id     text        CHECK (ended_by_id IS NULL OR char_length(ended_by_id) BETWEEN 1 AND 256),
    end_reason      text        CHECK (end_reason IS NULL OR end_reason IN ('ENDED', 'EXPIRED', 'HOLDER_REMOVED')),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK (expires_at > started_at AND expires_at <= started_at + interval '60 minutes'),
    CHECK ((ended_at IS NULL) = (end_reason IS NULL)),
    CHECK ((ended_by_type IS NULL) = (ended_by_id IS NULL))
);
-- One activation not ended per holder.
CREATE UNIQUE INDEX breakglass_activations_open ON pc.breakglass_activations (org_id, user_id) WHERE ended_at IS NULL;
CREATE INDEX breakglass_activations_started ON pc.breakglass_activations (org_id, id DESC);

-- An activation is for a designated holder's own role, and afterwards
-- only its end is written, once.
-- +goose StatementBegin
CREATE FUNCTION pc.breakglass_activation_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (SELECT 1 FROM pc.breakglass_holders h
                       WHERE h.org_id = NEW.org_id AND h.user_id = NEW.user_id AND h.role = NEW.role)
            OR NEW.ended_at IS NOT NULL THEN
            RAISE EXCEPTION 'only a designated holder activates their own emergency role' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.ended_at IS NOT NULL THEN
        RAISE EXCEPTION 'an ended break-glass activation is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id OR NEW.user_id IS DISTINCT FROM OLD.user_id
        OR NEW.role IS DISTINCT FROM OLD.role OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.credential IS DISTINCT FROM OLD.credential OR NEW.started_at IS DISTINCT FROM OLD.started_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'a break-glass activation is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER breakglass_activations_guard BEFORE INSERT OR UPDATE ON pc.breakglass_activations
    FOR EACH ROW EXECUTE FUNCTION pc.breakglass_activation_guard();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['breakglass_holders', 'breakglass_activations'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT, DELETE ON pc.breakglass_holders TO pc_app;
GRANT UPDATE (role, designated_by, designated_at) ON pc.breakglass_holders TO pc_app;
GRANT SELECT, INSERT ON pc.breakglass_activations TO pc_app;
GRANT UPDATE (ended_at, ended_by_type, ended_by_id, end_reason) ON pc.breakglass_activations TO pc_app;
GRANT SELECT ON pc.breakglass_holders, pc.breakglass_activations TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.breakglass_activations;
DROP FUNCTION pc.breakglass_activation_guard();
DROP TABLE pc.breakglass_holders;
DROP FUNCTION pc.breakglass_holders_limit();
