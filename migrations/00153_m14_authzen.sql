-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- AuthZEN enforcement points (G0 M14 D26-D29; PN-023, ADR-0019; HR-317,
-- HR-319). An enforcement point is a third-party policy enforcement point
-- that asks the AuthZEN decision endpoint for decisions: a service account
-- (its subject) bound to the connections it fronts. A person creates it
-- PENDING with the connections it proposes; a person who stepped up with a
-- security key activates it and so binds them. Narrowing its connections
-- applies at once, widening is proposed and needs the same confirmation,
-- and DISABLED is final. A service account is the subject of at most one
-- point that is not disabled.
--
-- A transaction an enforcement point asked for records decided_via
-- 'authzen' and the point (D28).

-- +goose Up

CREATE TABLE pc.enforcement_points (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    description          text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    service_account_id   uuid        NOT NULL,
    -- The connections a person proposed and nobody confirmed yet; NULL
    -- when nothing waits for a confirmation.
    proposed_connections uuid[]      CHECK (proposed_connections IS NULL OR (cardinality(proposed_connections) BETWEEN 1 AND 50
                                                                             AND array_position(proposed_connections, NULL) IS NULL)),
    rate_per_second      integer     NOT NULL DEFAULT 50 CHECK (rate_per_second BETWEEN 1 AND 1000),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'DISABLED')),
    created_by           uuid        NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    disabled_by          uuid,
    disabled_at          timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, service_account_id) REFERENCES pc.service_accounts (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, disabled_by) REFERENCES pc.users (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL)),
    CHECK (state <> 'PENDING' OR proposed_connections IS NOT NULL)
);
CREATE UNIQUE INDEX enforcement_points_name ON pc.enforcement_points (org_id, name) WHERE state <> 'DISABLED';
CREATE UNIQUE INDEX enforcement_points_subject ON pc.enforcement_points (org_id, service_account_id) WHERE state <> 'DISABLED';

-- DISABLED is final, a point never goes back to PENDING, and its first
-- activation is never rewritten.
-- +goose StatementBegin
CREATE FUNCTION pc.enforcement_point_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled enforcement point is final' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'ACTIVE' AND NEW.state = 'PENDING' THEN
        RAISE EXCEPTION 'an active enforcement point never goes back to pending' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_at IS NOT NULL AND (NEW.activated_at IS DISTINCT FROM OLD.activated_at
        OR NEW.activated_by IS DISTINCT FROM OLD.activated_by
        OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential) THEN
        RAISE EXCEPTION 'an enforcement point''s activation is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER enforcement_points_guard BEFORE UPDATE ON pc.enforcement_points
    FOR EACH ROW EXECUTE FUNCTION pc.enforcement_point_guard();

-- The connections a point is bound to: confirmed, never merely proposed.
CREATE TABLE pc.enforcement_point_connections (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    point_id      uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    bound_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, point_id, connection_id),
    FOREIGN KEY (org_id, point_id) REFERENCES pc.enforcement_points (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);
CREATE INDEX enforcement_point_connections_connection ON pc.enforcement_point_connections (org_id, connection_id);

ALTER TABLE pc.transactions
    ADD COLUMN decided_via text CHECK (decided_via IS NULL OR decided_via = 'authzen'),
    ADD COLUMN enforcement_point_id uuid;
-- squawk-ignore adding-foreign-key-constraint
ALTER TABLE pc.transactions
    ADD CONSTRAINT transactions_enforcement_point_fkey
        FOREIGN KEY (org_id, enforcement_point_id) REFERENCES pc.enforcement_points (org_id, id) NOT VALID,
    ADD CONSTRAINT transactions_decided_via_point
        CHECK ((decided_via IS NULL) = (enforcement_point_id IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_enforcement_point_fkey;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_decided_via_point;

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['enforcement_points', 'enforcement_point_connections'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.enforcement_points, pc.enforcement_point_connections TO pc_app;
GRANT UPDATE (proposed_connections, state, activated_by, activated_credential, activated_at, disabled_by, disabled_at,
    updated_at) ON pc.enforcement_points TO pc_app;
GRANT DELETE ON pc.enforcement_point_connections TO pc_app;
-- Set once, by the decision endpoint's own request (D28).
GRANT UPDATE (decided_via, enforcement_point_id) ON pc.transactions TO pc_app;
GRANT SELECT ON pc.enforcement_points, pc.enforcement_point_connections TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_decided_via_point,
    DROP CONSTRAINT transactions_enforcement_point_fkey,
    DROP COLUMN enforcement_point_id,
    DROP COLUMN decided_via;
DROP TABLE pc.enforcement_point_connections;
DROP TABLE pc.enforcement_points;
DROP FUNCTION pc.enforcement_point_guard();
