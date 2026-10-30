-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy exception groups (G0 M18 D154; F602, HR-477, T-209). A group
-- waives one exceptable rule, for the listed operations, for the agents
-- of a fleet cohort. It is requested and approved exactly like an
-- exception (00112): PENDING until its EXCEPTION change request is
-- confirmed like a loosening, then ACTIVE for at most 30 days, by the
-- database clock, never extended.
--
-- Membership is a snapshot taken at approval: in the confirming
-- transaction one policy_exceptions row per agent the cohort holds then
-- is inserted with the group's id and activated, and the group becomes
-- ACTIVE. An agent that joins the cohort later is not covered (HR-477):
-- a member row is accepted only while its group is PENDING, so an ACTIVE
-- group never gains an agent, and group_id never changes.
--
-- The cohort is named by id only: a cohort deleted afterwards leaves the
-- group and its member rows as they are.
--
-- pc_app may UPDATE only the transition columns, as for exceptions (D22):
-- state, activated_at, expires_at, members, revoked_by and revoked_reason.

-- +goose Up
CREATE TABLE pc.policy_exception_groups (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    cohort_id        uuid        NOT NULL,
    bundle_id        text        NOT NULL CHECK (bundle_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    rule_id          text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 64),
    rule_digest      bytea       NOT NULL CHECK (octet_length(rule_digest) = 32),
    operations       text[]      NOT NULL CHECK (cardinality(operations) BETWEEN 1 AND 16
                                                 AND array_position(operations, NULL) IS NULL),
    reason           text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 500),
    owner_id         uuid        NOT NULL,
    requested_by     uuid        NOT NULL,
    requested_expiry timestamptz NOT NULL,
    state            text        NOT NULL DEFAULT 'PENDING'
                                 CHECK (state IN ('PENDING', 'ACTIVE', 'DECLINED', 'REVOKED', 'EXPIRED')),
    activated_at     timestamptz,
    expires_at       timestamptz,
    -- How many agents the snapshot at approval held.
    members          integer     CHECK (members BETWEEN 0 AND 2000),
    revoked_by       uuid,
    revoked_reason   text        CHECK (char_length(btrim(revoked_reason)) BETWEEN 1 AND 500),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, owner_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, requested_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, revoked_by) REFERENCES pc.users (org_id, id),
    CHECK (requested_expiry > created_at AND requested_expiry <= created_at + interval '30 days'),
    CHECK ((activated_at IS NULL) = (expires_at IS NULL)),
    CHECK ((activated_at IS NULL) = (members IS NULL)),
    CHECK (expires_at IS NULL OR (expires_at > activated_at AND expires_at <= activated_at + interval '30 days'
                                  AND expires_at <= requested_expiry)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'REVOKED') = (revoked_by IS NOT NULL AND revoked_reason IS NOT NULL))
);
CREATE INDEX policy_exception_groups_open ON pc.policy_exception_groups (org_id, id) WHERE state IN ('PENDING', 'ACTIVE');
CREATE INDEX policy_exception_groups_cohort ON pc.policy_exception_groups (org_id, cohort_id);

-- A group is inserted PENDING with the database's time and nothing
-- decided, like an exception.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_exception_group_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'a policy exception group is inserted PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.requested_expiry > now() + interval '30 days' THEN
        RAISE EXCEPTION 'a policy exception group lasts at most 30 days' USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := now();
    NEW.activated_at := NULL;
    NEW.expires_at := NULL;
    NEW.members := NULL;
    NEW.revoked_by := NULL;
    NEW.revoked_reason := NULL;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_exception_groups_insert BEFORE INSERT ON pc.policy_exception_groups
    FOR EACH ROW EXECUTE FUNCTION pc.policy_exception_group_insert();

-- Transitions are one way; activation takes its times from the database
-- clock and counts the member rows inserted in this transaction, and the
-- count never changes afterwards.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_exception_group_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NOT ((OLD.state = 'PENDING' AND NEW.state IN ('ACTIVE', 'DECLINED', 'REVOKED', 'EXPIRED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state IN ('REVOKED', 'EXPIRED'))) THEN
        RAISE EXCEPTION 'a policy exception group cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'ACTIVE' THEN
        IF OLD.requested_expiry <= now() THEN
            RAISE EXCEPTION 'the requested expiry of the policy exception group has passed' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_at := now();
        NEW.expires_at := least(OLD.requested_expiry, now() + interval '30 days');
        NEW.members := (SELECT count(*) FROM pc.policy_exceptions x WHERE x.org_id = OLD.org_id AND x.group_id = OLD.id);
    ELSE
        NEW.activated_at := OLD.activated_at;
        NEW.expires_at := OLD.expires_at;
        NEW.members := OLD.members;
    END IF;
    IF NEW.state = 'EXPIRED' AND coalesce(OLD.expires_at, OLD.requested_expiry) > now() THEN
        RAISE EXCEPTION 'the policy exception group has not expired yet' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_exception_groups_transition BEFORE UPDATE ON pc.policy_exception_groups
    FOR EACH ROW EXECUTE FUNCTION pc.policy_exception_group_transition();

ALTER TABLE pc.policy_exception_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.policy_exception_groups FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.policy_exception_groups
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.policy_exception_groups
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.policy_exception_groups TO pc_app;
GRANT UPDATE (state, activated_at, expires_at, members, revoked_by, revoked_reason) ON pc.policy_exception_groups TO pc_app;
GRANT SELECT ON pc.policy_exception_groups TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.policy_exception_groups TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- A member row names its group; pc_app has no UPDATE on group_id, so it
-- never changes.
ALTER TABLE pc.policy_exceptions ADD COLUMN group_id uuid;
ALTER TABLE pc.policy_exceptions ADD CONSTRAINT policy_exceptions_group
    FOREIGN KEY (org_id, group_id) REFERENCES pc.policy_exception_groups (org_id, id);
CREATE INDEX policy_exceptions_group ON pc.policy_exceptions (org_id, group_id) WHERE group_id IS NOT NULL;
-- One member row per agent of a group.
CREATE UNIQUE INDEX policy_exceptions_group_agent ON pc.policy_exceptions (org_id, group_id, agent_id) WHERE group_id IS NOT NULL;

-- A member row joins only a PENDING group (the snapshot is taken in the
-- confirming transaction, before the group becomes ACTIVE), and repeats
-- the group's rule, operations, owner, requester and requested expiry
-- (HR-477, T-209).
-- +goose StatementBegin
CREATE FUNCTION pc.policy_exception_group_member() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    g pc.policy_exception_groups;
BEGIN
    IF NEW.group_id IS NULL THEN
        RETURN NEW;
    END IF;
    SELECT * INTO g FROM pc.policy_exception_groups WHERE org_id = NEW.org_id AND id = NEW.group_id FOR SHARE;
    IF NOT FOUND OR g.state <> 'PENDING' THEN
        RAISE EXCEPTION 'an agent joins an exception group only while the group is pending' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.bundle_id <> g.bundle_id OR NEW.rule_id <> g.rule_id OR NEW.rule_digest <> g.rule_digest
       OR NEW.operations <> g.operations OR NEW.reason <> g.reason OR NEW.owner_id <> g.owner_id
       OR NEW.requested_by <> g.requested_by OR NEW.requested_expiry <> g.requested_expiry THEN
        RAISE EXCEPTION 'a member of an exception group waives what the group waives' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_exceptions_group_member BEFORE INSERT ON pc.policy_exceptions
    FOR EACH ROW EXECUTE FUNCTION pc.policy_exception_group_member();

-- +goose Down
DROP TRIGGER policy_exceptions_group_member ON pc.policy_exceptions;
DROP FUNCTION pc.policy_exception_group_member();
DROP INDEX pc.policy_exceptions_group_agent;
DROP INDEX pc.policy_exceptions_group;
ALTER TABLE pc.policy_exceptions DROP CONSTRAINT policy_exceptions_group;
ALTER TABLE pc.policy_exceptions DROP COLUMN group_id;
DROP TABLE pc.policy_exception_groups;
DROP FUNCTION pc.policy_exception_group_transition();
DROP FUNCTION pc.policy_exception_group_insert();
