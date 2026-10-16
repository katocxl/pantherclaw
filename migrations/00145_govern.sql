-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Production promotions and fleet cohorts (G0 M11 part 2, coordinator
-- decisions D39 and D40; F333, F334, F600, F601, HR-290, HR-291).
--
-- A promotion says an agent may receive new or widened grants for one
-- exact operation in one PRODUCTION environment (a prefix such as
-- payments.* is expanded to the operations known under it and stored as
-- one row each, D70; the operation grammar is the grants domain's). It is
-- made by a person holding agent.promote with a fresh security-key
-- step-up, once the operation's checks pass (owner, identity, published
-- tests, eligible approvers, coverage, declared failure behaviour); the
-- checks it passed are kept with it. When everything passes but coverage,
-- and only because no coverage record exists yet, it is PROVISIONAL for at
-- most 7 days (D80): grants under it end with it, the sweep makes it
-- ACTIVE once coverage appears, or EXPIRED. At most one ACTIVE or
-- PROVISIONAL promotion per agent, environment and operation. A revocation
-- is final: promoting again is a new row. Revoking stops new and widened
-- grants only; existing grants keep working until they expire (F6).
--
-- A fleet cohort groups agents to organize them (HR-291): its static
-- members (at most 1 000) plus the agents its optional rule matches (team,
-- environment, task type), with an owner and an optional grant baseline.
-- A cohort grants nothing: its baseline is a template a person issues
-- grants from, and its queue lists what departs from it. pc.agents gains
-- task_type, the slug a cohort rule can match.

-- +goose Up
ALTER TABLE pc.agents ADD COLUMN task_type text CHECK (task_type ~ '^[a-z][a-z0-9-]{0,63}$');
GRANT UPDATE (task_type) ON pc.agents TO pc_app;

CREATE TABLE pc.agent_promotions (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    agent_id         uuid        NOT NULL,
    environment_id   uuid        NOT NULL,
    operation        text        NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 128
                                                 AND operation ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$'),
    state            text        NOT NULL CHECK (state IN ('ACTIVE', 'PROVISIONAL', 'REVOKED', 'EXPIRED')),
    -- The per-operation checks the promotion passed: [{name, passed, detail}].
    checks           jsonb       NOT NULL CHECK (jsonb_typeof(checks) = 'array' AND octet_length(checks::text) <= 16384),
    failure_behavior text        NOT NULL CHECK (failure_behavior IN ('FAIL_CLOSED', 'QUEUE', 'DEGRADE_READ_ONLY')),
    promoted_by      uuid        NOT NULL,
    -- The security key of the step-up behind the promotion.
    credential_id    uuid        NOT NULL,
    promoted_at      timestamptz NOT NULL DEFAULT now(),
    revoked_by       uuid,
    revoked_at       timestamptz,
    revoke_reason    text        CHECK (char_length(revoke_reason) BETWEEN 1 AND 500),
    -- A PROVISIONAL promotion (D80) lasts until expires_at (at most 7 days
    -- after it was made); confirmed_at is when coverage made it ACTIVE,
    -- expired_at when it lapsed. expires_at stays as history.
    expires_at       timestamptz,
    confirmed_at     timestamptz,
    expired_at       timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id),
    FOREIGN KEY (org_id, promoted_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, credential_id) REFERENCES pc.webauthn_credentials (org_id, id),
    FOREIGN KEY (org_id, revoked_by) REFERENCES pc.users (org_id, id),
    CONSTRAINT agent_promotions_revoked CHECK (
        (state = 'REVOKED') = (revoked_at IS NOT NULL)
        AND (revoked_at IS NULL) = (revoked_by IS NULL)
        AND (revoked_at IS NULL) = (revoke_reason IS NULL)),
    CONSTRAINT agent_promotions_provisional CHECK (
        (state <> 'PROVISIONAL' OR expires_at IS NOT NULL)
        AND ((state = 'EXPIRED') = (expired_at IS NOT NULL))
        AND (expired_at IS NULL OR expires_at IS NOT NULL)
        AND (confirmed_at IS NULL OR (expires_at IS NOT NULL AND state IN ('ACTIVE', 'REVOKED')))
        AND (state <> 'ACTIVE' OR expires_at IS NULL OR confirmed_at IS NOT NULL))
);
-- One ACTIVE promotion per agent, environment and operation (D39); the
-- gate reads an agent's active promotions in one environment.
CREATE UNIQUE INDEX agent_promotions_active ON pc.agent_promotions (org_id, agent_id, environment_id, operation)
    WHERE state IN ('ACTIVE', 'PROVISIONAL');
CREATE INDEX agent_promotions_provisional ON pc.agent_promotions (org_id, expires_at) WHERE state = 'PROVISIONAL';
CREATE INDEX agent_promotions_agent ON pc.agent_promotions (org_id, agent_id, promoted_at DESC);

CREATE TABLE pc.fleet_cohorts (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    name          text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,63}$'),
    description   text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 1000),
    -- {team_id?, environment_id?, task_type?}: the agents matching every
    -- field given are members too. NULL: static members only.
    rule          jsonb       CHECK (jsonb_typeof(rule) = 'object' AND octet_length(rule::text) <= 4096),
    owner_user_id uuid        NOT NULL,
    -- A grant template {bounds, limits, ttl_seconds}; never issued by itself.
    baseline      jsonb       CHECK (jsonb_typeof(baseline) = 'object' AND octet_length(baseline::text) <= 16384),
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    FOREIGN KEY (org_id, owner_user_id) REFERENCES pc.users (org_id, id)
);

CREATE TABLE pc.fleet_cohort_members (
    org_id    uuid        NOT NULL,
    cohort_id uuid        NOT NULL,
    agent_id  uuid        NOT NULL,
    added_by  text        NOT NULL CHECK (char_length(added_by) BETWEEN 1 AND 100),
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, cohort_id, agent_id),
    FOREIGN KEY (org_id, cohort_id) REFERENCES pc.fleet_cohorts (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id)
);
CREATE INDEX fleet_cohort_members_agent ON pc.fleet_cohort_members (org_id, agent_id);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['agent_promotions', 'fleet_cohorts', 'fleet_cohort_members']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- A promotion starts ACTIVE, or PROVISIONAL with an expiry within 7 days,
-- at the database's time (D80). Then only these moves exist, each once:
-- PROVISIONAL to ACTIVE while it has not expired (coverage confirmed it);
-- PROVISIONAL to EXPIRED once it has; ACTIVE or PROVISIONAL to REVOKED
-- with who and why. Their times are the database's, and nothing about
-- what was promoted moves.
-- +goose StatementBegin
CREATE FUNCTION pc.agent_promotions_guard() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state = 'ACTIVE' THEN
            IF NEW.expires_at IS NOT NULL THEN
                RAISE EXCEPTION 'an ACTIVE promotion does not expire' USING ERRCODE = 'check_violation';
            END IF;
        ELSIF NEW.state = 'PROVISIONAL' THEN
            IF NEW.expires_at IS NULL OR NEW.expires_at <= now() OR NEW.expires_at > now() + interval '7 days' THEN
                RAISE EXCEPTION 'a provisional promotion expires within 7 days' USING ERRCODE = 'check_violation';
            END IF;
        ELSE
            RAISE EXCEPTION 'a promotion starts ACTIVE or PROVISIONAL' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.confirmed_at IS NOT NULL OR NEW.expired_at IS NOT NULL OR NEW.revoked_at IS NOT NULL THEN
            RAISE EXCEPTION 'a new promotion has no history' USING ERRCODE = 'check_violation';
        END IF;
        NEW.promoted_at := now();
        RETURN NEW;
    END IF;
    IF (NEW.org_id, NEW.id, NEW.agent_id, NEW.environment_id, NEW.operation, NEW.checks, NEW.failure_behavior,
        NEW.promoted_by, NEW.credential_id, NEW.promoted_at, NEW.expires_at)
       IS DISTINCT FROM (OLD.org_id, OLD.id, OLD.agent_id, OLD.environment_id, OLD.operation, OLD.checks,
                         OLD.failure_behavior, OLD.promoted_by, OLD.credential_id, OLD.promoted_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'promotion % keeps what it promoted', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PROVISIONAL' AND NEW.state = 'ACTIVE' THEN
        IF now() >= OLD.expires_at THEN
            RAISE EXCEPTION 'provisional promotion % has expired', OLD.id USING ERRCODE = 'check_violation';
        END IF;
        NEW.confirmed_at := now();
    ELSIF OLD.state = 'PROVISIONAL' AND NEW.state = 'EXPIRED' THEN
        IF now() < OLD.expires_at THEN
            RAISE EXCEPTION 'provisional promotion % has not expired', OLD.id USING ERRCODE = 'check_violation';
        END IF;
        NEW.expired_at := now();
    ELSIF OLD.state IN ('ACTIVE', 'PROVISIONAL') AND NEW.state = 'REVOKED' THEN
        IF NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
            RAISE EXCEPTION 'promotion % keeps its history', OLD.id USING ERRCODE = 'check_violation';
        END IF;
        NEW.revoked_at := now();
    ELSE
        RAISE EXCEPTION 'promotion % cannot move from % to %', OLD.id, OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER agent_promotions_guard BEFORE INSERT OR UPDATE ON pc.agent_promotions
    FOR EACH ROW EXECUTE FUNCTION pc.agent_promotions_guard();

-- A cohort holds at most 1 000 static members. Additions to one cohort
-- take a transaction lock of their own and count after it, so two
-- concurrent additions cannot both pass (the trigger runs as the caller:
-- HR-053).
-- +goose StatementBegin
CREATE FUNCTION pc.fleet_cohort_members_limit() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('fleet_cohort:' || NEW.org_id::text || ':' || NEW.cohort_id::text, 0));
    IF (SELECT count(*) FROM pc.fleet_cohort_members WHERE org_id = NEW.org_id AND cohort_id = NEW.cohort_id) > 1000 THEN
        RAISE EXCEPTION 'cohort % holds at most 1000 agents', NEW.cohort_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER fleet_cohort_members_limit AFTER INSERT ON pc.fleet_cohort_members
    FOR EACH ROW EXECUTE FUNCTION pc.fleet_cohort_members_limit();

GRANT SELECT ON pc.agent_promotions, pc.fleet_cohorts, pc.fleet_cohort_members TO pc_app;
GRANT INSERT (org_id, id, agent_id, environment_id, operation, state, checks, failure_behavior, promoted_by, credential_id, expires_at)
    ON pc.agent_promotions TO pc_app;
GRANT UPDATE (state, revoked_by, revoked_at, revoke_reason, confirmed_at, expired_at) ON pc.agent_promotions TO pc_app;
GRANT INSERT (org_id, id, name, description, rule, owner_user_id, baseline, created_by),
    UPDATE (name, description, rule, owner_user_id, baseline, updated_at), DELETE ON pc.fleet_cohorts TO pc_app;
GRANT INSERT (org_id, cohort_id, agent_id, added_by), DELETE ON pc.fleet_cohort_members TO pc_app;
GRANT SELECT ON pc.agent_promotions, pc.fleet_cohorts, pc.fleet_cohort_members TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.fleet_cohort_members;
DROP TABLE pc.fleet_cohorts;
DROP TABLE pc.agent_promotions;
DROP FUNCTION pc.fleet_cohort_members_limit();
DROP FUNCTION pc.agent_promotions_guard();
ALTER TABLE pc.agents DROP COLUMN task_type;
