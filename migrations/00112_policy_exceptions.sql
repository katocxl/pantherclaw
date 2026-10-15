-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy exceptions (G0 M11.1 D14; F208–F210, HR-235, founder decision F2).
-- An exception waives one rule the publisher marked exceptable, for one
-- agent and the listed operations, until it expires. It never waives a
-- grant, a guardrail, containment, identity, a budget, a missing or stale
-- fact, coverage or a route mode: those are not policy rules.
--
-- A person holding policy.exception.request asks for one; it is PENDING
-- until its EXCEPTION change request is approved like a loosening (F1),
-- which makes it ACTIVE. The database clock sets activated_at and
-- expires_at = least(requested_expiry, activated_at + 30 days); no
-- exception lasts longer than 30 days and none is ever extended: renewal
-- is a new request. A rule whose digest changed no longer matches.
--
-- Every transition is conditional and one way: PENDING → ACTIVE, DECLINED,
-- REVOKED or EXPIRED; ACTIVE → REVOKED or EXPIRED. An ACTIVE exception past
-- its expiry already waives nothing (readers check expires_at > now()); the
-- sweep only records the state.
--
-- pc_app may UPDATE only the transition columns (D22): state, activated_at,
-- expires_at, revoked_by and revoked_reason; never the ids, the rule, its
-- digest, the agent, the operations, the reason, the owner or requester.

-- +goose Up
CREATE TABLE pc.policy_exceptions (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    bundle_id        text        NOT NULL CHECK (bundle_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    rule_id          text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 64),
    -- RuleDigest of the rule in the version the request was made against.
    rule_digest      bytea       NOT NULL CHECK (octet_length(rule_digest) = 32),
    agent_id         uuid        NOT NULL,
    -- Exact operations inside the rule's scope; never a prefix.
    operations       text[]      NOT NULL CHECK (cardinality(operations) BETWEEN 1 AND 16
                                                 AND array_position(operations, NULL) IS NULL),
    -- Why, in the requester's words (untrusted text).
    reason           text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 500),
    -- The person accountable for it, told of its activation and expiry.
    owner_id         uuid        NOT NULL,
    -- Only a person (HR-235).
    requested_by     uuid        NOT NULL,
    requested_expiry timestamptz NOT NULL,
    state            text        NOT NULL DEFAULT 'PENDING'
                                 CHECK (state IN ('PENDING', 'ACTIVE', 'DECLINED', 'REVOKED', 'EXPIRED')),
    activated_at     timestamptz,
    expires_at       timestamptz,
    revoked_by       uuid,
    revoked_reason   text        CHECK (char_length(btrim(revoked_reason)) BETWEEN 1 AND 500),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, owner_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, requested_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, revoked_by) REFERENCES pc.users (org_id, id),
    CHECK (requested_expiry > created_at AND requested_expiry <= created_at + interval '30 days'),
    CHECK ((activated_at IS NULL) = (expires_at IS NULL)),
    CHECK (expires_at IS NULL OR (expires_at > activated_at AND expires_at <= activated_at + interval '30 days'
                                  AND expires_at <= requested_expiry)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'REVOKED') = (revoked_by IS NOT NULL AND revoked_reason IS NOT NULL))
);
CREATE INDEX policy_exceptions_active ON pc.policy_exceptions (org_id, agent_id) WHERE state = 'ACTIVE';
CREATE INDEX policy_exceptions_open ON pc.policy_exceptions (org_id, id) WHERE state IN ('PENDING', 'ACTIVE');

-- Transitions are one way, and activation takes its times from the
-- database clock whatever the statement says (HR-235).
-- +goose StatementBegin
CREATE FUNCTION pc.policy_exception_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NOT ((OLD.state = 'PENDING' AND NEW.state IN ('ACTIVE', 'DECLINED', 'REVOKED', 'EXPIRED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state IN ('REVOKED', 'EXPIRED'))) THEN
        RAISE EXCEPTION 'a policy exception cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'ACTIVE' THEN
        IF OLD.requested_expiry <= now() THEN
            RAISE EXCEPTION 'the requested expiry of the policy exception has passed' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_at := now();
        NEW.expires_at := least(OLD.requested_expiry, now() + interval '30 days');
    ELSE
        NEW.activated_at := OLD.activated_at;
        NEW.expires_at := OLD.expires_at;
    END IF;
    IF NEW.state = 'EXPIRED' AND coalesce(OLD.expires_at, OLD.requested_expiry) > now() THEN
        RAISE EXCEPTION 'the policy exception has not expired yet' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_exceptions_transition BEFORE UPDATE ON pc.policy_exceptions
    FOR EACH ROW EXECUTE FUNCTION pc.policy_exception_transition();

ALTER TABLE pc.policy_exceptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.policy_exceptions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.policy_exceptions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.policy_exceptions TO pc_app;
GRANT UPDATE (state, activated_at, expires_at, revoked_by, revoked_reason) ON pc.policy_exceptions TO pc_app;
GRANT SELECT ON pc.policy_exceptions TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.policy_exceptions;
DROP FUNCTION pc.policy_exception_transition();
