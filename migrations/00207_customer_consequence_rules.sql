-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Customer consequence rules (G0 M17 D106, D107; F405, HR-453, HR-454).
-- An org's own reviewed consequence rules, outside signed packages, which
-- the pipeline evaluates after the package rules and only adds to (D108).
-- Each version of a rule is one row: proposing writes it PROPOSED, and
-- only the confirmation of its protected change by a second person makes
-- it ACTIVE (approved_by), retiring the version it replaces; retiring a
-- rule is a protected change too. A version's body (the canonical JSON of
-- the rule, defs.ConsequenceRule plus max_depth) and digest never change,
-- so a recorded evaluation names the exact rule by version and digest.
-- Rule ids start with cx. and so never collide with a package rule's.

-- +goose Up
CREATE TABLE pc.customer_consequence_rules (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    rule_id     text        NOT NULL CHECK (rule_id ~ '^cx\.[a-z0-9][a-z0-9_.-]{0,63}$'),
    version     integer     NOT NULL CHECK (version BETWEEN 1 AND 100000),
    body        bytea       NOT NULL CHECK (octet_length(body) BETWEEN 2 AND 16384),
    digest      bytea       NOT NULL CHECK (octet_length(digest) = 32),
    state       text        NOT NULL DEFAULT 'PROPOSED' CHECK (state IN ('PROPOSED', 'ACTIVE', 'RETIRED')),
    proposed_by uuid        NOT NULL,
    approved_by uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, rule_id, version),
    FOREIGN KEY (org_id, proposed_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, approved_by) REFERENCES pc.users (org_id, id),
    -- Two people: the one who proposed a version never approves it.
    CHECK (approved_by IS NULL OR approved_by <> proposed_by),
    -- A version was ACTIVE, and so approved, before it is RETIRED; a
    -- proposal retired unapproved (its replacement went ahead) has none.
    CHECK (state <> 'ACTIVE' OR approved_by IS NOT NULL)
);
-- One ACTIVE version per rule.
CREATE UNIQUE INDEX customer_consequence_rules_active ON pc.customer_consequence_rules (org_id, rule_id) WHERE state = 'ACTIVE';
CREATE INDEX customer_consequence_rules_listed ON pc.customer_consequence_rules (org_id, rule_id, version DESC);

ALTER TABLE pc.customer_consequence_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.customer_consequence_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.customer_consequence_rules
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- pc_app writes a version once and only moves its state and approver.
GRANT SELECT, INSERT ON pc.customer_consequence_rules TO pc_app;
GRANT UPDATE (state, approved_by, updated_at) ON pc.customer_consequence_rules TO pc_app;
-- Auditors see which rules exist and who approved them, never the body.
GRANT SELECT (org_id, id, rule_id, version, digest, state, proposed_by, approved_by, created_at, updated_at)
    ON pc.customer_consequence_rules TO pc_audit_ro;

-- +goose StatementBegin
-- The state only moves forward: PROPOSED to ACTIVE or RETIRED, ACTIVE to
-- RETIRED; the approver is set once, with ACTIVE.
CREATE FUNCTION pc.customer_consequence_rules_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NOT (OLD.state = NEW.state
            OR (OLD.state = 'PROPOSED' AND NEW.state IN ('ACTIVE', 'RETIRED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'RETIRED')) THEN
        RAISE EXCEPTION 'customer consequence rule %: % cannot become %', OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.approved_by IS DISTINCT FROM NEW.approved_by AND NOT (OLD.approved_by IS NULL AND NEW.state = 'ACTIVE') THEN
        RAISE EXCEPTION 'customer consequence rule %: the approver is set once, with ACTIVE', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER customer_consequence_rules_transition BEFORE UPDATE ON pc.customer_consequence_rules
    FOR EACH ROW EXECUTE FUNCTION pc.customer_consequence_rules_transition();

-- 00181 is required: never silently omit the tenant write freeze.
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.customer_consequence_rules
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
-- The login role is optional until db bootstrap --deleter-password-file.
-- Bootstrap grants it all tenant tables when it is configured later.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.customer_consequence_rules TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.customer_consequence_rules;
DROP FUNCTION pc.customer_consequence_rules_transition();
