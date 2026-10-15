-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Custom detection rules and first-seen sets (G0 M10 D9, D10, D13; HR-241;
-- founder decision F4).
--
-- A custom rule version is immutable content (YAML) with its SHA-256. It is
-- DRAFT until a person publishes it with passing firing and non-firing
-- tests; publishing records the content digest in the ledger
-- (audit.detection.rule_published) and stores that ledger entry's id. The
-- engine runs a published version only while the stored content digest
-- equals the ledger-recorded one (HR-241). A rule id has at most one
-- PUBLISHED version; publishing a new one disables the old one. Each test
-- run is recorded.
--
-- First-seen sets keep a SHA-256 of each key a first_seen detector has
-- seen, never the key itself, with when it was first and last seen.

-- +goose Up
CREATE TABLE pc.custom_detection_rules (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    rule_id         text        NOT NULL CHECK (rule_id ~ '^org\.[a-z][a-z0-9_]{0,62}(\.[a-z0-9_]{1,63}){0,3}$'),
    version         integer     NOT NULL CHECK (version >= 1),
    content         text        NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 65536),
    content_digest  bytea       NOT NULL CHECK (octet_length(content_digest) = 32),
    state           text        NOT NULL DEFAULT 'DRAFT' CHECK (state IN ('DRAFT', 'PUBLISHED', 'DISABLED')),
    created_by      uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    published_by    uuid,
    published_at    timestamptz,
    -- The audit.detection.rule_published entry recording content_digest.
    ledger_entry_id uuid,
    disabled_by     uuid,
    disabled_at     timestamptz,
    disabled_reason text        CHECK (char_length(btrim(disabled_reason)) BETWEEN 1 AND 500),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, rule_id, version),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, published_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, disabled_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, ledger_entry_id) REFERENCES pc.ledger_entries (org_id, id),
    CHECK (state <> 'PUBLISHED' OR published_at IS NOT NULL),
    CHECK ((published_at IS NULL) = (ledger_entry_id IS NULL)),
    CHECK ((published_at IS NULL) = (published_by IS NULL)),
    CHECK ((state = 'DISABLED') = (disabled_at IS NOT NULL))
);
CREATE UNIQUE INDEX custom_detection_rules_published ON pc.custom_detection_rules (org_id, rule_id) WHERE state = 'PUBLISHED';

-- Transitions are one way: DRAFT → PUBLISHED → DISABLED, or DRAFT →
-- DISABLED; content never changes.
-- +goose StatementBegin
CREATE FUNCTION pc.custom_detection_rule_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NOT ((OLD.state = 'DRAFT' AND NEW.state IN ('PUBLISHED', 'DISABLED'))
            OR (OLD.state = 'PUBLISHED' AND NEW.state = 'DISABLED')) THEN
        RAISE EXCEPTION 'a custom detection rule cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PUBLISHED' THEN
        NEW.published_at := now();
    ELSE
        NEW.published_at := OLD.published_at;
        NEW.disabled_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER custom_detection_rules_transition BEFORE UPDATE ON pc.custom_detection_rules
    FOR EACH ROW EXECUTE FUNCTION pc.custom_detection_rule_transition();

CREATE TABLE pc.custom_detection_rule_tests (
    org_id     uuid        NOT NULL,
    id         uuid        NOT NULL,
    rule       uuid        NOT NULL,
    passed     boolean     NOT NULL,
    firing     integer     NOT NULL CHECK (firing >= 0),
    non_firing integer     NOT NULL CHECK (non_firing >= 0),
    results    jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(results) = 'array'
                                                        AND octet_length(results::text) <= 65536),
    run_by     uuid        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, rule) REFERENCES pc.custom_detection_rules (org_id, id),
    FOREIGN KEY (org_id, run_by) REFERENCES pc.users (org_id, id)
);
CREATE INDEX custom_detection_rule_tests_by_rule ON pc.custom_detection_rule_tests (org_id, rule, id);

CREATE TABLE pc.detection_seen (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    rule_id    text        NOT NULL CHECK (char_length(rule_id) BETWEEN 1 AND 128),
    key_hash   bytea       NOT NULL CHECK (octet_length(key_hash) = 32),
    first_seen timestamptz NOT NULL,
    last_seen  timestamptz NOT NULL,
    PRIMARY KEY (org_id, rule_id, key_hash),
    CHECK (last_seen >= first_seen)
);
CREATE INDEX detection_seen_age ON pc.detection_seen (org_id, last_seen);

ALTER TABLE pc.custom_detection_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.custom_detection_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.custom_detection_rules
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.custom_detection_rule_tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.custom_detection_rule_tests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.custom_detection_rule_tests
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.detection_seen ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.detection_seen FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.detection_seen
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.custom_detection_rules, pc.custom_detection_rule_tests TO pc_app;
GRANT UPDATE (state, published_by, published_at, ledger_entry_id, disabled_by, disabled_at, disabled_reason)
    ON pc.custom_detection_rules TO pc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pc.detection_seen TO pc_app;
GRANT SELECT ON pc.custom_detection_rules, pc.custom_detection_rule_tests, pc.detection_seen TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.detection_seen;
DROP TABLE pc.custom_detection_rule_tests;
DROP TABLE pc.custom_detection_rules;
DROP FUNCTION pc.custom_detection_rule_transition();
