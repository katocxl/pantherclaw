-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Confirmed custom detection rules (HR-666, HR-640). A person asks for one
-- exact published version of a custom rule to be confirmed; a second
-- person decides it with a security key on the always-protected surface
-- detection.custom_rule.confirm, and the confirmation row is written then,
-- bound to that version and its content digest. While a rule's open
-- confirmation matches its running published version and digest, the
-- engine raises the rule's alerts as RULE_MATCH; every other custom rule
-- stays INFERRED. Publishing a new version, disabling the version or
-- withdrawing the confirmation ends it in the same transaction. Rows are
-- append-mostly: only the end (ended_at, ended_reason, ended_by) is ever
-- written after the insert, and only once.

-- +goose Up
CREATE TABLE pc.custom_detection_rule_confirmations (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    rule_id             text        NOT NULL CHECK (char_length(rule_id) <= 128),
    version             integer     NOT NULL CHECK (version >= 1),
    content_digest      bytea       NOT NULL CHECK (octet_length(content_digest) = 32),
    -- The protected change a second person confirmed.
    protected_change_id uuid        NOT NULL,
    requested_by        text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
    confirmed_at        timestamptz NOT NULL DEFAULT now(),
    ended_at            timestamptz,
    ended_reason        text        CHECK (ended_reason IN ('withdrawn', 'superseded', 'disabled')),
    ended_by            text        CHECK (char_length(ended_by) BETWEEN 1 AND 128),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, rule_id, version) REFERENCES pc.custom_detection_rules (org_id, rule_id, version),
    FOREIGN KEY (org_id, protected_change_id) REFERENCES pc.protected_changes (org_id, id),
    CHECK ((ended_at IS NULL) = (ended_reason IS NULL)),
    CHECK (ended_at IS NOT NULL OR ended_by IS NULL)
);
-- One open confirmation per rule.
CREATE UNIQUE INDEX custom_detection_rule_confirmations_open
    ON pc.custom_detection_rule_confirmations (org_id, rule_id) WHERE ended_at IS NULL;

-- Only the end changes, once; nothing else ever does.
-- +goose StatementBegin
CREATE FUNCTION pc.custom_detection_rule_confirmation_end() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF OLD.ended_at IS NOT NULL THEN
        RAISE EXCEPTION 'a custom detection rule confirmation ends once' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id OR NEW.rule_id IS DISTINCT FROM OLD.rule_id
            OR NEW.version IS DISTINCT FROM OLD.version OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
            OR NEW.protected_change_id IS DISTINCT FROM OLD.protected_change_id
            OR NEW.requested_by IS DISTINCT FROM OLD.requested_by OR NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at THEN
        RAISE EXCEPTION 'only the end of a custom detection rule confirmation changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.ended_reason IS NULL THEN
        RAISE EXCEPTION 'a custom detection rule confirmation ends with a reason' USING ERRCODE = 'check_violation';
    END IF;
    NEW.ended_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER custom_detection_rule_confirmations_end BEFORE UPDATE ON pc.custom_detection_rule_confirmations
    FOR EACH ROW EXECUTE FUNCTION pc.custom_detection_rule_confirmation_end();

ALTER TABLE pc.custom_detection_rule_confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.custom_detection_rule_confirmations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.custom_detection_rule_confirmations
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.custom_detection_rule_confirmations
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.custom_detection_rule_confirmations TO pc_app;
GRANT UPDATE (ended_at, ended_reason, ended_by) ON pc.custom_detection_rule_confirmations TO pc_app;
GRANT SELECT ON pc.custom_detection_rule_confirmations TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.custom_detection_rule_confirmations;
DROP FUNCTION pc.custom_detection_rule_confirmation_end();
