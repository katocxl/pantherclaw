-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- v0.1.0 known limit (D24 follow-up): a connection test records the
-- connection revision it was requested against, so a target_verifier test
-- requested before a change but finished after it no longer vouches for the
-- changed connection (HR-211). The database fills the column from the
-- connection row at insert, whatever the caller sends, and pc_app cannot
-- update it. Tests recorded before this migration have none, and so never
-- vouch again: a new test is needed (fail closed).
-- +goose Up
ALTER TABLE pc.connection_tests ADD COLUMN connection_revision integer
    CHECK (connection_revision IS NULL OR connection_revision > 0);

-- +goose StatementBegin
CREATE FUNCTION pc.connection_tests_revision()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    SELECT c.revision INTO NEW.connection_revision FROM pc.connections c
    WHERE c.org_id = NEW.org_id AND c.id = NEW.connection_id;
    IF NEW.connection_revision IS NULL THEN
        RAISE EXCEPTION 'connection test %: connection % not found', NEW.id, NEW.connection_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connection_tests_revision BEFORE INSERT ON pc.connection_tests
    FOR EACH ROW EXECUTE FUNCTION pc.connection_tests_revision();

-- +goose Down
DROP TRIGGER connection_tests_revision ON pc.connection_tests;
DROP FUNCTION pc.connection_tests_revision();
ALTER TABLE pc.connection_tests DROP COLUMN connection_revision;
