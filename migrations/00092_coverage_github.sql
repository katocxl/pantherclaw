-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A connection's GitHub App installation is part of what the connection
-- lets an agent reach (G0 M9 track A slice A9; N24, F048, HR-211): its
-- permissions and repository selection decide what the connection's
-- credential can do at GitHub. pc.connection_github (00081, M8) records
-- the installation and is read again; recording one, removing one, or a
-- change to anything but when and by whom it was read writes a coverage
-- invalidation of kind credential for the connection, in the changing
-- transaction, like a credential sealed or revoked (00087).

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION pc.coverage_github_installation_changed() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    -- When the installation was read again, and by whom, changes nothing
    -- it reaches.
    quiet constant text[] := ARRAY['read_at', 'updated_by', 'updated_at'];
    org uuid;
    conn uuid;
BEGIN
    IF TG_OP = 'UPDATE' AND (to_jsonb(NEW) - quiet) IS NOT DISTINCT FROM (to_jsonb(OLD) - quiet) THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'DELETE' THEN
        org := OLD.org_id;
        conn := OLD.connection_id;
    ELSE
        org := NEW.org_id;
        conn := NEW.connection_id;
    END IF;
    INSERT INTO pc.coverage_invalidations (org_id, id, kind, connection_id, subject_id, detail)
    VALUES (org, pc.coverage_uuid_v7(), 'credential', conn, conn,
            CASE TG_OP WHEN 'INSERT' THEN 'GitHub installation recorded'
                       WHEN 'DELETE' THEN 'GitHub installation removed'
                       ELSE 'GitHub installation changed' END);
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER connection_github_coverage AFTER INSERT OR UPDATE OR DELETE ON pc.connection_github
    FOR EACH ROW EXECUTE FUNCTION pc.coverage_github_installation_changed();

-- +goose Down
DROP TRIGGER connection_github_coverage ON pc.connection_github;
DROP FUNCTION pc.coverage_github_installation_changed();
