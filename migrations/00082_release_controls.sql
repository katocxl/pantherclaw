-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Release controls (G0 M8 track P: P2, P3; HR-207, HR-205):
--
-- * change_windows: when a release approval for a deployment environment
--   counts. A window has weekly entries in its time zone, one-off windows
--   and freezes, for an environment and optionally one repository. A freeze
--   overrides every window. At most one window is ACTIVE per environment
--   and repository: a new one retires the current one and takes the next
--   revision. A window is never changed or deleted; pc_app only retires it,
--   once: a retired window stays retired. The finalization that consumes a window requirement reads it by the
--   database clock (HR-171).
-- * approval_requests.invalidation_key, for example
--   github.pull:<connection>:<owner>/<repo>#<number>: a pull request's new
--   head supersedes every unconsumed request with the same key (P3).
--
-- The roles code_reviewer and release_approver are listed in Go only
-- (tenancy domain); no table lists roles.

-- +goose Up
CREATE TABLE pc.change_windows (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    -- The deployment environment as a consequence names it (for example a
    -- GitHub environment such as production), in lowercase: GitHub's
    -- environment names are case-insensitive.
    environment text        NOT NULL CHECK (char_length(environment) BETWEEN 1 AND 100 AND environment !~ '[[:cntrl:]]'
                                            AND environment = lower(environment)),
    -- owner/name; NULL for every repository of the environment.
    repository  text        CHECK (repository IS NULL OR repository ~ '^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9._-]{1,100}$'),
    time_zone   text        NOT NULL CHECK (char_length(time_zone) BETWEEN 1 AND 64),
    -- [{day, start, minutes}], local times in time_zone.
    weekly      jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(weekly) = 'array' AND jsonb_array_length(weekly) <= 32),
    -- [{start, end}], instants.
    one_off     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(one_off) = 'array' AND jsonb_array_length(one_off) <= 32),
    freezes     jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(freezes) = 'array' AND jsonb_array_length(freezes) <= 32),
    revision    integer     NOT NULL CHECK (revision >= 1),
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RETIRED')),
    created_by  text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_by  text        CHECK (retired_by IS NULL OR char_length(retired_by) BETWEEN 1 AND 100),
    retired_at  timestamptz,
    PRIMARY KEY (org_id, id),
    CHECK ((state = 'RETIRED') = (retired_by IS NOT NULL AND retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX change_windows_active ON pc.change_windows (org_id, environment, coalesce(repository, '')) WHERE state = 'ACTIVE';
CREATE UNIQUE INDEX change_windows_revision ON pc.change_windows (org_id, environment, coalesce(repository, ''), revision);

ALTER TABLE pc.change_windows ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.change_windows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.change_windows
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.change_windows TO pc_app;
GRANT UPDATE (state, retired_by, retired_at) ON pc.change_windows TO pc_app;
GRANT SELECT ON pc.change_windows TO pc_audit_ro;

-- Retiring is final: a retired window never becomes ACTIVE again and
-- keeps who retired it and when. A window is replaced by a new revision.
-- +goose StatementBegin
CREATE FUNCTION pc.change_windows_retired_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state = 'RETIRED' THEN
        RAISE EXCEPTION 'change window % is retired', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER change_windows_retired_is_final BEFORE UPDATE ON pc.change_windows
    FOR EACH ROW EXECUTE FUNCTION pc.change_windows_retired_is_final();

ALTER TABLE pc.approval_requests
    ADD COLUMN invalidation_key text CHECK (invalidation_key IS NULL OR char_length(invalidation_key) BETWEEN 1 AND 300);
CREATE INDEX approval_requests_invalidation ON pc.approval_requests (org_id, invalidation_key)
    WHERE invalidation_key IS NOT NULL;

-- +goose Down
DROP INDEX pc.approval_requests_invalidation;
ALTER TABLE pc.approval_requests DROP COLUMN invalidation_key;
DROP TABLE pc.change_windows;
DROP FUNCTION pc.change_windows_retired_is_final();
