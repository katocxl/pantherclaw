-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- PantherClaw Hub installs (G0 M23 D102, D104): one row per item version an
-- organization installed, naming the inert draft it made. The draft is made
-- by its kind's own use case in its own transaction, so a row starts PENDING
-- and ends INSTALLED or FAILED; a FAILED one, or one left PENDING by a crash,
-- is retried by installing the same digest again. claim names the worker that
-- holds the row: only it can end the install (D130). range_scenario is not a
-- kind here: no server installs one (D104).
-- +goose Up
CREATE TABLE pc.hub_installs (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    name          text        NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 128),
    version       text        NOT NULL CHECK (octet_length(version) BETWEEN 1 AND 128),
    kind          text        NOT NULL CHECK (kind IN ('policy_template', 'detection_rule', 'tool_package', 'automation')),
    item_sha256   text        NOT NULL CHECK (item_sha256 ~ '^[0-9a-f]{64}$'),
    index_version bigint      NOT NULL CHECK (index_version >= 1),
    -- What the install made, once it ended: empty until then.
    result_kind   text        NOT NULL DEFAULT '' CHECK (result_kind IN ('', 'policy_version', 'custom_rule', 'automation', 'package_version')),
    result_ref    text        NOT NULL DEFAULT '' CHECK (octet_length(result_ref) <= 256),
    installed_by  text        NOT NULL CHECK (char_length(installed_by) BETWEEN 1 AND 200),
    installed_at  timestamptz NOT NULL DEFAULT now(),
    status        text        NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'INSTALLED', 'FAILED')),
    claim         uuid        NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name, version),
    CHECK ((status = 'INSTALLED') = (result_kind <> ''))
);
CREATE INDEX hub_installs_newest ON pc.hub_installs (org_id, id DESC);

ALTER TABLE pc.hub_installs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.hub_installs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.hub_installs
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.hub_installs
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.hub_installs TO pc_app;
GRANT UPDATE (index_version, result_kind, result_ref, installed_by, installed_at, status, claim) ON pc.hub_installs TO pc_app;
GRANT SELECT ON pc.hub_installs TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.hub_installs TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.hub_installs;
