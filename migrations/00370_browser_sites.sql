-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Browser sites (G0 M33 D976; HR-749). The sites an org lists for its
-- agents' managed browsers. A pc.browser action whose target host matches
-- no site holds for a person (SITE_NOT_LISTED); an empty list holds every
-- site (D977). A site matches its host, and with include_subdomains every
-- name under it. compare marks a site for the gateway's cloaking compare
-- (D986), and click_selectors are the admin's marked-click rules (D980).
-- Adding a row loosens the hold, so it is a protected change applied on
-- confirm; removing one is immediate, as for pc.owned_accounts (00342).
-- Formats are also checked in Go.

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION pc.valid_browser_selectors(s text[]) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT cardinality(s) <= 16
       AND NOT EXISTS (SELECT 1 FROM unnest(s) e WHERE e IS NULL OR char_length(e) NOT BETWEEN 1 AND 256)
$$;
-- +goose StatementEnd

CREATE TABLE pc.browser_sites (
    id                 uuid        NOT NULL PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    -- A lower-case DNS name of at least two labels: no IP, no port.
    host               text        NOT NULL CHECK (char_length(host) <= 253
                                       AND host ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
                                       AND host !~ '^[0-9.]+$'),
    include_subdomains boolean     NOT NULL,
    compare            boolean     NOT NULL DEFAULT false,
    click_selectors    text[]      NOT NULL DEFAULT '{}' CHECK (pc.valid_browser_selectors(click_selectors)),
    note               text        NOT NULL DEFAULT '' CHECK (char_length(note) <= 256),
    created_at         timestamptz NOT NULL DEFAULT now(),
    created_by         text        NOT NULL,
    UNIQUE (org_id, host, include_subdomains)
);

ALTER TABLE pc.browser_sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.browser_sites FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.browser_sites
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.browser_sites
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT, DELETE ON pc.browser_sites TO pc_app;
GRANT SELECT ON pc.browser_sites TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.browser_sites TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.browser_sites;
DROP FUNCTION pc.valid_browser_selectors(text[]);
