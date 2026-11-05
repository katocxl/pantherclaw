-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Bundle revocations (G0 M37 D1083; FQ37-3; HR-799, HR-800). A revocation
-- comes from an admin (RevokePublisherPin COMPROMISED or
-- RevokeBundleInstall, source ADMIN) or from a publisher-signed statement,
-- submitted (STATEMENT) or fetched daily from an ACTIVE pin's
-- revocations_url (FETCH). A statement is accepted only when a key the org
-- has pinned for that publisher signed it, and is applied once
-- (statement_sha256). Scope KEY revokes a kid; scope BUNDLE revokes a
-- bundle's versions up to max_version, which install then refuses. Every
-- affected install, its items, package versions, custom rules and
-- automations stop in the same transaction that records the revocation.
-- Rows are never changed or deleted (except by org deletion).

-- +goose Up
CREATE TABLE pc.bundle_revocations (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    publisher        text        NOT NULL CHECK (publisher ~ '^[a-z][a-z0-9-]{2,31}$'),
    statement_sha256 text        CHECK (statement_sha256 IS NULL OR statement_sha256 ~ '^[0-9a-f]{64}$'),
    scope            text        NOT NULL CHECK (scope IN ('KEY', 'BUNDLE')),
    kid              text        CHECK (kid IS NULL OR kid ~ '^publisher-[a-z][a-z0-9-]{2,31}-[A-Za-z0-9_-]{22}$'),
    name             text        CHECK (name IS NULL OR name ~ '^ext\.[a-z][a-z0-9-]{2,31}\.[a-z0-9][a-z0-9-]{0,62}$'),
    max_version      text        CHECK (max_version IS NULL
                                        OR max_version ~ '^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$'),
    signed_at        timestamptz,
    received_at      timestamptz NOT NULL DEFAULT now(),
    applied_at       timestamptz NOT NULL DEFAULT now(),
    source           text        NOT NULL CHECK (source IN ('ADMIN', 'STATEMENT', 'FETCH')),
    PRIMARY KEY (org_id, id),
    CHECK ((scope = 'KEY') = (kid IS NOT NULL)),
    CHECK ((scope = 'BUNDLE') = (name IS NOT NULL AND max_version IS NOT NULL)),
    CHECK ((source = 'ADMIN') = (statement_sha256 IS NULL)),
    CHECK ((source = 'ADMIN') = (signed_at IS NULL))
);
-- One statement is applied once.
CREATE UNIQUE INDEX bundle_revocations_statement ON pc.bundle_revocations (org_id, statement_sha256)
    WHERE statement_sha256 IS NOT NULL;
CREATE INDEX bundle_revocations_name ON pc.bundle_revocations (org_id, name) WHERE scope = 'BUNDLE';
CREATE INDEX bundle_revocations_kid ON pc.bundle_revocations (org_id, kid) WHERE scope = 'KEY';

ALTER TABLE pc.bundle_revocations ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.bundle_revocations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.bundle_revocations
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.bundle_revocations
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

GRANT SELECT, INSERT ON pc.bundle_revocations TO pc_app;
GRANT SELECT ON pc.bundle_revocations TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.bundle_revocations TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.bundle_revocations;
