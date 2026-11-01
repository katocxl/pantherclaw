-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- The directory an enterprise identity provider keeps in step over SCIM
-- (G0 M26 D405, D406; F918). The protocol is in the private enterprise
-- package; the tables stay here, so the core owns what they may hold.
--
-- A SCIM token is bound to the one issuer it provisions: it sees and
-- changes only that issuer's users and groups. Only the token's hash is
-- stored. A group maps only to non-admin roles: Org Admin, Security Admin
-- and Scope Admin bindings stay in PantherClaw (R-08, HR-630), which the
-- checks here hold even if the code above them is wrong.
-- +goose Up
CREATE TABLE pc.groups (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    issuer       text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    display_name text        NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    external_id  text        CHECK (char_length(external_id) BETWEEN 1 AND 256),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, issuer, display_name)
);

CREATE TABLE pc.group_members (
    org_id   uuid        NOT NULL REFERENCES pc.orgs (id),
    group_id uuid        NOT NULL,
    user_id  uuid        NOT NULL,
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, group_id, user_id),
    FOREIGN KEY (org_id, group_id) REFERENCES pc.groups (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);
CREATE INDEX group_members_user ON pc.group_members (org_id, user_id);

-- One role at one scope for every member of one group. Only an applied
-- protected change writes a row (D406).
CREATE TABLE pc.group_role_mappings (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    group_id         uuid        NOT NULL,
    role             text        NOT NULL CHECK (role ~ '^[a-z][a-z_]{0,62}$'
                                                 AND role NOT IN ('org_admin', 'security_admin', 'scope_admin')),
    scope_type       text        NOT NULL CHECK (scope_type IN ('ORG', 'BUSINESS_UNIT', 'TEAM', 'ENVIRONMENT')),
    business_unit_id uuid,
    team_id          uuid,
    environment_id   uuid,
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CONSTRAINT group_role_mappings_scope CHECK (CASE scope_type
        WHEN 'ORG' THEN business_unit_id IS NULL AND team_id IS NULL AND environment_id IS NULL
        WHEN 'BUSINESS_UNIT' THEN business_unit_id IS NOT NULL AND team_id IS NULL AND environment_id IS NULL
        WHEN 'TEAM' THEN team_id IS NOT NULL AND business_unit_id IS NULL AND environment_id IS NULL
        WHEN 'ENVIRONMENT' THEN environment_id IS NOT NULL AND business_unit_id IS NULL AND team_id IS NULL
    END),
    UNIQUE NULLS NOT DISTINCT (org_id, group_id, role, scope_type, business_unit_id, team_id, environment_id),
    FOREIGN KEY (org_id, group_id) REFERENCES pc.groups (org_id, id) ON DELETE CASCADE,
    FOREIGN KEY (org_id, business_unit_id) REFERENCES pc.business_units (org_id, id),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id),
    FOREIGN KEY (org_id, environment_id) REFERENCES pc.environments (org_id, id)
);

-- subject_attribute names the SCIM attribute that holds the identity's
-- subject at sign-in: pc.users is one (issuer, subject).
CREATE TABLE pc.scim_tokens (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    name              text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    issuer            text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 512),
    subject_attribute text        NOT NULL CHECK (subject_attribute IN ('userName', 'externalId')),
    secret_hash       bytea       NOT NULL CHECK (octet_length(secret_hash) = 32),
    hint              text        NOT NULL CHECK (char_length(hint) BETWEEN 1 AND 16),
    state             text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'REVOKED')),
    created_by        text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    revoked_at        timestamptz,
    last_used_at      timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, secret_hash),
    UNIQUE (org_id, name),
    CHECK ((state = 'REVOKED') = (revoked_at IS NOT NULL))
);

-- What SCIM needs of a user that pc.users has no place for. disabled_by_scim
-- is what lets SCIM re-enable a user: a person who disabled someone in
-- PantherClaw is never overruled by the next sync. deleted_at hides the
-- user from SCIM (RFC 7644 3.6); the pc.users row stays, disabled.
CREATE TABLE pc.scim_users (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    user_id          uuid        NOT NULL,
    external_id      text        CHECK (char_length(external_id) BETWEEN 1 AND 256),
    disabled_by_scim boolean     NOT NULL DEFAULT false,
    deleted_at       timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);

-- A binding that a group mapping made. Reconciling adds and removes only
-- these, so a binding a person made is never touched, and none is ever an
-- admin role (D406).
ALTER TABLE pc.role_bindings ADD COLUMN provisioned boolean NOT NULL DEFAULT false
    CONSTRAINT role_bindings_provisioned_role CHECK (NOT provisioned OR role NOT IN ('org_admin', 'security_admin', 'scope_admin'));

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['groups', 'group_members', 'group_role_mappings', 'scim_tokens', 'scim_users']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($q$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$q$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
    END LOOP;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.groups, pc.group_members, pc.group_role_mappings, pc.scim_tokens, pc.scim_users TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

GRANT SELECT, INSERT, DELETE ON pc.groups, pc.group_members, pc.group_role_mappings TO pc_app;
GRANT SELECT, INSERT ON pc.scim_tokens, pc.scim_users TO pc_app;
GRANT UPDATE (display_name, external_id, updated_at) ON pc.groups TO pc_app;
GRANT UPDATE (state, revoked_at, last_used_at) ON pc.scim_tokens TO pc_app;
GRANT UPDATE (external_id, disabled_by_scim, deleted_at, updated_at) ON pc.scim_users TO pc_app;
-- The hash stays out of the auditors' read.
GRANT SELECT (org_id, id, name, issuer, subject_attribute, hint, state, created_by, created_at, expires_at, revoked_at, last_used_at)
    ON pc.scim_tokens TO pc_audit_ro;
GRANT SELECT ON pc.groups, pc.group_members, pc.group_role_mappings, pc.scim_users TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.role_bindings DROP COLUMN provisioned;
DROP TABLE pc.scim_users;
DROP TABLE pc.scim_tokens;
DROP TABLE pc.group_role_mappings;
DROP TABLE pc.group_members;
DROP TABLE pc.groups;
