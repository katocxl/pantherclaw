-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- MCP authorization for standard clients (G0 M26 D402, D408) and what runs
-- gain from IdP-native access (D400).
--
-- pc.org_mcp_access: the org's opt-in, off by default, and the gateway URL
-- its protected resources live under. Turning it on waits for a second
-- person; turning it off is at once (D408.5).
--
-- pc.mcp_clients: the allow-list. One client URL (a Client ID Metadata
-- Document) is one enrolled agent, acting through its own instance whose
-- private key no one holds (enrolled_via 'mcp_client', D408.1). That
-- instance is outside every PAP/1 proof path and always reports level 0.
-- The entry keeps the document as the second person confirmed it: its
-- digest, its redirect URIs and its (untrusted) name. A redirect is usable
-- only while both this copy and the live document list it; taking a changed
-- document is a new protected change.
--
-- pc.mcp_authorization_codes and pc.mcp_refresh_tokens hold hashes only. A
-- code is single use and PKCE S256 bound. A refresh token is rotated on
-- every use; reusing a rotated one kills its whole family (D408.4).
--
-- pc.runs gains source 'id_jag': the principal is the user an assertion
-- proves and the launcher is the instance that presented it. Only that
-- source may have a root run with a launcher instance. scope_operations is
-- the assertion's narrowing of the run's grant (D408.3): NULL means the
-- whole grant, and it can only narrow.
-- +goose Up
CREATE TABLE pc.org_mcp_access (
    org_id      uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    enabled     boolean     NOT NULL DEFAULT false,
    gateway_url text        CHECK (gateway_url ~ '^https?://[^/?#@[:space:]]+(/[^?#[:space:]]*[^/?#[:space:]])?$'
                                   AND char_length(gateway_url) <= 512),
    updated_by  uuid        NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (NOT enabled OR gateway_url IS NOT NULL)
);

CREATE TABLE pc.mcp_clients (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    client_url  text        NOT NULL CHECK (client_url ~ '^https://[^/?#@[:space:]]+/[^#[:space:]]*$' AND char_length(client_url) <= 1024),
    agent_id    uuid        NOT NULL,
    instance_id uuid        NOT NULL,
    client_name text        NOT NULL DEFAULT '' CHECK (char_length(client_name) <= 256),
    redirect_uris text[]    NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 16),
    document_digest bytea   NOT NULL CHECK (octet_length(document_digest) = 32),
    state       text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'REMOVED')),
    created_by  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    removed_by  uuid,
    removed_at  timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'REMOVED') = (removed_at IS NOT NULL)),
    CHECK ((removed_by IS NULL) = (removed_at IS NULL))
);
CREATE UNIQUE INDEX mcp_clients_one ON pc.mcp_clients (org_id, client_url) WHERE state <> 'REMOVED';
CREATE UNIQUE INDEX mcp_clients_instance ON pc.mcp_clients (org_id, instance_id);

CREATE TABLE pc.mcp_authorization_codes (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    code_hash      bytea       NOT NULL CHECK (octet_length(code_hash) = 32),
    client_id      uuid        NOT NULL,
    user_id        uuid        NOT NULL,
    redirect_uri   text        NOT NULL CHECK (char_length(redirect_uri) BETWEEN 1 AND 2048),
    code_challenge text        NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    resource       text        NOT NULL CHECK (char_length(resource) BETWEEN 1 AND 1024),
    scope_operations text[],
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    -- The run the code started: a second use ends it (RFC 6749 §4.1.2).
    run_id         uuid,
    PRIMARY KEY (org_id, code_hash),
    FOREIGN KEY (org_id, client_id) REFERENCES pc.mcp_clients (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    CHECK (run_id IS NULL OR used_at IS NOT NULL),
    CONSTRAINT mcp_authorization_codes_short CHECK (expires_at <= created_at + interval '60 seconds')
);
CREATE INDEX mcp_authorization_codes_expiry ON pc.mcp_authorization_codes (expires_at);

CREATE TABLE pc.mcp_refresh_tokens (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    family_id   uuid        NOT NULL,
    token_hash  bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    client_id   uuid        NOT NULL,
    run_id      uuid        NOT NULL,
    resource    text        NOT NULL CHECK (char_length(resource) BETWEEN 1 AND 1024),
    -- ACTIVE, then ROTATED when used; KILLED with its family.
    state       text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'ROTATED', 'KILLED')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, token_hash),
    FOREIGN KEY (org_id, client_id) REFERENCES pc.mcp_clients (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id)
);
-- At most one live token in a family: a parallel rotation loses.
CREATE UNIQUE INDEX mcp_refresh_tokens_live ON pc.mcp_refresh_tokens (org_id, family_id) WHERE state = 'ACTIVE';
CREATE INDEX mcp_refresh_tokens_expiry ON pc.mcp_refresh_tokens (expires_at);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_mcp_access', 'mcp_clients', 'mcp_authorization_codes', 'mcp_refresh_tokens']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.org_mcp_access, pc.mcp_clients, pc.mcp_authorization_codes, pc.mcp_refresh_tokens TO pc_app;
GRANT UPDATE (enabled, gateway_url, updated_by, updated_at) ON pc.org_mcp_access TO pc_app;
GRANT UPDATE (state, activated_at, removed_by, removed_at, client_name, redirect_uris, document_digest) ON pc.mcp_clients TO pc_app;
GRANT UPDATE (used_at, run_id) ON pc.mcp_authorization_codes TO pc_app;
GRANT UPDATE (state) ON pc.mcp_refresh_tokens TO pc_app;
GRANT DELETE ON pc.mcp_authorization_codes, pc.mcp_refresh_tokens TO pc_app;
-- The audit reader sees neither code nor token hashes.
GRANT SELECT ON pc.org_mcp_access, pc.mcp_clients TO pc_audit_ro;
GRANT SELECT (org_id, client_id, user_id, redirect_uri, resource, scope_operations, created_at, expires_at, used_at, run_id)
    ON pc.mcp_authorization_codes TO pc_audit_ro;
GRANT SELECT (org_id, id, family_id, client_id, run_id, resource, state, created_at, expires_at)
    ON pc.mcp_refresh_tokens TO pc_audit_ro;

-- The instance an allow-listed client acts through. It is never attested:
-- it holds no key to attest with.
ALTER TABLE pc.agent_instances
    DROP CONSTRAINT agent_instances_enrolled_via_check,
    ADD CONSTRAINT agent_instances_enrolled_via_check
        CHECK (enrolled_via IN ('enrollment_token', 'attestation', 'discovery', 'mcp_client')) NOT VALID,
    ADD CONSTRAINT agent_instances_mcp_client
        CHECK (enrolled_via <> 'mcp_client' OR (att_level = 1 AND issuer_revision_id IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agent_instances VALIDATE CONSTRAINT agent_instances_enrolled_via_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agent_instances VALIDATE CONSTRAINT agent_instances_mcp_client;

ALTER TABLE pc.runs
    ADD COLUMN scope_operations text[] CHECK (cardinality(scope_operations) BETWEEN 1 AND 64),
    DROP CONSTRAINT runs_principal_source_check,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation', 'id_jag')) NOT VALID,
    DROP CONSTRAINT runs_principal_source,
    ADD CONSTRAINT runs_principal_source CHECK (
        (principal_source IN ('subject_token', 'id_jag') AND principal_user_id IS NOT NULL
            AND subject_issuer IS NOT NULL AND subject_subject IS NOT NULL)
        OR (principal_source NOT IN ('subject_token', 'id_jag') AND subject_issuer IS NULL AND subject_subject IS NULL)) NOT VALID,
    DROP CONSTRAINT runs_child,
    ADD CONSTRAINT runs_child CHECK (
        (parent_run_id IS NULL AND depth = 0 AND principal_source <> 'parent_run'
            AND (launcher_instance_id IS NULL) = (principal_source <> 'id_jag'))
        OR (parent_run_id IS NOT NULL AND depth > 0 AND principal_source = 'parent_run'
            AND launcher_instance_id IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_principal_source_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_principal_source;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_child;

ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card',
                       'mcp_tokens')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;

-- +goose Down
-- The tables of this migration go first; then the runs and instances only
-- it allows (id_jag runs, runs through an mcp_client instance, their child
-- runs, and mcp_client instances), so the old checks hold. A row of another
-- table that still refers to one of them stops the Down, deleting nothing.
-- Row security is lifted for these reads and deletes only, inside this
-- migration's transaction.
DROP TABLE pc.mcp_refresh_tokens;
DROP TABLE pc.mcp_authorization_codes;
DROP TABLE pc.mcp_clients;
DROP TABLE pc.org_mcp_access;
-- +goose StatementBegin
DO $$
DECLARE
    forced   boolean;
    forced_i boolean;
    doomed   uuid[];
    insts    uuid[];
    c        record;
    col      text;
    f        boolean;
    hit      boolean;
BEGIN
    SELECT relforcerowsecurity INTO forced FROM pg_class WHERE oid = 'pc.runs'::regclass;
    SELECT relforcerowsecurity INTO forced_i FROM pg_class WHERE oid = 'pc.agent_instances'::regclass;
    ALTER TABLE pc.runs NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE pc.agent_instances NO FORCE ROW LEVEL SECURITY;
    SELECT coalesce(array_agg(id), '{}') INTO insts FROM pc.agent_instances WHERE enrolled_via = 'mcp_client';
    WITH RECURSIVE tree AS (
        SELECT r.org_id, r.id FROM pc.runs r
        WHERE r.principal_source = 'id_jag' OR r.instance_id = ANY (insts) OR r.launcher_instance_id = ANY (insts)
        UNION
        SELECT ch.org_id, ch.id FROM pc.runs ch JOIN tree t ON ch.org_id = t.org_id AND ch.parent_run_id = t.id)
    SELECT coalesce(array_agg(id), '{}') INTO doomed FROM tree;
    -- Anything else that refers to them is kept: the Down refuses instead.
    FOR c IN SELECT conrelid, conkey, confkey, confrelid FROM pg_constraint
             WHERE contype = 'f' AND confrelid IN ('pc.runs'::regclass, 'pc.agent_instances'::regclass)
               AND conrelid <> 'pc.runs'::regclass LOOP
        SELECT quote_ident(a.attname) INTO col
          FROM unnest(c.conkey, c.confkey) AS k (n, rn)
          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n
          JOIN pg_attribute r ON r.attrelid = c.confrelid AND r.attnum = k.rn
         WHERE r.attname = 'id';
        SELECT relforcerowsecurity INTO f FROM pg_class WHERE oid = c.conrelid;
        EXECUTE format('ALTER TABLE %s NO FORCE ROW LEVEL SECURITY', c.conrelid::regclass);
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %s WHERE %s = ANY ($1))', c.conrelid::regclass, col)
            INTO hit USING CASE WHEN c.confrelid = 'pc.runs'::regclass THEN doomed ELSE insts END;
        IF f THEN
            EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', c.conrelid::regclass);
        END IF;
        IF hit THEN
            RAISE EXCEPTION '00291 Down: % refers to an id_jag run or an mcp_client instance; remove those rows first',
                c.conrelid::regclass;
        END IF;
    END LOOP;
    DELETE FROM pc.runs WHERE id = ANY (doomed);
    DELETE FROM pc.agent_instances WHERE id = ANY (insts);
    IF forced THEN
        ALTER TABLE pc.runs FORCE ROW LEVEL SECURITY;
    END IF;
    IF forced_i THEN
        ALTER TABLE pc.agent_instances FORCE ROW LEVEL SECURITY;
    END IF;
END
$$;
-- +goose StatementEnd
DELETE FROM pc.keys WHERE purpose = 'mcp_tokens';
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card'));
ALTER TABLE pc.runs
    DROP CONSTRAINT runs_child,
    DROP CONSTRAINT runs_principal_source,
    DROP CONSTRAINT runs_principal_source_check,
    DROP COLUMN scope_operations,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation')),
    ADD CONSTRAINT runs_principal_source CHECK (
        (principal_source = 'subject_token' AND principal_user_id IS NOT NULL
            AND subject_issuer IS NOT NULL AND subject_subject IS NOT NULL)
        OR (principal_source <> 'subject_token' AND subject_issuer IS NULL AND subject_subject IS NULL)),
    ADD CONSTRAINT runs_child CHECK (
        (parent_run_id IS NULL AND depth = 0 AND principal_source <> 'parent_run' AND launcher_instance_id IS NULL)
        OR (parent_run_id IS NOT NULL AND depth > 0 AND principal_source = 'parent_run'
            AND launcher_instance_id IS NOT NULL));
ALTER TABLE pc.agent_instances
    DROP CONSTRAINT agent_instances_mcp_client,
    DROP CONSTRAINT agent_instances_enrolled_via_check,
    ADD CONSTRAINT agent_instances_enrolled_via_check CHECK (enrolled_via IN ('enrollment_token', 'attestation', 'discovery'));
