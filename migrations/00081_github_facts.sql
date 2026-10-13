-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- GitHub facts, identities, a connection's GitHub installation and the
-- organisation scan (G0 M8 track G, slices G3, G4 and G5; decisions 3 and 5,
-- HR-160, HR-203, HR-207, HR-209).
--
-- - A fact provider is bound to exactly one of a service account (it pushes
--   facts through the API, M4) or a gateway and one of its connections: the
--   gateway reads the connection's system of record before a decision (for
--   GitHub: the pull request's head and people, reviews, checks, branch
--   rules and deploy triggers) and reports them over its mTLS identity. At
--   most one active provider per connection. A person registers either kind
--   (fact.provider.manage, human only).
-- - Structured facts (value type object, at most 16 KiB): one GitHub read is
--   one fact with several members.
-- - github_identities links a user to a GitHub user id, so independence can
--   exclude a pull request's author, committers and pushers (HR-207). Links
--   are made by a person holding github.identity.manage and audited.
-- - connection_github records the GitHub App installation behind a
--   connection (G3; the brief places it in 00080, which shipped before it):
--   the App, the installation, its account, and the installation's
--   permissions and repository selection as last read. The account is what
--   a target's owner must be (WRONG_ACCOUNT, ADR-0021); M9 (F048) reads the
--   rest.
-- - github_scan_runs records an organisation scan: the lease it ran under,
--   what it found and which sources it could and could not read (F450).
-- - Discoveries gain the source github_scan, and the M7 verification tasks
--   the purpose org_scan, a lease without a transaction like target_log. A
--   finding's key is unique within its source, so a person's scan never
--   matches, overwrites or pre-seeds a finding of the gateway's org scan.
--   The two verification checks are named so that 00084 (C2) can replace
--   them again with connection_test.

-- +goose Up
ALTER TABLE pc.fact_providers
    ALTER COLUMN service_account_id DROP NOT NULL,
    ADD COLUMN gateway_id uuid,
    ADD COLUMN connection_id uuid,
    ADD CONSTRAINT fact_providers_one_source CHECK (
        (service_account_id IS NOT NULL AND gateway_id IS NULL AND connection_id IS NULL)
        OR (service_account_id IS NULL AND gateway_id IS NOT NULL AND connection_id IS NOT NULL)),
    ADD CONSTRAINT fact_providers_gateway_fk FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    ADD CONSTRAINT fact_providers_connection_fk FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id);
CREATE UNIQUE INDEX fact_providers_connection ON pc.fact_providers (org_id, connection_id) WHERE connection_id IS NOT NULL AND state = 'ACTIVE';

ALTER TABLE pc.fact_declarations
    DROP CONSTRAINT fact_declarations_value_type_check,
    ADD CONSTRAINT fact_declarations_value_type CHECK (value_type IN ('boolean', 'integer', 'decimal', 'money', 'identifier', 'timestamp', 'object'));
ALTER TABLE pc.facts
    DROP CONSTRAINT facts_value_check,
    ADD CONSTRAINT facts_value_size CHECK (octet_length(value) BETWEEN 2 AND 16640);

CREATE TABLE pc.connection_github (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id        uuid        NOT NULL,
    app_client_id        text        NOT NULL CHECK (app_client_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    installation_id      bigint      NOT NULL CHECK (installation_id > 0),
    account_login        text        NOT NULL CHECK (account_login ~ '^[a-z0-9][a-z0-9-]{0,38}$'),
    account_id           bigint      CHECK (account_id > 0),
    permissions          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(permissions) = 'object' AND octet_length(permissions::text) <= 4096),
    repository_selection text        CHECK (repository_selection IN ('all', 'selected')),
    read_at              timestamptz,
    updated_by           text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CHECK ((read_at IS NULL) = (repository_selection IS NULL))
);

CREATE TABLE pc.github_identities (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    user_id        uuid        NOT NULL,
    github_login   text        NOT NULL CHECK (github_login ~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'),
    github_user_id bigint      NOT NULL CHECK (github_user_id > 0),
    linked_by      text        NOT NULL CHECK (char_length(linked_by) BETWEEN 1 AND 128),
    linked_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, github_user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id)
);
CREATE INDEX github_identities_user ON pc.github_identities (org_id, user_id);

CREATE TABLE pc.github_scan_runs (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    connection_id   uuid        NOT NULL,
    verification_id uuid,
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'RUNNING', 'DONE', 'FAILED')),
    counts          jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(counts) = 'object' AND octet_length(counts::text) <= 4096),
    scanned         text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(scanned) <= 256),
    not_scanned     jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(not_scanned) = 'object' AND octet_length(not_scanned::text) <= 16384),
    started_by      text        NOT NULL CHECK (char_length(started_by) BETWEEN 1 AND 128),
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    CHECK ((state IN ('DONE', 'FAILED')) = (finished_at IS NOT NULL))
);
CREATE INDEX github_scan_runs_recent ON pc.github_scan_runs (org_id, connection_id, created_at DESC);

-- A scan run only moves forward (PENDING, RUNNING, then DONE or FAILED),
-- a finished run never changes, and a run keeps the lease it was given.
-- +goose StatementBegin
CREATE FUNCTION pc.github_scan_runs_forward() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.state IN ('DONE', 'FAILED') THEN
        RAISE EXCEPTION 'scan run % is finished', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state <> 'PENDING' THEN
        RAISE EXCEPTION 'scan run % only moves forward', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.verification_id IS NOT NULL AND NEW.verification_id IS DISTINCT FROM OLD.verification_id THEN
        RAISE EXCEPTION 'scan run % keeps its lease', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER github_scan_runs_forward BEFORE UPDATE ON pc.github_scan_runs
    FOR EACH ROW EXECUTE FUNCTION pc.github_scan_runs_forward();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connection_github', 'github_identities', 'github_scan_runs']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- A connection's installation is recorded and read again; identities are
-- linked and unlinked (deleted, audited); scan runs only move forward.
GRANT SELECT, INSERT, DELETE ON pc.github_identities TO pc_app;
GRANT SELECT, INSERT ON pc.github_scan_runs TO pc_app;
GRANT UPDATE (state, counts, scanned, not_scanned, verification_id, finished_at) ON pc.github_scan_runs TO pc_app;
GRANT SELECT, INSERT, UPDATE ON pc.connection_github TO pc_app;
GRANT SELECT ON pc.connection_github, pc.github_identities, pc.github_scan_runs TO pc_audit_ro;

ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_source_check,
    DROP CONSTRAINT discoveries_source_key,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan')),
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan') AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL)),
    DROP CONSTRAINT discoveries_org_id_scan_key_key,
    ADD CONSTRAINT discoveries_source_scan_key UNIQUE (org_id, source, scan_key);

ALTER TABLE pc.verifications
    DROP CONSTRAINT verifications_purpose_check,
    DROP CONSTRAINT verifications_check,
    ADD CONSTRAINT verifications_purpose CHECK (purpose IN ('follow_up', 'reconcile', 'target_log', 'org_scan')),
    ADD CONSTRAINT verifications_transaction CHECK ((purpose IN ('target_log', 'org_scan')) = (transaction_id IS NULL));

-- +goose Down
-- Rows only this migration allows go first, so that the earlier rules hold
-- again: org scans and their findings, gateway fact providers with their
-- declarations and facts, and object or large facts. Row security is lifted
-- for these deletes only.
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['verifications', 'discoveries', 'fact_providers', 'fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I NO FORCE ROW LEVEL SECURITY', t);
    END LOOP;
    DROP TABLE pc.github_scan_runs;
    DROP FUNCTION pc.github_scan_runs_forward();
    DELETE FROM pc.verifications WHERE purpose = 'org_scan';
    DELETE FROM pc.discoveries WHERE source = 'github_scan';
    DELETE FROM pc.facts f WHERE octet_length(f.value) > 1024
        OR f.provider_id IN (SELECT id FROM pc.fact_providers WHERE gateway_id IS NOT NULL)
        OR EXISTS (SELECT 1 FROM pc.fact_declarations d
            WHERE d.org_id = f.org_id AND d.provider_id = f.provider_id AND d.name = f.name AND d.value_type = 'object');
    DELETE FROM pc.fact_declarations WHERE value_type = 'object'
        OR provider_id IN (SELECT id FROM pc.fact_providers WHERE gateway_id IS NOT NULL);
    DELETE FROM pc.fact_providers WHERE gateway_id IS NOT NULL;
    FOREACH t IN ARRAY ARRAY['verifications', 'discoveries', 'fact_providers', 'fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.verifications
    DROP CONSTRAINT verifications_transaction,
    DROP CONSTRAINT verifications_purpose,
    ADD CONSTRAINT verifications_purpose_check CHECK (purpose IN ('follow_up', 'reconcile', 'target_log')),
    ADD CONSTRAINT verifications_check CHECK ((purpose = 'target_log') = (transaction_id IS NULL));
ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_source_scan_key,
    ADD CONSTRAINT discoveries_org_id_scan_key_key UNIQUE (org_id, scan_key),
    DROP CONSTRAINT discoveries_source_key,
    DROP CONSTRAINT discoveries_source,
    ADD CONSTRAINT discoveries_source_check CHECK (source IN ('gateway', 'scan')),
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source = 'scan' AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL));
DROP TABLE pc.github_identities;
DROP TABLE pc.connection_github;
ALTER TABLE pc.facts
    DROP CONSTRAINT facts_value_size,
    ADD CONSTRAINT facts_value_check CHECK (octet_length(value) BETWEEN 2 AND 1024);
ALTER TABLE pc.fact_declarations
    DROP CONSTRAINT fact_declarations_value_type,
    ADD CONSTRAINT fact_declarations_value_type_check CHECK (value_type IN ('boolean', 'integer', 'decimal', 'money', 'identifier', 'timestamp'));
DROP INDEX pc.fact_providers_connection;
ALTER TABLE pc.fact_providers
    DROP CONSTRAINT fact_providers_connection_fk,
    DROP CONSTRAINT fact_providers_gateway_fk,
    DROP CONSTRAINT fact_providers_one_source,
    DROP COLUMN connection_id,
    DROP COLUMN gateway_id,
    ALTER COLUMN service_account_id SET NOT NULL;
