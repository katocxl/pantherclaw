-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The policy publish gate (G0 M11.1 design decisions 1, 6 and 11; HR-230,
-- HR-231). A version moves DRAFT -> VALIDATED -> TESTED -> PUBLISHED ->
-- SUPERSEDED, each step a conditional UPDATE (HR-004); VALIDATED and
-- TESTED never go back. A version carries the SHA-256 of its content (the
-- bundle without its version number); a row from before this migration has
-- none, so it can never be validated, tested or published again (an org's
-- published one stays published until a new version supersedes it).
-- Publishing needs a passing test run of exactly that content, recorded
-- in pc.policy_test_runs; the publish UPDATE itself checks it.
--
-- A change that loosens the published policy waits as a change request
-- (PUBLISH; S2 adds ROLLOUT and S3 EXCEPTION) until enough people holding
-- policy.publish confirm it, each with a security key in M5 part 2's
-- BINDING ceremony over the request's binding: distinct persons and
-- distinct keys. A BINDING ceremony therefore names exactly one of an
-- approval request, a batch, a reconciliation and a policy change request.
--
-- pc_app may UPDATE only the columns the conditional transitions need
-- (G0 M11.1 design decision 22): policy_versions (state, published_by,
-- published_at), as granted in 00021, and policy_change_requests (state,
-- decided_at, decided_reason). Ids, content, digests, bindings and
-- requesters never change; validations, test runs and confirmations are
-- insert-only.

-- +goose Up
ALTER TABLE pc.policy_versions
    ADD COLUMN content_digest bytea CHECK (octet_length(content_digest) = 32),
    DROP CONSTRAINT policy_versions_state_check,
    ADD CONSTRAINT policy_versions_state_check
        CHECK (state IN ('DRAFT', 'VALIDATED', 'TESTED', 'PUBLISHED', 'SUPERSEDED')) NOT VALID,
    DROP CONSTRAINT policy_versions_published,
    ADD CONSTRAINT policy_versions_published
        CHECK ((state IN ('DRAFT', 'VALIDATED', 'TESTED')) = (published_at IS NULL)
               AND (published_at IS NULL) = (published_by IS NULL)) NOT VALID,
    ADD CONSTRAINT policy_versions_digest
        CHECK (state NOT IN ('VALIDATED', 'TESTED') OR content_digest IS NOT NULL) NOT VALID;
-- squawk: pc.policy_versions holds a few versions per org, so validating each
-- constraint takes its lock briefly; goose runs each migration in one
-- transaction (.squawk.toml), so the validation cannot move to its own.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.policy_versions VALIDATE CONSTRAINT policy_versions_state_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.policy_versions VALIDATE CONSTRAINT policy_versions_published;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.policy_versions VALIDATE CONSTRAINT policy_versions_digest;

-- One validation of a version: the content, active definitions and fact
-- catalog it ran against, and its findings.
CREATE TABLE pc.policy_validations (
    org_id             uuid        NOT NULL,
    id                 uuid        NOT NULL,
    version_id         uuid        NOT NULL,
    content_digest     bytea       NOT NULL CHECK (octet_length(content_digest) = 32),
    definitions_digest bytea       NOT NULL CHECK (octet_length(definitions_digest) = 32),
    catalog_digest     bytea       NOT NULL CHECK (octet_length(catalog_digest) = 32),
    passed             boolean     NOT NULL,
    findings           jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(findings) = 'array'
                                                                AND octet_length(findings::text) <= 262144),
    run_by             text        NOT NULL CHECK (char_length(run_by) BETWEEN 1 AND 128),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.policy_versions (org_id, id)
);
CREATE INDEX policy_validations_version ON pc.policy_validations (org_id, version_id, created_at DESC);

-- One scenario test run of a version (HR-044): cases, mutants and the
-- survivors.
CREATE TABLE pc.policy_test_runs (
    org_id             uuid        NOT NULL,
    id                 uuid        NOT NULL,
    version_id         uuid        NOT NULL,
    content_digest     bytea       NOT NULL CHECK (octet_length(content_digest) = 32),
    definitions_digest bytea       NOT NULL CHECK (octet_length(definitions_digest) = 32),
    catalog_digest     bytea       NOT NULL CHECK (octet_length(catalog_digest) = 32),
    passed             boolean     NOT NULL,
    cases              integer     NOT NULL CHECK (cases >= 0),
    mutants            integer     NOT NULL CHECK (mutants >= 0),
    survivors          integer     NOT NULL CHECK (survivors >= 0),
    results            jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(results) = 'object'
                                                                AND octet_length(results::text) <= 1048576),
    run_by             text        NOT NULL CHECK (char_length(run_by) BETWEEN 1 AND 128),
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.policy_versions (org_id, id)
);
CREATE INDEX policy_test_runs_version ON pc.policy_test_runs (org_id, version_id, created_at DESC);

-- A change waiting for confirmations (design decision 11). expires_at is
-- 24 hours after creation by the database clock; expiry is applied when
-- the request is next used.
CREATE TABLE pc.policy_change_requests (
    org_id          uuid        NOT NULL,
    id              uuid        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('PUBLISH', 'ROLLOUT', 'EXCEPTION')),
    subject_id      uuid        NOT NULL,
    base_version_id uuid,
    binding         bytea       NOT NULL CHECK (octet_length(binding) = 32),
    summary         jsonb       NOT NULL CHECK (octet_length(summary::text) <= 262144),
    required        smallint    NOT NULL CHECK (required BETWEEN 1 AND 2),
    state           text        NOT NULL DEFAULT 'PENDING'
                                CHECK (state IN ('PENDING', 'APPROVED', 'DECLINED', 'EXPIRED', 'VOIDED')),
    requested_by    text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    decided_at      timestamptz,
    decided_reason  text        CHECK (char_length(decided_reason) BETWEEN 1 AND 500),
    PRIMARY KEY (org_id, id),
    CHECK (expires_at = created_at + interval '24 hours'),
    CHECK ((state = 'PENDING') = (decided_at IS NULL))
);
CREATE UNIQUE INDEX policy_change_requests_one_pending ON pc.policy_change_requests (org_id, kind, subject_id)
    WHERE state = 'PENDING';
CREATE INDEX policy_change_requests_created ON pc.policy_change_requests (org_id, created_at DESC);

-- One person's confirmation of a change request, with the security key
-- that signed its binding: distinct persons and distinct keys.
CREATE TABLE pc.policy_change_confirmations (
    org_id        uuid        NOT NULL,
    request_id    uuid        NOT NULL,
    principal_id  uuid        NOT NULL,
    credential_id uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, request_id, principal_id),
    UNIQUE (org_id, request_id, credential_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.policy_change_requests (org_id, id),
    FOREIGN KEY (org_id, principal_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, credential_id) REFERENCES pc.webauthn_credentials (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['policy_validations', 'policy_test_runs', 'policy_change_requests', 'policy_change_confirmations']
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

GRANT SELECT, INSERT ON pc.policy_validations, pc.policy_test_runs, pc.policy_change_requests,
    pc.policy_change_confirmations TO pc_app;
GRANT UPDATE (state, decided_at, decided_reason) ON pc.policy_change_requests TO pc_app;
GRANT SELECT ON pc.policy_validations, pc.policy_test_runs, pc.policy_change_requests,
    pc.policy_change_confirmations TO pc_audit_ro;

-- The confirmation ceremony of a change request. pc_app's table-level
-- SELECT and INSERT on webauthn_ceremonies (00030) cover the new column.
-- squawk: pc.webauthn_ceremonies rows live 5 minutes, so the table is small and
-- adding and validating the constraints locks it briefly; goose runs each
-- migration in one transaction (.squawk.toml), so CONCURRENTLY and a separate
-- VALIDATE are not possible. squawk reads an ignore on the line above the
-- clause it flags.
ALTER TABLE pc.webauthn_ceremonies
    ADD COLUMN policy_change_request_id uuid,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id) <= 1) NOT VALID,
    -- squawk-ignore constraint-missing-not-valid, adding-foreign-key-constraint
    ADD CONSTRAINT webauthn_ceremonies_policy_change_fk FOREIGN KEY (org_id, policy_change_request_id)
        REFERENCES pc.policy_change_requests (org_id, id);
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX webauthn_ceremonies_binding_policy_change
    ON pc.webauthn_ceremonies (org_id, policy_change_request_id, user_id)
    WHERE policy_change_request_id IS NOT NULL AND consumed_at IS NULL;

-- +goose Down
DELETE FROM pc.webauthn_ceremonies WHERE policy_change_request_id IS NOT NULL;
DROP INDEX pc.webauthn_ceremonies_binding_policy_change;
ALTER TABLE pc.webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_policy_change_fk,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    DROP COLUMN policy_change_request_id,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id) <= 1) NOT VALID;
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
DROP TABLE pc.policy_change_confirmations;
DROP TABLE pc.policy_change_requests;
DROP TABLE pc.policy_test_runs;
DROP TABLE pc.policy_validations;
UPDATE pc.policy_versions SET state = 'DRAFT' WHERE state IN ('VALIDATED', 'TESTED');
ALTER TABLE pc.policy_versions
    DROP CONSTRAINT policy_versions_digest,
    DROP CONSTRAINT policy_versions_published,
    DROP CONSTRAINT policy_versions_state_check,
    DROP COLUMN content_digest,
    ADD CONSTRAINT policy_versions_state_check CHECK (state IN ('DRAFT', 'PUBLISHED', 'SUPERSEDED')),
    ADD CONSTRAINT policy_versions_published CHECK ((state = 'DRAFT') = (published_at IS NULL)
                                                    AND (published_at IS NULL) = (published_by IS NULL));
