-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- SDK connections, capability declarations and connection tests (G0 M8
-- track C: C1, C2; F346, F350, F353, F354, F358; HR-200, HR-210). Track C's
-- only migration, so it holds everything track C stores:
--
-- * connection_capabilities: what a connection declares it supports (from
--   its kind, access mode and package), and the subset a person approved.
--   A new connection revision supersedes the current declaration.
-- * connection_tests: each test of a connection. A credential test checks
--   what the connection depends on without calling the target; a read test
--   and a target_verifier test are leased to the gateway as verification
--   tasks of purpose connection_test (M7's machinery) and reach the target.
--   M9 lifts the cooperative cap for an operation only on a passing
--   target_verifier test (HR-210). A test result is evidence: pc_app only
--   moves an open test to its result and never deletes one.
-- * tool_observations: the OBSERVE_ONLY records of tools an agent SDK ran
--   without a mapping (HR-200), which M9's route inventory reads. The tool
--   name is untrusted and only its input's digest is kept. Append-only.
-- * the verification task purpose connection_test, added to the purposes
--   the checks already allow whatever migrations came before (00060, and
--   00081 (track G) when it is there), under their own names; Down removes
--   it the same way, after deleting connection test tasks.
-- * an index on transactions by connection for connection health.

-- +goose Up
CREATE TABLE pc.connection_capabilities (
    org_id              uuid        NOT NULL REFERENCES pc.orgs (id),
    id                  uuid        NOT NULL,
    connection_id       uuid        NOT NULL,
    connection_revision integer     NOT NULL CHECK (connection_revision > 0),
    declaration         jsonb       NOT NULL CHECK (jsonb_typeof(declaration) = 'object' AND octet_length(declaration::text) <= 65536),
    declaration_sha256  bytea       NOT NULL CHECK (octet_length(declaration_sha256) = 32),
    approved            jsonb       CHECK (approved IS NULL OR (jsonb_typeof(approved) = 'object' AND octet_length(approved::text) <= 65536)),
    state               text        NOT NULL DEFAULT 'PROPOSED' CHECK (state IN ('PROPOSED', 'APPROVED', 'SUPERSEDED')),
    proposed_at         timestamptz NOT NULL DEFAULT now(),
    approved_by         text        CHECK (approved_by IS NULL OR char_length(approved_by) BETWEEN 1 AND 100),
    approved_at         timestamptz,
    superseded_at       timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CHECK ((approved IS NULL) = (approved_by IS NULL) AND (approved_by IS NULL) = (approved_at IS NULL)),
    CHECK ((state = 'APPROVED') = (approved IS NOT NULL) OR state = 'SUPERSEDED'),
    CHECK ((state = 'SUPERSEDED') = (superseded_at IS NOT NULL))
);
-- At most one current declaration per connection.
CREATE UNIQUE INDEX connection_capabilities_current ON pc.connection_capabilities (org_id, connection_id)
    WHERE state <> 'SUPERSEDED';

CREATE TABLE pc.connection_tests (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    connection_id   uuid        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('credential', 'read', 'target_verifier')),
    -- PENDING and RUNNING are open; DONE has a result; FAILED could not run
    -- (the lease expired, the gateway never claimed it).
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'RUNNING', 'DONE', 'FAILED')),
    -- The gateway that ran a leased test, and its lease.
    gateway_id      uuid,
    verification_id uuid,
    result          text        CHECK (result IS NULL OR result IN ('PASSED', 'FAILED')),
    -- One {check, passed, detail} object per check, in order.
    checks          jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(checks) = 'array' AND octet_length(checks::text) <= 16384),
    -- The SHA-256 of the gateway's detailed report, which is not stored.
    detail_sha256   bytea       CHECK (detail_sha256 IS NULL OR octet_length(detail_sha256) = 32),
    requested_by    text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 100),
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, gateway_id) REFERENCES pc.gateways (org_id, id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    CHECK ((kind = 'credential') = (verification_id IS NULL)),
    CHECK ((state IN ('DONE', 'FAILED')) = (finished_at IS NOT NULL)),
    CHECK ((state = 'DONE') = (result IS NOT NULL))
);
CREATE INDEX connection_tests_latest ON pc.connection_tests (org_id, connection_id, created_at DESC);
CREATE UNIQUE INDEX connection_tests_verification ON pc.connection_tests (org_id, verification_id) WHERE verification_id IS NOT NULL;

CREATE TABLE pc.tool_observations (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    run_id        uuid        NOT NULL,
    instance_id   uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    -- UNTRUSTED: the name the agent SDK sent.
    tool          text        NOT NULL CHECK (octet_length(tool) BETWEEN 1 AND 128),
    input_sha256  bytea       NOT NULL CHECK (octet_length(input_sha256) = 32),
    channel       text        NOT NULL CHECK (channel = 'sdk'),
    observed_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);
CREATE INDEX tool_observations_connection ON pc.tool_observations (org_id, connection_id, observed_at);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connection_capabilities', 'connection_tests', 'tool_observations'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting(''app.org_id'', true), '''')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting(''app.org_id'', true), '''')::uuid))', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.connection_capabilities, pc.connection_tests, pc.tool_observations TO pc_app;
GRANT UPDATE (approved, state, approved_by, approved_at, superseded_at) ON pc.connection_capabilities TO pc_app;
GRANT UPDATE (state, gateway_id, result, checks, detail_sha256, finished_at) ON pc.connection_tests TO pc_app;
GRANT SELECT ON pc.connection_capabilities, pc.connection_tests, pc.tool_observations TO pc_audit_ro;

-- Connection tests reach the target as verification tasks of their own
-- purpose, which belong to no transaction. The two checks that list the
-- purposes are rebuilt under their own names from their own lists plus
-- connection_test, so every purpose already allowed (00060's, and 00081's
-- org_scan when it is there) stays allowed whatever the order the
-- migrations came in; Down removes connection_test the same way. Any
-- other shape of those checks fails the migration instead of being
-- guessed at.
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
    n        integer := 0;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%purpose%' AND pg_get_constraintdef(oid) NOT LIKE '%window_start%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i);
        IF purposes IS NULL OR purposes LIKE '%connection_test%' THEN
            RAISE EXCEPTION '00084: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        purposes := purposes || ', ''connection_test''';
        IF c.def LIKE '%transaction_id IS NULL%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((purpose IN (%s)) = (transaction_id IS NULL)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSIF c.def LIKE '%follow_up%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSE
            RAISE EXCEPTION '00084: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        EXECUTE format('ALTER TABLE pc.verifications VALIDATE CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 2 THEN
        RAISE EXCEPTION '00084: found % purpose checks on pc.verifications, not 2', n;
    END IF;
END
$$;
-- +goose StatementEnd

-- Connection health reads the recent transactions through a connection:
-- delivery failures and the agents that depend on it.
CREATE INDEX transactions_connection ON pc.transactions (org_id, connection_id, created_at)
    WHERE connection_id IS NOT NULL;

-- +goose Down
DROP INDEX pc.transactions_connection;
DROP TABLE pc.tool_observations;
DROP TABLE pc.connection_tests;
DROP TABLE pc.connection_capabilities;
-- Connection test tasks go before their purpose does. RLS is forced even
-- for the owner, so it is lifted for these two deletes only, inside this
-- migration's transaction; no other session ever sees it lifted.
ALTER TABLE pc.observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.observations o USING pc.verifications v
 WHERE o.org_id = v.org_id AND o.verification_id = v.id AND v.purpose = 'connection_test';
DELETE FROM pc.verifications WHERE purpose = 'connection_test';
ALTER TABLE pc.verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.observations FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%connection_test%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i)
         WHERE m.v[1] <> 'connection_test';
        IF c.def LIKE '%transaction_id IS NULL%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((purpose IN (%s)) = (transaction_id IS NULL))',
                           c.conname, c.conname, purposes);
        ELSE
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s))',
                           c.conname, c.conname, purposes);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd
