-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Governed automations, assurance (G0 M11 part 2 D34–D38, D37a;
-- HR-287..289, T-127).
--
-- * automation_test_cases: a version's scenario tests (D34): a trigger,
--   stubbed step results and the expected outcome. They change only while
--   the version is DRAFT or VALIDATED; once it is TESTED or later its tests
--   are part of what was reviewed.
-- * automation_test_runs: one run of a version's tests against the
--   version's digest and the tests' digest; insert-only. A passing run for
--   the current digests is what makes a version TESTED (HR-287).
-- * automation_simulations: a historical simulation over at most 30 days
--   (D35). It writes nothing but its own row (HR-288).
-- * exposure_rights gains automation_id and the ISSUANCE_CEILING view
--   (D37a): an automation's potential reach, its ceiling's bounds through
--   each ceiling agent, kept apart from held reach. A ceiling right always
--   names its automation and never a grant; it is never USABLE (an
--   execution must issue it first). Effective rights of grants an
--   automation issued carry the automation too.

-- +goose Up
CREATE TABLE pc.automation_test_cases (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    version_id uuid        NOT NULL,
    name       text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9_-]{0,62}$'),
    case_kind  text        NOT NULL CHECK (case_kind IN ('NORMAL', 'DENIED', 'TIMEOUT', 'DUPLICATE', 'PARTIAL', 'UNKNOWN',
                                                         'CUSTOM')),
    -- The trigger the case submits: kind, params and subjects.
    trigger    jsonb       NOT NULL CHECK (jsonb_typeof(trigger) = 'object' AND octet_length(trigger::text) <= 8192),
    -- {step_id: [StepResult, ...]}: what each attempt of a step returns.
    stubs      jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(stubs) = 'object' AND octet_length(stubs::text) <= 32768),
    -- {state, reason?, steps: {step_id: state}}.
    expect     jsonb       NOT NULL CHECK (jsonb_typeof(expect) = 'object' AND octet_length(expect::text) <= 8192),
    seq        integer     NOT NULL CHECK (seq BETWEEN 1 AND 50),
    created_by uuid        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, version_id, name),
    UNIQUE (org_id, version_id, seq),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.automation_versions (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id)
);

-- Test cases change only while their version is DRAFT or VALIDATED.
-- +goose StatementBegin
CREATE FUNCTION pc.automation_test_case_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pc
AS $$
DECLARE
    v_org     uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.org_id ELSE NEW.org_id END;
    v_version uuid := CASE WHEN TG_OP = 'DELETE' THEN OLD.version_id ELSE NEW.version_id END;
    v_state   text;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'automation test cases are replaced, never updated' USING ERRCODE = 'check_violation';
    END IF;
    SELECT v.state INTO v_state FROM pc.automation_versions v WHERE v.org_id = v_org AND v.id = v_version;
    IF v_state IS DISTINCT FROM 'DRAFT' AND v_state IS DISTINCT FROM 'VALIDATED' THEN
        RAISE EXCEPTION 'automation version % is %: its tests no longer change', v_version, v_state
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_test_cases_guard BEFORE INSERT OR UPDATE OR DELETE ON pc.automation_test_cases
    FOR EACH ROW EXECUTE FUNCTION pc.automation_test_case_guard();

CREATE TABLE pc.automation_test_runs (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    version_id        uuid        NOT NULL,
    definition_digest bytea       NOT NULL CHECK (octet_length(definition_digest) = 32),
    -- SHA-256 of the canonical cases the run ran, in order.
    tests_digest      bytea       NOT NULL CHECK (octet_length(tests_digest) = 32),
    passed            boolean     NOT NULL,
    -- Per case: kind, passed, the simulated execution and what differed;
    -- plus the required kinds missing.
    results           jsonb       NOT NULL CHECK (jsonb_typeof(results) = 'object' AND octet_length(results::text) <= 262144),
    run_by            uuid        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.automation_versions (org_id, id),
    FOREIGN KEY (org_id, run_by) REFERENCES pc.users (org_id, id)
);
CREATE INDEX automation_test_runs_version ON pc.automation_test_runs (org_id, version_id, created_at DESC, id DESC);

CREATE TABLE pc.automation_simulations (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    version_id   uuid        NOT NULL,
    from_at      timestamptz NOT NULL,
    to_at        timestamptz NOT NULL,
    state        text        NOT NULL DEFAULT 'QUEUED' CHECK (state IN ('QUEUED', 'RUNNING', 'DONE', 'FAILED')),
    results      jsonb       CHECK (results IS NULL OR (jsonb_typeof(results) = 'object'
                                                        AND octet_length(results::text) <= 1048576)),
    error        text        CHECK (char_length(error) BETWEEN 1 AND 500),
    requested_by uuid        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.automation_versions (org_id, id),
    FOREIGN KEY (org_id, requested_by) REFERENCES pc.users (org_id, id),
    CHECK (to_at > from_at AND to_at <= from_at + interval '30 days'),
    CHECK ((state = 'DONE') = (results IS NOT NULL)),
    CHECK ((state = 'FAILED') = (error IS NOT NULL)),
    CHECK ((state IN ('DONE', 'FAILED')) = (finished_at IS NOT NULL))
);
CREATE INDEX automation_simulations_version ON pc.automation_simulations (org_id, version_id, created_at DESC, id DESC);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['automation_test_cases', 'automation_test_runs', 'automation_simulations']
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

GRANT SELECT, INSERT, DELETE ON pc.automation_test_cases TO pc_app;
GRANT SELECT, INSERT ON pc.automation_test_runs, pc.automation_simulations TO pc_app;
GRANT UPDATE (state, results, error, started_at, finished_at) ON pc.automation_simulations TO pc_app;
GRANT SELECT ON pc.automation_test_cases, pc.automation_test_runs, pc.automation_simulations TO pc_audit_ro;

-- Exposure: the automation holder and the issuance-ceiling view (D37a).
-- squawk: a nullable column without a default and CHECKs on rows that are
-- pruned within days; goose runs each migration in one transaction.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.exposure_rights
    ADD COLUMN automation_id uuid,
    DROP CONSTRAINT exposure_rights_reach_view_check,
    ADD CONSTRAINT exposure_rights_reach_view_check
        CHECK (reach_view IN ('OBSERVED', 'EFFECTIVE', 'CREDENTIAL', 'ISSUANCE_CEILING')),
    ADD CONSTRAINT exposure_rights_ceiling CHECK (reach_view <> 'ISSUANCE_CEILING'
        OR (automation_id IS NOT NULL AND grant_id IS NULL AND agent_id IS NOT NULL
            AND label IN ('CONDITIONAL', 'UNCERTAIN'))),
    ADD CONSTRAINT exposure_rights_automation CHECK (automation_id IS NULL OR reach_view IN ('EFFECTIVE', 'ISSUANCE_CEILING'));
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX exposure_rights_automation ON pc.exposure_rights (org_id, snapshot_id, automation_id)
    WHERE automation_id IS NOT NULL;

-- +goose Down
DROP INDEX pc.exposure_rights_automation;
DELETE FROM pc.exposure_rights WHERE reach_view = 'ISSUANCE_CEILING';
ALTER TABLE pc.exposure_rights
    DROP CONSTRAINT exposure_rights_automation,
    DROP CONSTRAINT exposure_rights_ceiling,
    DROP CONSTRAINT exposure_rights_reach_view_check,
    ADD CONSTRAINT exposure_rights_reach_view_check CHECK (reach_view IN ('OBSERVED', 'EFFECTIVE', 'CREDENTIAL')),
    DROP COLUMN automation_id;

DROP TABLE pc.automation_simulations;
DROP TABLE pc.automation_test_runs;
DROP TABLE pc.automation_test_cases;
DROP FUNCTION pc.automation_test_case_guard();
