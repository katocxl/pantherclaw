-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Governed automations, core (G0 M11 part 2 D5, D6, D8, D9, D10, D13;
-- HR-270..274, founder decision F1).
--
-- An automation is a named, owned workflow whose versions are immutable
-- documents (definition + SHA-256 digest + plain-language summary). A
-- version is enabled, and its issuance ceiling activated, only by a change
-- request confirmed in BINDING ceremonies over its digest (the generic M11
-- ceremony: pc.change_requests, also used for protected changes and
-- compromised publishers). Each automation acts as its own service account
-- (pc.service_accounts.automation_id, immutable): that account never holds
-- API keys, assertion keys or role bindings and is never edited or
-- re-enabled through the service-account API; triggers here refuse it as a
-- backstop to the use cases (HR-270).
--
-- A root grant may now name a service-account grantor, but only with a
-- ceiling (grants_root_grantor, HR-271): the database refuses a
-- service-account root grant without one, and a ceiling on anything but a
-- service-account root grant. Runs gain principal source 'automation'.
-- The foreign keys of grants.automation_execution_id and
-- runs.automation_execution_id are added with pc.automation_executions
-- (00142).
--
-- Daily issuance usage is counted by conditional increments only
-- (pc.automation_usage, pc.automation_budget_usage).

-- +goose Up

-- Automations. ACTIVE and PAUSED have an enabled version and a rollout;
-- PAUSED has a reason; RETIRED is final.
CREATE TABLE pc.automations (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    name               text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,62}$'),
    purpose            text        NOT NULL CHECK (char_length(btrim(purpose)) BETWEEN 1 AND 2000),
    kind               text        NOT NULL CHECK (kind IN ('AGENT_WORK', 'SECURITY_WORK')),
    owner_user_id      uuid        NOT NULL,
    service_account_id uuid        NOT NULL,
    state              text        NOT NULL DEFAULT 'DRAFT' CHECK (state IN ('DRAFT', 'ACTIVE', 'PAUSED', 'RETIRED')),
    rollout            text        CHECK (rollout IN ('SHADOW', 'COHORT', 'FULL')),
    cohort_agents      uuid[]      CHECK (cardinality(cohort_agents) BETWEEN 1 AND 50 AND array_position(cohort_agents, NULL) IS NULL),
    enabled_version_id uuid,
    pause_reason       text        CHECK (pause_reason IN ('USER', 'KILL_SWITCH', 'CEILING_VOID', 'CEILING_EXPIRED',
                                                           'OWNER_INACTIVE', 'CONTAINED', 'COMPROMISED_PUBLISHER',
                                                           'AUTHORITY_REVOKED', 'COVERAGE_RECOVERY', 'LOOP')),
    paused_at          timestamptz,
    created_by         uuid        NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    retired_at         timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    UNIQUE (org_id, service_account_id),
    FOREIGN KEY (org_id, owner_user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    CONSTRAINT automations_enabled CHECK (
        (state IN ('ACTIVE', 'PAUSED')) = (enabled_version_id IS NOT NULL)
        AND (enabled_version_id IS NULL) = (rollout IS NULL)),
    CONSTRAINT automations_cohort CHECK ((rollout = 'COHORT') = (cohort_agents IS NOT NULL)),
    CONSTRAINT automations_paused CHECK (
        (state = 'PAUSED') = (pause_reason IS NOT NULL) AND (pause_reason IS NULL) = (paused_at IS NULL)),
    CONSTRAINT automations_retired CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);
CREATE INDEX automations_owner ON pc.automations (org_id, owner_user_id);
CREATE INDEX automations_live ON pc.automations (org_id, state) WHERE state IN ('ACTIVE', 'PAUSED');

-- Versions: definition and digest never change once the version leaves the
-- authoring states (DRAFT, VALIDATED, TESTED); an edit returns it to DRAFT.
-- One PUBLISHED version per automation.
CREATE TABLE pc.automation_versions (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    automation_id     uuid        NOT NULL,
    number            integer     NOT NULL CHECK (number BETWEEN 1 AND 100000),
    state             text        NOT NULL DEFAULT 'DRAFT'
                                  CHECK (state IN ('DRAFT', 'VALIDATED', 'TESTED', 'PUBLISHED', 'SUPERSEDED', 'RETIRED')),
    definition        jsonb       NOT NULL CHECK (jsonb_typeof(definition) = 'object' AND octet_length(definition::text) <= 65536),
    digest            bytea       NOT NULL CHECK (octet_length(digest) = 32),
    summary           text        NOT NULL DEFAULT '' CHECK (char_length(summary) <= 8000),
    findings          jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(findings) = 'array'
                                                               AND octet_length(findings::text) <= 65536),
    tested_run_id     uuid,
    created_by        uuid        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    validated_at      timestamptz,
    tested_at         timestamptz,
    published_at      timestamptz,
    change_request_id uuid,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, automation_id, number),
    UNIQUE (org_id, automation_id, id),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    CONSTRAINT automation_versions_validated CHECK (state = 'DRAFT' OR validated_at IS NOT NULL),
    CONSTRAINT automation_versions_tested CHECK (state <> 'TESTED' OR tested_at IS NOT NULL),
    CONSTRAINT automation_versions_published CHECK (
        (state IN ('PUBLISHED', 'SUPERSEDED')) <= (published_at IS NOT NULL))
);
CREATE UNIQUE INDEX automation_versions_one_published ON pc.automation_versions (org_id, automation_id)
    WHERE state = 'PUBLISHED';

ALTER TABLE pc.automations ADD CONSTRAINT automations_enabled_version_fk
    FOREIGN KEY (org_id, id, enabled_version_id) REFERENCES pc.automation_versions (org_id, automation_id, id);

-- +goose StatementBegin
CREATE FUNCTION pc.automation_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'DRAFT' THEN
            RAISE EXCEPTION 'an automation is inserted DRAFT' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state = 'RETIRED' THEN
        RAISE EXCEPTION 'a retired automation stays retired' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.name IS DISTINCT FROM OLD.name OR NEW.kind IS DISTINCT FROM OLD.kind
            OR NEW.service_account_id IS DISTINCT FROM OLD.service_account_id OR NEW.created_by IS DISTINCT FROM OLD.created_by
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'an automation''s name, kind and identity never change' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'DRAFT' AND OLD.state IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION 'an enabled automation never returns to DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automations_guard BEFORE INSERT OR UPDATE ON pc.automations
    FOR EACH ROW EXECUTE FUNCTION pc.automation_guard();

-- +goose StatementBegin
CREATE FUNCTION pc.automation_version_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    allowed boolean;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'DRAFT' THEN
            RAISE EXCEPTION 'a version is inserted DRAFT' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.automation_id IS DISTINCT FROM OLD.automation_id
            OR NEW.number IS DISTINCT FROM OLD.number OR NEW.created_by IS DISTINCT FROM OLD.created_by
            OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a version''s identity never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.definition IS DISTINCT FROM OLD.definition OR NEW.digest IS DISTINCT FROM OLD.digest)
            AND NOT (OLD.state IN ('DRAFT', 'VALIDATED', 'TESTED') AND NEW.state = 'DRAFT') THEN
        RAISE EXCEPTION 'a version''s definition changes only while it is authored, and returns it to DRAFT'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.change_request_id IS DISTINCT FROM OLD.change_request_id AND OLD.change_request_id IS NOT NULL THEN
        RAISE EXCEPTION 'a version is enabled by one change request' USING ERRCODE = 'check_violation';
    END IF;
    allowed := NEW.state = OLD.state OR (OLD.state, NEW.state) IN (
        ('DRAFT', 'VALIDATED'), ('VALIDATED', 'DRAFT'), ('VALIDATED', 'TESTED'), ('TESTED', 'DRAFT'),
        ('TESTED', 'VALIDATED'), ('VALIDATED', 'PUBLISHED'), ('TESTED', 'PUBLISHED'), ('PUBLISHED', 'SUPERSEDED'),
        ('PUBLISHED', 'RETIRED'), ('SUPERSEDED', 'RETIRED'), ('DRAFT', 'RETIRED'), ('VALIDATED', 'RETIRED'),
        ('TESTED', 'RETIRED'));
    IF NOT allowed THEN
        RAISE EXCEPTION 'a version cannot move from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state IN ('PUBLISHED', 'SUPERSEDED', 'RETIRED')
            AND (NEW.summary IS DISTINCT FROM OLD.summary OR NEW.findings IS DISTINCT FROM OLD.findings
                 OR NEW.published_at IS DISTINCT FROM OLD.published_at) THEN
        RAISE EXCEPTION 'a published version never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PUBLISHED' AND OLD.state IS DISTINCT FROM 'PUBLISHED' THEN
        NEW.published_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_versions_guard BEFORE INSERT OR UPDATE ON pc.automation_versions
    FOR EACH ROW EXECUTE FUNCTION pc.automation_version_guard();

-- The generic M11 BINDING ceremony (D6): a request to apply content of a
-- domain's kind to a subject, confirmed by `required` distinct people with
-- distinct security keys; one PENDING per (domain, kind, subject). It
-- expires 24 hours after creation at the latest.
CREATE TABLE pc.change_requests (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    domain         text        NOT NULL CHECK (domain IN ('automation', 'protected', 'publisher')),
    kind           text        NOT NULL CHECK (kind ~ '^[A-Z][A-Z_]{1,40}$'),
    subject_id     uuid        NOT NULL,
    content_digest bytea       NOT NULL CHECK (octet_length(content_digest) = 32),
    binding        bytea       NOT NULL CHECK (octet_length(binding) = 32),
    summary        jsonb       NOT NULL CHECK (jsonb_typeof(summary) = 'object' AND octet_length(summary::text) <= 16384),
    required       smallint    NOT NULL CHECK (required BETWEEN 1 AND 2),
    state          text        NOT NULL DEFAULT 'PENDING'
                               CHECK (state IN ('PENDING', 'APPROVED', 'DECLINED', 'EXPIRED', 'VOIDED')),
    requested_by   text        NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 128),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    decided_at     timestamptz,
    decided_reason text        CHECK (char_length(decided_reason) BETWEEN 1 AND 500),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, binding),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
    CHECK ((state = 'PENDING') = (decided_at IS NULL))
);
CREATE UNIQUE INDEX change_requests_one_pending ON pc.change_requests (org_id, domain, kind, subject_id)
    WHERE state = 'PENDING';
CREATE INDEX change_requests_subject ON pc.change_requests (org_id, domain, subject_id, created_at DESC);
CREATE INDEX change_requests_pending_expiry ON pc.change_requests (org_id, expires_at) WHERE state = 'PENDING';

-- +goose StatementBegin
CREATE FUNCTION pc.change_request_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' THEN
            RAISE EXCEPTION 'a change request is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'a decided change request never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.domain, NEW.kind, NEW.subject_id, NEW.content_digest, NEW.binding, NEW.summary, NEW.required,
            NEW.requested_by, NEW.created_at, NEW.expires_at)
            IS DISTINCT FROM (OLD.id, OLD.domain, OLD.kind, OLD.subject_id, OLD.content_digest, OLD.binding, OLD.summary,
                              OLD.required, OLD.requested_by, OLD.created_at, OLD.expires_at) THEN
        RAISE EXCEPTION 'a change request''s content never changes' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER change_requests_guard BEFORE INSERT OR UPDATE ON pc.change_requests
    FOR EACH ROW EXECUTE FUNCTION pc.change_request_guard();

-- One person's confirmation with the key that signed the binding:
-- distinct persons and distinct keys per request (HR-272).
CREATE TABLE pc.change_confirmations (
    org_id        uuid        NOT NULL,
    request_id    uuid        NOT NULL,
    user_id       uuid        NOT NULL,
    credential_id uuid        NOT NULL,
    confirmed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, request_id, user_id),
    UNIQUE (org_id, request_id, credential_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.change_requests (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, credential_id) REFERENCES pc.webauthn_credentials (org_id, id)
);

ALTER TABLE pc.automation_versions ADD CONSTRAINT automation_versions_change_request_fk
    FOREIGN KEY (org_id, change_request_id) REFERENCES pc.change_requests (org_id, id);

-- Issuance ceilings (D5, D9): the ceiling of an enabled version, approved
-- by the people who confirmed it; one ACTIVE per automation. Only ACTIVE
-- issues; every other state is final.
CREATE TABLE pc.automation_ceilings (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    automation_id     uuid        NOT NULL,
    version_id        uuid        NOT NULL,
    digest            bytea       NOT NULL CHECK (octet_length(digest) = 32),
    approved_by       uuid[]      NOT NULL CHECK (cardinality(approved_by) BETWEEN 1 AND 2
                                                  AND array_position(approved_by, NULL) IS NULL),
    change_request_id uuid        NOT NULL,
    state             text        NOT NULL DEFAULT 'ACTIVE'
                                  CHECK (state IN ('ACTIVE', 'SUPERSEDED', 'EXPIRED', 'VOID', 'REVOKED')),
    review_by         timestamptz NOT NULL,
    void_reason       text        CHECK (char_length(void_reason) BETWEEN 1 AND 128),
    created_at        timestamptz NOT NULL DEFAULT now(),
    ended_at          timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, automation_id, version_id) REFERENCES pc.automation_versions (org_id, automation_id, id),
    FOREIGN KEY (org_id, change_request_id) REFERENCES pc.change_requests (org_id, id),
    CHECK (review_by > created_at AND review_by <= created_at + interval '90 days'),
    CHECK ((state = 'ACTIVE') = (ended_at IS NULL)),
    CHECK ((state = 'VOID') = (void_reason IS NOT NULL))
);
CREATE UNIQUE INDEX automation_ceilings_one_active ON pc.automation_ceilings (org_id, automation_id)
    WHERE state = 'ACTIVE';
CREATE INDEX automation_ceilings_review ON pc.automation_ceilings (org_id, review_by) WHERE state = 'ACTIVE';

-- +goose StatementBegin
CREATE FUNCTION pc.automation_ceiling_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'ACTIVE' THEN
            RAISE EXCEPTION 'a ceiling is inserted ACTIVE' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state IS DISTINCT FROM 'ACTIVE' THEN
        RAISE EXCEPTION 'an ended ceiling never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF (NEW.id, NEW.automation_id, NEW.version_id, NEW.digest, NEW.approved_by, NEW.change_request_id, NEW.review_by,
            NEW.created_at)
            IS DISTINCT FROM (OLD.id, OLD.automation_id, OLD.version_id, OLD.digest, OLD.approved_by,
                              OLD.change_request_id, OLD.review_by, OLD.created_at) THEN
        RAISE EXCEPTION 'a ceiling''s content never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM 'ACTIVE' THEN
        NEW.ended_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER automation_ceilings_guard BEFORE INSERT OR UPDATE ON pc.automation_ceilings
    FOR EACH ROW EXECUTE FUNCTION pc.automation_ceiling_guard();

-- Daily issuance usage (UTC day), changed only by conditional increments.
CREATE TABLE pc.automation_usage (
    org_id        uuid    NOT NULL REFERENCES pc.orgs (id),
    automation_id uuid    NOT NULL,
    day           date    NOT NULL,
    grants        integer NOT NULL DEFAULT 0 CHECK (grants BETWEEN 0 AND 1000),
    runs          integer NOT NULL DEFAULT 0 CHECK (runs BETWEEN 0 AND 1000),
    PRIMARY KEY (org_id, automation_id, day),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id)
);

CREATE TABLE pc.automation_budget_usage (
    org_id        uuid    NOT NULL REFERENCES pc.orgs (id),
    automation_id uuid    NOT NULL,
    day           date    NOT NULL,
    currency      text    NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    reserved      numeric NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    PRIMARY KEY (org_id, automation_id, day, currency),
    FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['automations', 'automation_versions', 'change_requests', 'change_confirmations',
                             'automation_ceilings', 'automation_usage', 'automation_budget_usage']
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

GRANT SELECT, INSERT ON pc.automations, pc.automation_versions, pc.change_requests, pc.change_confirmations,
    pc.automation_ceilings, pc.automation_usage, pc.automation_budget_usage TO pc_app;
GRANT UPDATE (purpose, owner_user_id, state, rollout, cohort_agents, enabled_version_id, pause_reason, paused_at,
    updated_at, retired_at) ON pc.automations TO pc_app;
GRANT UPDATE (state, definition, digest, summary, findings, tested_run_id, updated_at, validated_at, tested_at,
    published_at, change_request_id) ON pc.automation_versions TO pc_app;
GRANT UPDATE (state, decided_at, decided_reason) ON pc.change_requests TO pc_app;
GRANT UPDATE (state, void_reason, ended_at) ON pc.automation_ceilings TO pc_app;
GRANT UPDATE (grants, runs) ON pc.automation_usage TO pc_app;
GRANT UPDATE (reserved) ON pc.automation_budget_usage TO pc_app;
GRANT SELECT ON pc.automations, pc.automation_versions, pc.change_requests, pc.change_confirmations,
    pc.automation_ceilings, pc.automation_usage, pc.automation_budget_usage TO pc_audit_ro;

-- The execution identity (D8, HR-270). The account is inserted with its
-- automation's id (the automation row follows in the same transaction, so
-- both foreign keys are deferred); the id never changes.
-- squawk: pc.service_accounts holds a few rows per org, so adding the
-- column and its constraints locks it briefly; goose runs each migration in
-- one transaction (.squawk.toml), so CONCURRENTLY and a separate VALIDATE
-- are not possible.
ALTER TABLE pc.service_accounts
    ADD COLUMN automation_id uuid,
    -- squawk-ignore constraint-missing-not-valid, adding-foreign-key-constraint
    ADD CONSTRAINT service_accounts_automation_fk FOREIGN KEY (org_id, automation_id)
        REFERENCES pc.automations (org_id, id) DEFERRABLE INITIALLY DEFERRED;
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX service_accounts_automation ON pc.service_accounts (org_id, automation_id)
    WHERE automation_id IS NOT NULL;
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX service_accounts_identity ON pc.service_accounts (org_id, id, automation_id);
ALTER TABLE pc.automations ADD CONSTRAINT automations_identity_fk
    FOREIGN KEY (org_id, service_account_id, id) REFERENCES pc.service_accounts (org_id, id, automation_id)
    DEFERRABLE INITIALLY DEFERRED;

-- An automation's account is never renamed, described, re-enabled or
-- re-assigned (the automations app alone disables it, at retirement).
-- +goose StatementBegin
CREATE FUNCTION pc.service_account_automation_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.automation_id IS DISTINCT FROM OLD.automation_id THEN
        RAISE EXCEPTION 'AUTOMATION_IDENTITY: a service account''s automation never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.automation_id IS NOT NULL AND (NEW.name IS DISTINCT FROM OLD.name
            OR NEW.description IS DISTINCT FROM OLD.description
            OR (OLD.state = 'DISABLED' AND NEW.state IS DISTINCT FROM 'DISABLED')) THEN
        RAISE EXCEPTION 'AUTOMATION_IDENTITY: an automation''s identity is changed only by the automation'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER service_accounts_automation_guard BEFORE UPDATE ON pc.service_accounts
    FOR EACH ROW EXECUTE FUNCTION pc.service_account_automation_guard();

-- No API key, assertion key or role binding for an automation's account.
-- +goose StatementBegin
CREATE FUNCTION pc.automation_identity_credential_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.service_account_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM pc.service_accounts s
            WHERE s.org_id = NEW.org_id AND s.id = NEW.service_account_id AND s.automation_id IS NOT NULL) THEN
        RAISE EXCEPTION 'AUTOMATION_IDENTITY: an automation''s identity holds no keys or role bindings'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER api_keys_automation_guard BEFORE INSERT OR UPDATE ON pc.api_keys
    FOR EACH ROW EXECUTE FUNCTION pc.automation_identity_credential_guard();
CREATE TRIGGER service_account_keys_automation_guard BEFORE INSERT OR UPDATE ON pc.service_account_keys
    FOR EACH ROW EXECUTE FUNCTION pc.automation_identity_credential_guard();
CREATE TRIGGER role_bindings_automation_guard BEFORE INSERT OR UPDATE ON pc.role_bindings
    FOR EACH ROW EXECUTE FUNCTION pc.automation_identity_credential_guard();

-- Ceiling-bounded issuance (D9, HR-271). Only a service-account root grant
-- carries a ceiling, and a service-account root grant needs one.
-- squawk: pc.grants is checked row by row by the new constraints (no
-- table rewrite: nullable columns without defaults); goose runs each
-- migration in one transaction (.squawk.toml), so the validation cannot
-- move to its own.
ALTER TABLE pc.grants
    ADD COLUMN ceiling_id uuid,
    ADD COLUMN automation_execution_id uuid,
    -- squawk-ignore constraint-missing-not-valid, adding-foreign-key-constraint
    ADD CONSTRAINT grants_ceiling_fk FOREIGN KEY (org_id, ceiling_id) REFERENCES pc.automation_ceilings (org_id, id),
    DROP CONSTRAINT grants_root_by_a_person,
    ADD CONSTRAINT grants_root_grantor CHECK (parent_id IS NOT NULL OR grantor_kind = 'user'
        OR (grantor_kind = 'service_account' AND ceiling_id IS NOT NULL)) NOT VALID,
    ADD CONSTRAINT grants_ceiling CHECK (ceiling_id IS NULL
        OR (grantor_kind = 'service_account' AND parent_id IS NULL)) NOT VALID,
    ADD CONSTRAINT grants_automation_execution CHECK (automation_execution_id IS NULL OR ceiling_id IS NOT NULL) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_root_grantor;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_ceiling;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_automation_execution;
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX grants_ceiling ON pc.grants (org_id, ceiling_id) WHERE ceiling_id IS NOT NULL;
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX grants_automation_execution ON pc.grants (org_id, automation_execution_id)
    WHERE automation_execution_id IS NOT NULL;

-- Runs for automations (D10): principal source 'automation' is the
-- principal a version declares and a confirmer consented to; the launcher
-- is the automation's account and the run names its execution.
-- squawk: as for pc.grants above.
ALTER TABLE pc.runs
    ADD COLUMN automation_execution_id uuid,
    DROP CONSTRAINT runs_principal_source_check,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation')) NOT VALID,
    ADD CONSTRAINT runs_automation CHECK ((principal_source = 'automation') = (automation_execution_id IS NOT NULL)
        AND (principal_source <> 'automation' OR launcher_sa_id IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_principal_source_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_automation;
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX runs_automation_execution ON pc.runs (org_id, automation_execution_id)
    WHERE automation_execution_id IS NOT NULL;

-- Signals from automations (reflexdomain SourceAutomation, D11).
-- squawk: pc.alerts and pc.cases are checked row by row; as above.
ALTER TABLE pc.alerts
    DROP CONSTRAINT alerts_source_check,
    ADD CONSTRAINT alerts_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'automation')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.alerts VALIDATE CONSTRAINT alerts_source_check;
ALTER TABLE pc.cases
    DROP CONSTRAINT cases_source_check,
    ADD CONSTRAINT cases_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'manual', 'automation')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.cases VALIDATE CONSTRAINT cases_source_check;

-- The confirmation ceremony of a change request. pc_app's table-level
-- SELECT and INSERT on webauthn_ceremonies (00030) cover the new column.
-- squawk: pc.webauthn_ceremonies rows live 5 minutes, so the table is small
-- and adding and validating the constraints locks it briefly; as above.
ALTER TABLE pc.webauthn_ceremonies
    ADD COLUMN change_request_id uuid,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id,
                                                     identity_playbook_request_id, change_request_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id,
                                identity_playbook_request_id, change_request_id) <= 1) NOT VALID,
    -- squawk-ignore constraint-missing-not-valid, adding-foreign-key-constraint
    ADD CONSTRAINT webauthn_ceremonies_change_request_fk FOREIGN KEY (org_id, change_request_id)
        REFERENCES pc.change_requests (org_id, id);
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX webauthn_ceremonies_binding_change_request
    ON pc.webauthn_ceremonies (org_id, change_request_id, user_id)
    WHERE change_request_id IS NOT NULL AND consumed_at IS NULL;

-- +goose Down
DELETE FROM pc.webauthn_ceremonies WHERE change_request_id IS NOT NULL;
DROP INDEX pc.webauthn_ceremonies_binding_change_request;
ALTER TABLE pc.webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_change_request_fk,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    DROP COLUMN change_request_id,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id,
                                                     identity_playbook_request_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id,
                                identity_playbook_request_id) <= 1) NOT VALID;
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;

DELETE FROM pc.cases WHERE source = 'automation';
ALTER TABLE pc.cases
    DROP CONSTRAINT cases_source_check,
    ADD CONSTRAINT cases_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system', 'manual'));
DELETE FROM pc.alerts WHERE source = 'automation';
ALTER TABLE pc.alerts
    DROP CONSTRAINT alerts_source_check,
    ADD CONSTRAINT alerts_source_check
        CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage', 'system'));

DROP INDEX pc.runs_automation_execution;
ALTER TABLE pc.runs
    DROP CONSTRAINT runs_automation,
    DROP CONSTRAINT runs_principal_source_check,
    DROP COLUMN automation_execution_id,
    ADD CONSTRAINT runs_principal_source_check CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run'));

DROP INDEX pc.grants_automation_execution;
DROP INDEX pc.grants_ceiling;
ALTER TABLE pc.grants
    DROP CONSTRAINT grants_automation_execution,
    DROP CONSTRAINT grants_ceiling,
    DROP CONSTRAINT grants_root_grantor,
    DROP CONSTRAINT grants_ceiling_fk,
    DROP COLUMN automation_execution_id,
    DROP COLUMN ceiling_id,
    ADD CONSTRAINT grants_root_by_a_person CHECK (parent_id IS NOT NULL OR grantor_kind = 'user');

DROP TRIGGER role_bindings_automation_guard ON pc.role_bindings;
DROP TRIGGER service_account_keys_automation_guard ON pc.service_account_keys;
DROP TRIGGER api_keys_automation_guard ON pc.api_keys;
DROP FUNCTION pc.automation_identity_credential_guard();
DROP TRIGGER service_accounts_automation_guard ON pc.service_accounts;
DROP FUNCTION pc.service_account_automation_guard();
ALTER TABLE pc.automations DROP CONSTRAINT automations_identity_fk;
ALTER TABLE pc.automations DROP CONSTRAINT automations_enabled_version_fk;
DROP INDEX pc.service_accounts_identity;
DROP INDEX pc.service_accounts_automation;
ALTER TABLE pc.service_accounts
    DROP CONSTRAINT service_accounts_automation_fk,
    DROP COLUMN automation_id;

DROP TABLE pc.automation_budget_usage;
DROP TABLE pc.automation_usage;
DROP TABLE pc.automation_ceilings;
DROP FUNCTION pc.automation_ceiling_guard();
ALTER TABLE pc.automation_versions DROP CONSTRAINT automation_versions_change_request_fk;
DROP TABLE pc.change_confirmations;
DROP TABLE pc.change_requests;
DROP FUNCTION pc.change_request_guard();
DROP TABLE pc.automation_versions;
DROP FUNCTION pc.automation_version_guard();
DROP TABLE pc.automations;
DROP FUNCTION pc.automation_guard();
