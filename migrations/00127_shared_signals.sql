-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Shared Signals receiver (G0 M10 D37; PN-024, HR-261, founder decision
-- F1). A transmitter is an identity provider that pushes Security Event
-- Tokens (RFC 8417, RFC 8935) to POST /v1/ssf/{org}/{transmitter}. It is
-- created PENDING through the API and becomes ACTIVE only when a person
-- activates it on its page with a fresh WebAuthn step-up. Its issuer, JWKS
-- URI (on the issuer's host) and audience never change once stored: other
-- keys or another issuer are a new transmitter, activated again.
--
-- Every verified event is recorded once per (transmitter, jti); a second
-- token with the same jti is refused as a replay for as long as the row
-- is kept (7 days, deleted by the janitor; iat older than 5 minutes is
-- refused anyway). The row keeps the event type, the subject's format,
-- the matched user and the match basis, never the token or the raw
-- subject identifiers.

-- +goose Up
CREATE TABLE pc.ssf_transmitters (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    name                 text        NOT NULL CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    issuer               text        NOT NULL CHECK (char_length(issuer) BETWEEN 9 AND 512 AND issuer LIKE 'https://%'),
    jwks_uri             text        NOT NULL CHECK (char_length(jwks_uri) BETWEEN 9 AND 2048 AND jwks_uri LIKE 'https://%'),
    audience             text        NOT NULL CHECK (char_length(audience) BETWEEN 1 AND 2048),
    state                text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'ACTIVE', 'PAUSED', 'DISABLED')),
    created_by           text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at           timestamptz NOT NULL DEFAULT now(),
    activated_by         uuid,
    activated_credential uuid,
    activated_at         timestamptz,
    updated_at           timestamptz NOT NULL DEFAULT now(),
    last_event_at        timestamptz,
    events_accepted      bigint      NOT NULL DEFAULT 0 CHECK (events_accepted >= 0),
    events_refused       bigint      NOT NULL DEFAULT 0 CHECK (events_refused >= 0),
    last_refusal_at      timestamptz,
    last_refusal_code    text        CHECK (last_refusal_code IS NULL OR last_refusal_code ~ '^[a-z_]{1,64}$'),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, activated_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, activated_credential) REFERENCES pc.webauthn_credentials (org_id, id),
    CHECK ((activated_at IS NULL) = (activated_by IS NULL) AND (activated_by IS NULL) = (activated_credential IS NULL)),
    CHECK (state IN ('PENDING', 'DISABLED') OR activated_at IS NOT NULL)
);
CREATE UNIQUE INDEX ssf_transmitters_name ON pc.ssf_transmitters (org_id, name) WHERE state <> 'DISABLED';

-- Inserted PENDING, activated once by a person with a key, DISABLED is
-- final (HR-261).
-- +goose StatementBegin
CREATE FUNCTION pc.ssf_transmitter_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'PENDING' OR NEW.activated_by IS NOT NULL THEN
            RAISE EXCEPTION 'a transmitter is inserted PENDING' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        RETURN NEW;
    END IF;
    IF OLD.state = 'DISABLED' AND NEW.state IS DISTINCT FROM 'DISABLED' THEN
        RAISE EXCEPTION 'a disabled transmitter stays disabled' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'PENDING' AND OLD.state IS DISTINCT FROM 'PENDING' THEN
        RAISE EXCEPTION 'a transmitter cannot return to PENDING' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NOT NULL AND (NEW.activated_by IS DISTINCT FROM OLD.activated_by
            OR NEW.activated_credential IS DISTINCT FROM OLD.activated_credential
            OR NEW.activated_at IS DISTINCT FROM OLD.activated_at) THEN
        RAISE EXCEPTION 'a transmitter is activated once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.activated_by IS NULL AND NEW.activated_by IS NOT NULL THEN
        NEW.activated_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER ssf_transmitters_guard BEFORE INSERT OR UPDATE ON pc.ssf_transmitters
    FOR EACH ROW EXECUTE FUNCTION pc.ssf_transmitter_guard();

-- One verified event. outcome: ACCEPTED (a handled event type that matched
-- a person), UNMATCHED (handled, no person matched: recorded, no case),
-- IGNORED (an event type PantherClaw does not act on), VERIFICATION (the
-- SSF verification event, acknowledged).
CREATE TABLE pc.ssf_events (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    transmitter_id uuid        NOT NULL,
    jti            text        NOT NULL CHECK (char_length(jti) BETWEEN 1 AND 256),
    event_type     text        NOT NULL CHECK (char_length(event_type) BETWEEN 1 AND 256),
    issued_at      timestamptz NOT NULL,
    subject_format text        CHECK (subject_format IS NULL OR subject_format ~ '^[a-z_]{1,32}$'),
    user_id        uuid,
    -- iss_sub only when the subject's issuer is the transmitter's own (D64);
    -- foreign_iss_sub and email open a case only.
    match_basis    text        CHECK (match_basis IS NULL OR match_basis IN ('iss_sub', 'foreign_iss_sub', 'email')),
    outcome        text        NOT NULL CHECK (outcome IN ('ACCEPTED', 'UNMATCHED', 'IGNORED', 'VERIFICATION')),
    case_id        uuid,
    -- Why an accepted event opened no case (cases unavailable).
    case_note      text        CHECK (char_length(case_note) BETWEEN 1 AND 200),
    received_at    timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL DEFAULT now() + interval '7 days',
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, transmitter_id, jti),
    FOREIGN KEY (org_id, transmitter_id) REFERENCES pc.ssf_transmitters (org_id, id),
    FOREIGN KEY (org_id, user_id) REFERENCES pc.users (org_id, id),
    CHECK ((user_id IS NULL) = (match_basis IS NULL)),
    CHECK ((outcome = 'ACCEPTED') = (user_id IS NOT NULL)),
    CHECK (expires_at > received_at)
);
CREATE INDEX ssf_events_recent ON pc.ssf_events (org_id, transmitter_id, received_at DESC);
CREATE INDEX ssf_events_expiry ON pc.ssf_events (org_id, expires_at);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ssf_transmitters', 'ssf_events']
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

GRANT SELECT, INSERT ON pc.ssf_transmitters, pc.ssf_events TO pc_app;
GRANT UPDATE (state, activated_by, activated_credential, activated_at, updated_at, last_event_at, events_accepted,
    events_refused, last_refusal_at, last_refusal_code) ON pc.ssf_transmitters TO pc_app;
GRANT UPDATE (case_id, case_note) ON pc.ssf_events TO pc_app;
GRANT DELETE ON pc.ssf_events TO pc_app;
GRANT SELECT ON pc.ssf_transmitters, pc.ssf_events TO pc_audit_ro;

-- The identity playbook (G0 M10 D38; HR-262, founder decision F1): one row
-- per org, off by default. When enabled, an accepted event of one of its
-- event types about a person matched by OIDC issuer and subject (never by
-- email alone, D46) contains that person and the grants they issued and
-- voids their waiting approvals. It changes only through a request
-- confirmed in BINDING ceremonies: ENABLE and CHANGE by two distinct
-- people with two distinct security keys, DISABLE by one. The row is
-- written only by the request's last confirmation (version + 1).
CREATE TABLE pc.identity_playbooks (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    enabled    boolean     NOT NULL DEFAULT false,
    events     text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(events) <= 8 AND array_position(events, NULL) IS NULL),
    version    integer     NOT NULL DEFAULT 0 CHECK (version >= 0),
    request_id uuid,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id),
    CHECK (NOT enabled OR cardinality(events) >= 1)
);

CREATE TABLE pc.identity_playbook_requests (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    kind           text        NOT NULL CHECK (kind IN ('ENABLE', 'DISABLE', 'CHANGE')),
    events         text[]      NOT NULL CHECK (cardinality(events) <= 8 AND array_position(events, NULL) IS NULL),
    -- The playbook version the request was made against: a request applies
    -- only to that version (VOIDED otherwise).
    base_version   integer     NOT NULL CHECK (base_version >= 0),
    binding        bytea       NOT NULL CHECK (octet_length(binding) = 32),
    required       smallint    NOT NULL CHECK (required BETWEEN 1 AND 2),
    state          text        NOT NULL DEFAULT 'PENDING'
                               CHECK (state IN ('PENDING', 'APPLIED', 'DECLINED', 'EXPIRED', 'VOIDED')),
    requested_by   uuid        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL DEFAULT now() + interval '24 hours',
    decided_at     timestamptz,
    decided_reason text        CHECK (char_length(decided_reason) BETWEEN 1 AND 500),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, requested_by) REFERENCES pc.users (org_id, id),
    CHECK (expires_at = created_at + interval '24 hours'),
    CHECK ((state = 'PENDING') = (decided_at IS NULL)),
    CHECK ((kind = 'DISABLE') = (required = 1)),
    CHECK ((kind = 'DISABLE') = (cardinality(events) = 0))
);
CREATE UNIQUE INDEX identity_playbook_requests_one_pending ON pc.identity_playbook_requests (org_id) WHERE state = 'PENDING';
CREATE INDEX identity_playbook_requests_created ON pc.identity_playbook_requests (org_id, created_at DESC);

-- One person's confirmation with the key that signed the request's
-- binding: distinct persons and distinct keys (HR-262).
CREATE TABLE pc.identity_playbook_confirmations (
    org_id        uuid        NOT NULL,
    request_id    uuid        NOT NULL,
    principal_id  uuid        NOT NULL,
    credential_id uuid        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, request_id, principal_id),
    UNIQUE (org_id, request_id, credential_id),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.identity_playbook_requests (org_id, id),
    FOREIGN KEY (org_id, principal_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, credential_id) REFERENCES pc.webauthn_credentials (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['identity_playbooks', 'identity_playbook_requests', 'identity_playbook_confirmations']
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

GRANT SELECT, INSERT ON pc.identity_playbooks, pc.identity_playbook_requests, pc.identity_playbook_confirmations TO pc_app;
GRANT UPDATE (enabled, events, version, request_id, updated_at) ON pc.identity_playbooks TO pc_app;
GRANT UPDATE (state, decided_at, decided_reason) ON pc.identity_playbook_requests TO pc_app;
GRANT SELECT ON pc.identity_playbooks, pc.identity_playbook_requests, pc.identity_playbook_confirmations TO pc_audit_ro;

-- The confirmation ceremony of a playbook request. pc_app's table-level
-- SELECT and INSERT on webauthn_ceremonies (00030) cover the new column.
-- squawk: pc.webauthn_ceremonies rows live 5 minutes, so the table is small and
-- adding and validating the constraints locks it briefly; goose runs each
-- migration in one transaction (.squawk.toml), so CONCURRENTLY and a separate
-- VALIDATE are not possible.
ALTER TABLE pc.webauthn_ceremonies
    ADD COLUMN identity_playbook_request_id uuid,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id,
                                                     identity_playbook_request_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id,
                                identity_playbook_request_id) <= 1) NOT VALID,
    -- squawk-ignore constraint-missing-not-valid, adding-foreign-key-constraint
    ADD CONSTRAINT webauthn_ceremonies_identity_playbook_fk FOREIGN KEY (org_id, identity_playbook_request_id)
        REFERENCES pc.identity_playbook_requests (org_id, id);
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX webauthn_ceremonies_binding_identity_playbook
    ON pc.webauthn_ceremonies (org_id, identity_playbook_request_id, user_id)
    WHERE identity_playbook_request_id IS NOT NULL AND consumed_at IS NULL;

-- +goose Down
DELETE FROM pc.webauthn_ceremonies WHERE identity_playbook_request_id IS NOT NULL;
DROP INDEX pc.webauthn_ceremonies_binding_identity_playbook;
ALTER TABLE pc.webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_identity_playbook_fk,
    DROP CONSTRAINT webauthn_ceremonies_binding_subject,
    DROP COLUMN identity_playbook_request_id,
    ADD CONSTRAINT webauthn_ceremonies_binding_subject
        CHECK ((purpose = 'BINDING') = (num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id) = 1)
               AND num_nonnulls(approval_request_id, batch_id, reconciliation_id, policy_change_request_id) <= 1) NOT VALID;
ALTER TABLE pc.webauthn_ceremonies VALIDATE CONSTRAINT webauthn_ceremonies_binding_subject;
DROP TABLE pc.identity_playbook_confirmations;
DROP TABLE pc.identity_playbook_requests;
DROP TABLE pc.identity_playbooks;
DROP TABLE pc.ssf_events;
DROP TABLE pc.ssf_transmitters;
DROP FUNCTION pc.ssf_transmitter_guard();
