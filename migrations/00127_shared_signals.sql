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
    match_basis    text        CHECK (match_basis IS NULL OR match_basis IN ('iss_sub', 'email')),
    outcome        text        NOT NULL CHECK (outcome IN ('ACCEPTED', 'UNMATCHED', 'IGNORED', 'VERIFICATION')),
    case_id        uuid,
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
GRANT UPDATE (case_id) ON pc.ssf_events TO pc_app;
GRANT DELETE ON pc.ssf_events TO pc_app;
GRANT SELECT ON pc.ssf_transmitters, pc.ssf_events TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.ssf_events;
DROP TABLE pc.ssf_transmitters;
DROP FUNCTION pc.ssf_transmitter_guard();
