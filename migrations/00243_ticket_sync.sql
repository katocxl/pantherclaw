-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Ticket sync configuration, inbound log and outbound tasks (G0 M20 D255;
-- F545, HR-527, HR-528, T-227).
--
-- A sync configuration binds one ticket-system project behind one
-- connection to the organization. The ticket system's credential is the
-- connection's, sealed to the gateway (HR-060): the server never holds it.
-- Every call to the ticket system is a verification task of the new
-- purpose ticket_sync, leased by the org's gateway like any other target
-- call, with no transaction. pc.ticket_outbound records what each task was
-- for and what came of it.
--
-- Inbound webhooks are verified on the server with the configuration's own
-- secret, DEK-encrypted per row like the notification secrets (HR-062);
-- the previous secret verifies for 24 hours after a rotation. Each
-- delivery the server accepted or refused is one row of
-- pc.ticket_inbound_events, unique per delivery id, so a replayed delivery
-- finds its earlier row and changes nothing. The log is append-only.

-- +goose Up
CREATE TABLE pc.ticket_sync_configs (
    org_id                 uuid        NOT NULL REFERENCES pc.orgs (id),
    id                     uuid        NOT NULL,
    system                 text        NOT NULL CHECK (system IN ('jira')),
    connection_id          uuid        NOT NULL,
    project_key            text        NOT NULL CHECK (project_key ~ '^[A-Z][A-Z0-9_]{1,9}$'),
    state                  text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'PAUSED')),
    webhook_secret         bytea       NOT NULL CHECK (octet_length(webhook_secret) BETWEEN 16 AND 8192),
    prev_webhook_secret    bytea       CHECK (prev_webhook_secret IS NULL OR octet_length(prev_webhook_secret) BETWEEN 16 AND 8192),
    prev_secret_expires_at timestamptz,
    created_by             text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 300),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CHECK ((prev_webhook_secret IS NULL) = (prev_secret_expires_at IS NULL))
);
CREATE UNIQUE INDEX ticket_sync_configs_project ON pc.ticket_sync_configs (org_id, system, connection_id, project_key);

CREATE TABLE pc.ticket_inbound_events (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    config_id   uuid        NOT NULL,
    -- The ticket system's delivery id (Jira: X-Atlassian-Webhook-Identifier).
    delivery_id text        NOT NULL CHECK (delivery_id ~ '^[A-Za-z0-9._:-]{1,128}$'),
    body_sha256 bytea       NOT NULL CHECK (octet_length(body_sha256) = 32),
    issue_key   text        CHECK (issue_key IS NULL OR issue_key ~ '^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,9}$'),
    -- APPLIED: a ticket-owned field was mirrored; IGNORED: a change to a
    -- PantherClaw-owned field was dropped and recorded (HR-528); NOTED: a
    -- status such as Done was only noted (HR-527); STALE: not newer than
    -- what the sync had seen; UNLINKED: no case or incident has the ticket.
    outcome     text        NOT NULL CHECK (outcome IN ('APPLIED', 'IGNORED', 'NOTED', 'STALE', 'UNLINKED')),
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, config_id) REFERENCES pc.ticket_sync_configs (org_id, id)
);
CREATE UNIQUE INDEX ticket_inbound_events_delivery ON pc.ticket_inbound_events (org_id, config_id, delivery_id);
CREATE INDEX ticket_inbound_events_recent ON pc.ticket_inbound_events (org_id, config_id, received_at DESC);

CREATE TABLE pc.ticket_outbound (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    config_id       uuid        NOT NULL,
    case_id         uuid,
    incident_id     uuid,
    -- CREATE opens the ticket of a case or an incident; COMMENT adds what
    -- PantherClaw changed on a PantherClaw-owned field.
    action          text        NOT NULL CHECK (action IN ('CREATE', 'COMMENT')),
    verification_id uuid        NOT NULL,
    state           text        NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'DONE', 'FAILED')),
    result_code     text        CHECK (result_code IS NULL OR result_code ~ '^[a-z0-9_]{1,64}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, config_id) REFERENCES pc.ticket_sync_configs (org_id, id),
    FOREIGN KEY (org_id, case_id) REFERENCES pc.cases (org_id, id),
    FOREIGN KEY (org_id, incident_id) REFERENCES pc.incidents (org_id, id),
    FOREIGN KEY (org_id, verification_id) REFERENCES pc.verifications (org_id, id),
    CHECK ((case_id IS NULL) <> (incident_id IS NULL)),
    CHECK ((state = 'PENDING') = (finished_at IS NULL))
);
CREATE UNIQUE INDEX ticket_outbound_verification ON pc.ticket_outbound (org_id, verification_id);
-- One open at a time: a second open of a waiting ticket is the same open
-- (D277), so it never makes a second ticket.
CREATE UNIQUE INDEX ticket_outbound_case_waiting ON pc.ticket_outbound (org_id, case_id)
    WHERE action = 'CREATE' AND state = 'PENDING' AND case_id IS NOT NULL;
CREATE UNIQUE INDEX ticket_outbound_incident_waiting ON pc.ticket_outbound (org_id, incident_id)
    WHERE action = 'CREATE' AND state = 'PENDING' AND incident_id IS NOT NULL;
CREATE INDEX ticket_outbound_case ON pc.ticket_outbound (org_id, case_id) WHERE case_id IS NOT NULL;
CREATE INDEX ticket_outbound_incident ON pc.ticket_outbound (org_id, incident_id) WHERE incident_id IS NOT NULL;

-- The inbound log is append-only, but for pc_deleter, which empties a
-- deleted organization (HR-390..392, 00177's exception).
-- +goose StatementBegin
CREATE FUNCTION pc.ticket_inbound_immutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND current_user = 'pc_deleter' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'the ticket inbound log is append-only' USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER ticket_inbound_events_immutable BEFORE UPDATE OR DELETE ON pc.ticket_inbound_events
    FOR EACH ROW EXECUTE FUNCTION pc.ticket_inbound_immutable();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ticket_sync_configs', 'ticket_inbound_events', 'ticket_outbound']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.ticket_sync_configs, pc.ticket_inbound_events, pc.ticket_outbound TO pc_app;
GRANT UPDATE (state, webhook_secret, prev_webhook_secret, prev_secret_expires_at, updated_at) ON pc.ticket_sync_configs TO pc_app;
GRANT UPDATE (state, result_code, finished_at) ON pc.ticket_outbound TO pc_app;
GRANT SELECT ON pc.ticket_inbound_events, pc.ticket_outbound TO pc_audit_ro;
-- The webhook secrets stay out of the audit role's reach (HR-062).
GRANT SELECT (org_id, id, system, connection_id, project_key, state, prev_secret_expires_at, created_by, created_at, updated_at)
    ON pc.ticket_sync_configs TO pc_audit_ro;

-- Ticket sync calls reach the ticket system as verification tasks of their
-- own purpose, which belong to no transaction. The two checks that list
-- the purposes gain ticket_sync from their own lists, whatever else is
-- there (00084's pattern); any other shape fails the migration.
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
    n        integer := 0;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%purpose%' AND pg_get_constraintdef(oid) NOT LIKE '%window_start%'
               AND pg_get_constraintdef(oid) NOT LIKE '%definition_digest%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i);
        IF purposes IS NULL OR purposes LIKE '%ticket_sync%' THEN
            RAISE EXCEPTION '00243: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        -- First, not last: the Up and Down of 00084 and 00095 keep their own
        -- purposes last, and must find the list as they left it.
        purposes := '''ticket_sync'', ' || purposes;
        IF c.def LIKE '%transaction_id IS NULL%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((purpose IN (%s)) = (transaction_id IS NULL)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSIF c.def LIKE '%follow_up%' THEN
            EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s)) NOT VALID',
                           c.conname, c.conname, purposes);
        ELSE
            RAISE EXCEPTION '00243: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        EXECUTE format('ALTER TABLE pc.verifications VALIDATE CONSTRAINT %I', c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 2 THEN
        RAISE EXCEPTION '00243: found % purpose checks on pc.verifications, not 2', n;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.ticket_outbound;
DROP TABLE pc.ticket_inbound_events;
DROP FUNCTION pc.ticket_inbound_immutable();
DROP TABLE pc.ticket_sync_configs;
-- Ticket sync tasks go before their purpose does. RLS is forced even for
-- the owner, so it is lifted for these two deletes only, inside this
-- migration's transaction.
ALTER TABLE pc.observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.observations o USING pc.verifications v
 WHERE o.org_id = v.org_id AND o.verification_id = v.id AND v.purpose = 'ticket_sync';
DELETE FROM pc.verifications WHERE purpose = 'ticket_sync';
ALTER TABLE pc.verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.observations FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%ticket_sync%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i)
         WHERE m.v[1] <> 'ticket_sync';
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
