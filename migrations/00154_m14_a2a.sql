-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M14 peer agent calls over A2A (coordinator decisions D30, D33, D64,
-- D85; HR-322, HR-324..326).
--
-- pc.a2a_pins holds an a2a connection's configuration as pins: the agent
-- card as it was fetched, its digest (SHA-256 of its JCS form), the
-- optional pinned card keys, the interface the gateway calls, the allowed
-- skills, the answer and stream caps and, for a peer enrolled in the same
-- org, that agent and the scope its delegated runs get. Creating or
-- changing the connection stores a PROPOSED pin; it serves only once a
-- person holding connection.manage confirms it with a fresh security-key
-- step-up (D92; ACTIVE), and the pin it replaces is SUPERSEDED. A newer proposal voids an older one.
-- At most one pin of a connection is ACTIVE and one PROPOSED; the gateway
-- gets the ACTIVE one. A re-read whose digest differs is drift:
-- drifted_at and observed_digest record it on the ACTIVE pin.
--
-- pc.a2a_peer_runs links a requester's run, the connection and the A2A
-- context to the child runs (and their delegated grants) the Authority
-- created for the peer agent at BeginDispatch: the next message reuses
-- the newest one while it is active, and a new one replaces it once it
-- ended. context_id is empty while peer runs are kept per requester run
-- and connection (D33).

-- +goose Up
CREATE TABLE pc.a2a_pins (
    org_id               uuid        NOT NULL REFERENCES pc.orgs (id),
    id                   uuid        NOT NULL,
    connection_id        uuid        NOT NULL,
    state                text        NOT NULL DEFAULT 'PROPOSED'
                                     CHECK (state IN ('PROPOSED', 'ACTIVE', 'SUPERSEDED', 'VOIDED')),
    card_url             text        NOT NULL CHECK (char_length(card_url) BETWEEN 9 AND 2048 AND card_url ~ '^https?://'),
    binding              text        NOT NULL CHECK (binding IN ('JSONRPC', 'HTTP+JSON')),
    interface_url        text        NOT NULL CHECK (char_length(interface_url) BETWEEN 9 AND 2048 AND interface_url ~ '^https?://'),
    pinned_card          bytea       NOT NULL CHECK (octet_length(pinned_card) BETWEEN 2 AND 262144),
    card_digest          bytea       NOT NULL CHECK (octet_length(card_digest) = 32),
    card_keys            bytea       CHECK (octet_length(card_keys) BETWEEN 2 AND 65536),
    skills               text[]      NOT NULL DEFAULT '{}'
                                     CHECK (cardinality(skills) <= 64 AND array_position(skills, NULL) IS NULL),
    peer_agent_id        uuid,
    peer_bounds          bytea       CHECK (octet_length(peer_bounds) BETWEEN 2 AND 65536),
    peer_limits          bytea       CHECK (octet_length(peer_limits) <= 65536),
    max_answer_bytes     integer     NOT NULL DEFAULT 1048576 CHECK (max_answer_bytes BETWEEN 1024 AND 8388608),
    max_stream_seconds   integer     NOT NULL DEFAULT 300 CHECK (max_stream_seconds BETWEEN 1 AND 3600),
    proposed_by          text        NOT NULL CHECK (char_length(proposed_by) BETWEEN 1 AND 100),
    proposed_at          timestamptz NOT NULL DEFAULT now(),
    confirmed_by         uuid,
    confirmed_credential uuid,
    confirmed_at         timestamptz,
    decided_at           timestamptz,
    drifted_at           timestamptz,
    observed_digest      bytea       CHECK (octet_length(observed_digest) = 32),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, peer_agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, confirmed_by) REFERENCES pc.users (org_id, id),
    CHECK ((peer_agent_id IS NULL) = (peer_bounds IS NULL)),
    CHECK (peer_limits IS NULL OR peer_agent_id IS NOT NULL),
    CHECK ((state IN ('ACTIVE', 'SUPERSEDED')) = (confirmed_at IS NOT NULL)),
    CHECK ((confirmed_at IS NULL) = (confirmed_by IS NULL) AND (confirmed_at IS NULL) = (confirmed_credential IS NULL)),
    CHECK ((state = 'PROPOSED') = (decided_at IS NULL)),
    CHECK ((drifted_at IS NULL) = (observed_digest IS NULL)),
    CHECK (drifted_at IS NULL OR state IN ('ACTIVE', 'SUPERSEDED'))
);
CREATE UNIQUE INDEX a2a_pins_active ON pc.a2a_pins (org_id, connection_id) WHERE state = 'ACTIVE';
CREATE UNIQUE INDEX a2a_pins_proposed ON pc.a2a_pins (org_id, connection_id) WHERE state = 'PROPOSED';
CREATE INDEX a2a_pins_peer ON pc.a2a_pins (org_id, peer_agent_id) WHERE peer_agent_id IS NOT NULL AND state = 'ACTIVE';

-- What a pin is never changes; it only moves PROPOSED → ACTIVE →
-- SUPERSEDED, or PROPOSED → VOIDED, and an ACTIVE one gains its drift.
-- +goose StatementBegin
CREATE FUNCTION pc.a2a_pin_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'PROPOSED' OR NEW.confirmed_at IS NOT NULL OR NEW.drifted_at IS NOT NULL THEN
            RAISE EXCEPTION 'an a2a pin is inserted PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.proposed_at := now();
        RETURN NEW;
    END IF;
    IF NEW.connection_id IS DISTINCT FROM OLD.connection_id OR NEW.card_url IS DISTINCT FROM OLD.card_url
            OR NEW.binding IS DISTINCT FROM OLD.binding OR NEW.interface_url IS DISTINCT FROM OLD.interface_url
            OR NEW.pinned_card IS DISTINCT FROM OLD.pinned_card OR NEW.card_digest IS DISTINCT FROM OLD.card_digest
            OR NEW.card_keys IS DISTINCT FROM OLD.card_keys OR NEW.skills IS DISTINCT FROM OLD.skills
            OR NEW.peer_agent_id IS DISTINCT FROM OLD.peer_agent_id OR NEW.peer_bounds IS DISTINCT FROM OLD.peer_bounds
            OR NEW.peer_limits IS DISTINCT FROM OLD.peer_limits OR NEW.max_answer_bytes IS DISTINCT FROM OLD.max_answer_bytes
            OR NEW.max_stream_seconds IS DISTINCT FROM OLD.max_stream_seconds OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by
            OR NEW.proposed_at IS DISTINCT FROM OLD.proposed_at THEN
        RAISE EXCEPTION 'what an a2a pin is never changes' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT ((OLD.state = NEW.state)
            OR (OLD.state = 'PROPOSED' AND NEW.state IN ('ACTIVE', 'VOIDED'))
            OR (OLD.state = 'ACTIVE' AND NEW.state = 'SUPERSEDED')) THEN
        RAISE EXCEPTION 'an a2a pin moves PROPOSED to ACTIVE or VOIDED, ACTIVE to SUPERSEDED' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state <> 'PROPOSED' AND (NEW.confirmed_by IS DISTINCT FROM OLD.confirmed_by
            OR NEW.confirmed_credential IS DISTINCT FROM OLD.confirmed_credential OR NEW.confirmed_at IS DISTINCT FROM OLD.confirmed_at) THEN
        RAISE EXCEPTION 'an a2a pin is confirmed once' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'PROPOSED' AND NEW.state <> 'PROPOSED' THEN
        NEW.decided_at := now();
        IF NEW.state = 'ACTIVE' THEN
            NEW.confirmed_at := now();
        END IF;
    END IF;
    IF OLD.drifted_at IS NOT NULL AND (NEW.drifted_at IS DISTINCT FROM OLD.drifted_at OR NEW.observed_digest IS DISTINCT FROM OLD.observed_digest) THEN
        RAISE EXCEPTION 'an a2a pin records its drift once' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER a2a_pins_guard BEFORE INSERT OR UPDATE ON pc.a2a_pins
    FOR EACH ROW EXECUTE FUNCTION pc.a2a_pin_guard();

CREATE TABLE pc.a2a_peer_runs (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    requester_run_id uuid        NOT NULL,
    connection_id    uuid        NOT NULL,
    context_id       text        NOT NULL CHECK (char_length(context_id) <= 256),
    child_run_id     uuid        NOT NULL,
    child_grant_id   uuid        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, child_run_id),
    FOREIGN KEY (org_id, requester_run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, child_run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, child_grant_id) REFERENCES pc.grants (org_id, id),
    CHECK (child_run_id <> requester_run_id)
);
CREATE INDEX a2a_peer_runs_requester ON pc.a2a_peer_runs (org_id, requester_run_id, connection_id, context_id, created_at DESC);
CREATE INDEX a2a_peer_runs_connection ON pc.a2a_peer_runs (org_id, connection_id, created_at DESC);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['a2a_pins', 'a2a_peer_runs']
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

GRANT SELECT, INSERT ON pc.a2a_pins, pc.a2a_peer_runs TO pc_app;
GRANT UPDATE (state, confirmed_by, confirmed_credential, confirmed_at, decided_at, drifted_at, observed_digest)
    ON pc.a2a_pins TO pc_app;
GRANT SELECT ON pc.a2a_pins, pc.a2a_peer_runs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.a2a_peer_runs;
DROP TABLE pc.a2a_pins;
DROP FUNCTION pc.a2a_pin_guard();
