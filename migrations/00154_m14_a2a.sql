-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M14 peer agent calls over A2A (coordinator decisions D30, D33, D64;
-- HR-322, HR-324..326).
--
-- pc.a2a_connections holds an a2a connection's configuration: the agent
-- card as it was fetched and pinned, its digest (SHA-256 of its JCS form),
-- the optional pinned card keys, the interface the gateway calls, the
-- allowed skills, the answer and stream caps and, for a peer enrolled in
-- the same org, that agent and the scope its delegated runs get. Pinning
-- (create, refresh) needs a step-up and is audited; the card is a document,
-- never parsed by the database. A re-read whose digest differs is drift:
-- drifted_at and observed_digest record it and the connection is
-- quarantined until it is pinned again.
--
-- pc.a2a_peer_runs links a requester's run, the connection and the A2A
-- context to the child run (and its delegated grant) the Authority created
-- for the peer agent at BeginDispatch, so the next message in the same
-- context reuses it. An empty context_id is a message that named none.

-- +goose Up
CREATE TABLE pc.a2a_connections (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    connection_id      uuid        NOT NULL,
    card_url           text        NOT NULL CHECK (char_length(card_url) BETWEEN 9 AND 2048 AND card_url ~ '^https?://'),
    binding            text        NOT NULL CHECK (binding IN ('JSONRPC', 'HTTP+JSON')),
    interface_url      text        NOT NULL CHECK (char_length(interface_url) BETWEEN 9 AND 2048 AND interface_url ~ '^https?://'),
    pinned_card        bytea       NOT NULL CHECK (octet_length(pinned_card) BETWEEN 2 AND 262144),
    card_digest        bytea       NOT NULL CHECK (octet_length(card_digest) = 32),
    card_keys          bytea       CHECK (octet_length(card_keys) BETWEEN 2 AND 65536),
    skills             text[]      NOT NULL DEFAULT '{}'
                                   CHECK (cardinality(skills) <= 64 AND array_position(skills, NULL) IS NULL),
    peer_agent_id      uuid,
    peer_bounds        bytea       CHECK (octet_length(peer_bounds) BETWEEN 2 AND 65536),
    peer_limits        bytea       CHECK (octet_length(peer_limits) <= 65536),
    max_answer_bytes   integer     NOT NULL DEFAULT 1048576 CHECK (max_answer_bytes BETWEEN 1024 AND 8388608),
    max_stream_seconds integer     NOT NULL DEFAULT 300 CHECK (max_stream_seconds BETWEEN 1 AND 3600),
    pinned_by          text        NOT NULL CHECK (char_length(pinned_by) BETWEEN 1 AND 100),
    pinned_at          timestamptz NOT NULL DEFAULT now(),
    drifted_at         timestamptz,
    observed_digest    bytea       CHECK (octet_length(observed_digest) = 32),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, peer_agent_id) REFERENCES pc.agents (org_id, id),
    CHECK ((peer_agent_id IS NULL) = (peer_bounds IS NULL)),
    CHECK (peer_limits IS NULL OR peer_agent_id IS NOT NULL),
    CHECK ((drifted_at IS NULL) = (observed_digest IS NULL))
);
CREATE INDEX a2a_connections_peer ON pc.a2a_connections (org_id, peer_agent_id) WHERE peer_agent_id IS NOT NULL;

CREATE TABLE pc.a2a_peer_runs (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    requester_run_id uuid        NOT NULL,
    connection_id    uuid        NOT NULL,
    context_id       text        NOT NULL CHECK (char_length(context_id) <= 256),
    child_run_id     uuid        NOT NULL,
    child_grant_id   uuid        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, requester_run_id, connection_id, context_id),
    UNIQUE (org_id, child_run_id),
    FOREIGN KEY (org_id, requester_run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, child_run_id) REFERENCES pc.runs (org_id, id),
    FOREIGN KEY (org_id, child_grant_id) REFERENCES pc.grants (org_id, id),
    CHECK (child_run_id <> requester_run_id)
);
CREATE INDEX a2a_peer_runs_connection ON pc.a2a_peer_runs (org_id, connection_id, created_at DESC);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['a2a_connections', 'a2a_peer_runs']
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

GRANT SELECT, INSERT ON pc.a2a_connections, pc.a2a_peer_runs TO pc_app;
-- A refreshed pin replaces the card and what was checked against it; the
-- connection a row belongs to never changes.
GRANT UPDATE (card_url, binding, interface_url, pinned_card, card_digest, card_keys, skills, peer_agent_id, peer_bounds,
    peer_limits, max_answer_bytes, max_stream_seconds, pinned_by, pinned_at, drifted_at, observed_digest)
    ON pc.a2a_connections TO pc_app;
GRANT SELECT ON pc.a2a_connections, pc.a2a_peer_runs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.a2a_peer_runs;
DROP TABLE pc.a2a_connections;
