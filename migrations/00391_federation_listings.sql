-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Federation listings, the federation channel, cross-org grants and
-- federation runs (G0 M35 D1022, D1024; HR-773..775).
--
-- pc.federation_listings are the org's agents a trusted peer org's agents
-- may message: a name, the agent, the a2a connection the gateway forwards
-- through (whose peer is that agent) and the skills offered. Each ACTIVE
-- listing appears in the org's federation document.
--
-- Channel federation is a trusted peer org's agent messaging one of ours
-- through the gateway's federation face. It widens the channel lists of
-- transactions and coverage routes, following 00150's pattern.
--
-- A federated agent stands for one peer agent of one trust in this org
-- (D1024c): a pc.agents row (execution context federation, owned by the
-- person who first issued it a cross-org grant, in the listing agent's
-- team and environment) with one ADMITTED instance (enrolled via
-- federation, no key: its jkt is a synthetic digest no key has, and it
-- never verifies a PAP/1 proof). pc.federation_agents links them. The
-- agent is suspended when the trust is revoked.
--
-- A cross-org grant's principal is federated: the peer org and the peer
-- agent (its PAP subject), instead of a user or a service account. Its
-- agent is the federated agent, and it is still issued by a person.
--
-- A federation run is the run a peer agent's calls are decided in: one per
-- (trust, peer agent, UTC day) while active, of the federated agent and
-- its instance. It has no launcher and no principal of this org; it names
-- the trust, the peer org and peer agent, and the cross-org grant.
--
-- pc.federation_calls are the calls StartFederatedCall admitted: the
-- verified peer token's request (listing, htu, body digest) bound to the
-- run, for 60 seconds. Authorize on channel federation names one and uses
-- it once.

-- +goose Up
CREATE TABLE pc.federation_listings (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    name          text        NOT NULL CHECK (name ~ '^[a-z0-9-]{1,63}$'),
    agent_id      uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    skills        text[]      NOT NULL DEFAULT '{}'
                              CHECK (cardinality(skills) <= 64 AND array_position(skills, NULL) IS NULL),
    state         text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RETIRED')),
    created_by    text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at    timestamptz NOT NULL DEFAULT now(),
    retired_by    text        CHECK (char_length(retired_by) BETWEEN 1 AND 128),
    retired_at    timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CONSTRAINT federation_listings_retired CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL)
        AND (retired_at IS NULL) = (retired_by IS NULL))
);
CREATE UNIQUE INDEX federation_listings_active_name ON pc.federation_listings (org_id, name) WHERE state = 'ACTIVE';

ALTER TABLE pc.federation_listings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.federation_listings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.federation_listings
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.federation_listings
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
GRANT SELECT, INSERT ON pc.federation_listings TO pc_app;
GRANT UPDATE (state, retired_by, retired_at) ON pc.federation_listings TO pc_app;
GRANT SELECT ON pc.federation_listings TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.federation_listings TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- squawk: each CHECK only widens a value list; goose runs each migration
-- in one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.agents
    DROP CONSTRAINT agents_execution_context_check,
    ADD CONSTRAINT agents_execution_context_check
        CHECK (execution_context IN ('desktop', 'ci', 'kubernetes', 'service', 'federation')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agents VALIDATE CONSTRAINT agents_execution_context_check;
ALTER TABLE pc.agent_instances
    DROP CONSTRAINT agent_instances_enrolled_via_check,
    ADD CONSTRAINT agent_instances_enrolled_via_check
        CHECK (enrolled_via IN ('enrollment_token', 'attestation', 'discovery', 'mcp_client', 'federation')) NOT VALID,
    ADD CONSTRAINT agent_instances_federation
        CHECK (enrolled_via <> 'federation' OR (att_level = 1 AND issuer_revision_id IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agent_instances VALIDATE CONSTRAINT agent_instances_enrolled_via_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.agent_instances VALIDATE CONSTRAINT agent_instances_federation;

CREATE TABLE pc.federation_agents (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    trust_id    uuid        NOT NULL,
    peer_agent  text        NOT NULL CHECK (char_length(peer_agent) BETWEEN 1 AND 512),
    agent_id    uuid        NOT NULL,
    instance_id uuid        NOT NULL,
    created_by  text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, trust_id, peer_agent),
    UNIQUE (org_id, agent_id),
    FOREIGN KEY (org_id, trust_id) REFERENCES pc.federation_trusts (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, instance_id) REFERENCES pc.agent_instances (org_id, id)
);

ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_channel_check,
    ADD CONSTRAINT transactions_channel_check
        CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook', 'authzen', 'a2a', 'runtime', 'federation')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_channel_check;

ALTER TABLE pc.coverage_routes
    DROP CONSTRAINT coverage_routes_channel_check,
    ADD CONSTRAINT coverage_routes_channel_check
        CHECK (channel IN ('http', 'mcp', 'sdk', 'hook', 'authzen', 'a2a', 'runtime', 'federation')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.coverage_routes VALIDATE CONSTRAINT coverage_routes_channel_check;

-- Cross-org grants (D1024). The new columns are NULL in every row, so the
-- widened checks hold at once.
ALTER TABLE pc.grants
    ADD COLUMN peer_org_id uuid,
    ADD COLUMN peer_agent  text CHECK (char_length(peer_agent) BETWEEN 1 AND 512),
    DROP CONSTRAINT grants_one_principal,
    ADD CONSTRAINT grants_one_principal
        CHECK (num_nonnulls(principal_user_id, principal_sa_id, peer_org_id) = 1) NOT VALID,
    ADD CONSTRAINT grants_federated_principal CHECK ((peer_org_id IS NULL) = (peer_agent IS NULL)) NOT VALID,
    -- A cross-org grant is a root grant a person issued: it never delegates.
    ADD CONSTRAINT grants_federated_root CHECK (peer_org_id IS NULL OR (parent_id IS NULL AND grantor_kind = 'user')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_one_principal;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_federated_principal;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.grants VALIDATE CONSTRAINT grants_federated_root;
CREATE INDEX grants_peer ON pc.grants (org_id, peer_org_id, peer_agent) WHERE peer_org_id IS NOT NULL;

-- Federation runs (D1024).
ALTER TABLE pc.runs
    ADD COLUMN federation_trust_id uuid,
    ADD COLUMN peer_org_id         uuid,
    ADD COLUMN peer_agent          text CHECK (char_length(peer_agent) BETWEEN 1 AND 512),
    ADD COLUMN federation_day      date,
    DROP CONSTRAINT runs_principal_source_check,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation', 'id_jag', 'trusted_issuer',
                                    'federation')) NOT VALID,
    DROP CONSTRAINT runs_one_launcher,
    ADD CONSTRAINT runs_one_launcher CHECK (num_nonnulls(launcher_user_id, launcher_sa_id, launcher_instance_id)
        = CASE WHEN principal_source = 'federation' THEN 0 ELSE 1 END) NOT VALID,
    DROP CONSTRAINT runs_one_principal,
    ADD CONSTRAINT runs_one_principal CHECK (num_nonnulls(principal_user_id, principal_sa_id)
        = CASE WHEN principal_source = 'federation' THEN 0 ELSE 1 END) NOT VALID,
    ADD CONSTRAINT runs_federation CHECK (
        (principal_source = 'federation') = (federation_trust_id IS NOT NULL)
        AND (federation_trust_id IS NULL) = (peer_org_id IS NULL)
        AND (federation_trust_id IS NULL) = (peer_agent IS NULL)
        AND (federation_trust_id IS NULL) = (federation_day IS NULL)
        AND (federation_trust_id IS NULL OR grant_id IS NOT NULL)) NOT VALID;
-- The new column is NULL in every row, so the foreign key holds at once.
-- squawk-ignore adding-foreign-key-constraint
ALTER TABLE pc.runs
    ADD CONSTRAINT runs_federation_trust_fkey FOREIGN KEY (org_id, federation_trust_id)
        REFERENCES pc.federation_trusts (org_id, id) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_principal_source_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_one_launcher;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_one_principal;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_federation;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_federation_trust_fkey;
-- squawk-ignore require-concurrent-index-creation
CREATE UNIQUE INDEX runs_federation_day ON pc.runs (org_id, federation_trust_id, peer_agent, federation_day)
    WHERE principal_source = 'federation' AND state = 'ACTIVE';

CREATE TABLE pc.federation_calls (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    trust_id    uuid        NOT NULL,
    peer_agent  text        NOT NULL CHECK (char_length(peer_agent) BETWEEN 1 AND 512),
    run_id      uuid        NOT NULL,
    agent_id    uuid        NOT NULL,
    instance_id uuid        NOT NULL,
    listing     text        NOT NULL CHECK (listing ~ '^[a-z0-9-]{1,63}$'),
    htu         text        NOT NULL CHECK (char_length(htu) BETWEEN 9 AND 2048),
    body_sha256 bytea       NOT NULL CHECK (octet_length(body_sha256) = 32),
    -- The IN receipt: the peer's pap-fed+jwt this call was admitted on.
    receipt_id  uuid        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    -- The action Authorize decided on it (set with used_at).
    action_id   uuid,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, trust_id) REFERENCES pc.federation_trusts (org_id, id),
    FOREIGN KEY (org_id, run_id) REFERENCES pc.runs (org_id, id),
    CONSTRAINT federation_calls_lifetime CHECK (expires_at > created_at AND expires_at <= created_at + interval '60 seconds'),
    CONSTRAINT federation_calls_used CHECK ((used_at IS NULL) = (action_id IS NULL))
);
CREATE INDEX federation_calls_expiry ON pc.federation_calls (org_id, expires_at);
CREATE INDEX federation_calls_action ON pc.federation_calls (org_id, action_id) WHERE action_id IS NOT NULL;

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['federation_agents', 'federation_calls'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I
            FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format('GRANT SELECT ON pc.%I TO pc_audit_ro', t);
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
            EXECUTE format('GRANT SELECT, DELETE ON pc.%I TO pc_deleter', t);
        END IF;
    END LOOP;
END
$$;
-- +goose StatementEnd
GRANT SELECT, INSERT ON pc.federation_agents TO pc_app;
GRANT SELECT, INSERT, DELETE ON pc.federation_calls TO pc_app;
GRANT UPDATE (used_at, action_id) ON pc.federation_calls TO pc_app;

-- +goose Down
DROP TABLE pc.federation_calls;
DROP INDEX pc.runs_federation_day;
ALTER TABLE pc.runs
    DROP CONSTRAINT runs_federation_trust_fkey,
    DROP CONSTRAINT runs_federation,
    DROP CONSTRAINT runs_one_principal,
    ADD CONSTRAINT runs_one_principal CHECK (num_nonnulls(principal_user_id, principal_sa_id) = 1),
    DROP CONSTRAINT runs_one_launcher,
    ADD CONSTRAINT runs_one_launcher CHECK (num_nonnulls(launcher_user_id, launcher_sa_id, launcher_instance_id) = 1),
    DROP CONSTRAINT runs_principal_source_check,
    ADD CONSTRAINT runs_principal_source_check
        CHECK (principal_source IN ('launcher', 'subject_token', 'parent_run', 'automation', 'id_jag', 'trusted_issuer')),
    DROP COLUMN federation_day,
    DROP COLUMN peer_agent,
    DROP COLUMN peer_org_id,
    DROP COLUMN federation_trust_id;
DROP INDEX pc.grants_peer;
ALTER TABLE pc.grants
    DROP CONSTRAINT grants_federated_root,
    DROP CONSTRAINT grants_federated_principal,
    DROP CONSTRAINT grants_one_principal,
    ADD CONSTRAINT grants_one_principal CHECK (num_nonnulls(principal_user_id, principal_sa_id) = 1),
    DROP COLUMN peer_agent,
    DROP COLUMN peer_org_id;
ALTER TABLE pc.coverage_routes
    DROP CONSTRAINT coverage_routes_channel_check,
    ADD CONSTRAINT coverage_routes_channel_check CHECK (channel IN ('http', 'mcp', 'sdk', 'hook', 'authzen', 'a2a', 'runtime'));
ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_channel_check,
    ADD CONSTRAINT transactions_channel_check CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook', 'authzen', 'a2a', 'runtime'));
DROP TABLE pc.federation_agents;
ALTER TABLE pc.agent_instances
    DROP CONSTRAINT agent_instances_federation,
    DROP CONSTRAINT agent_instances_enrolled_via_check,
    ADD CONSTRAINT agent_instances_enrolled_via_check
        CHECK (enrolled_via IN ('enrollment_token', 'attestation', 'discovery', 'mcp_client'));
ALTER TABLE pc.agents
    DROP CONSTRAINT agents_execution_context_check,
    ADD CONSTRAINT agents_execution_context_check
        CHECK (execution_context IN ('desktop', 'ci', 'kubernetes', 'service'));
DROP TABLE pc.federation_listings;
