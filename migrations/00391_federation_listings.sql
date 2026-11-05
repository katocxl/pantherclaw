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
-- A cross-org grant's principal is federated: the peer org and the peer
-- agent (its PAP subject), instead of a user or a service account. Its
-- agent is the listing's agent, and it is still issued by a person.
--
-- A federation run is the run a peer agent's calls are decided in: one per
-- (trust, peer agent, UTC day) while active. It has no launcher and no
-- principal of this org; it names the trust, the peer org and peer agent,
-- and the cross-org grant.

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

-- +goose Down
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
DROP TABLE pc.federation_listings;
