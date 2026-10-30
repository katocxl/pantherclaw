-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The shared hosting hosts (G0 M19 D203, ADR-0041): the operator's hosts
-- that run one gateway process per org, and the certificates of their host
-- agents. A host certificate names one host and the purpose "hosting" and
-- no org (HR-500). The tables are operator-level: they hold no tenant data
-- and no org_id, and their rows are visible only in a global transaction
-- of the purpose "hosting" (app.purpose), like pc.rate_counters. Which
-- org's gateway runs on which host is in the tenant table
-- pc.hosted_gateways (00229), reached across orgs only through the audited
-- lister (HR-054).
-- +goose Up
CREATE TABLE pc.hosting_hosts (
    id           uuid        PRIMARY KEY,
    name         text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    -- domain: agents reach an org's process on this host as
    -- <slug>.gw.<domain>; one host per domain.
    domain       text        NOT NULL UNIQUE CHECK (char_length(domain) <= 253 AND domain ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'),
    state        text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DRAINING', 'RETIRED')),
    -- capacity: the most hosted gateways the host runs (T-218).
    capacity     integer     NOT NULL CHECK (capacity BETWEEN 1 AND 1000),
    milli_cpus   integer     NOT NULL CHECK (milli_cpus BETWEEN 100 AND 1024000),
    memory_mib   integer     NOT NULL CHECK (memory_mib BETWEEN 128 AND 16777216),
    agent_version text       CHECK (char_length(agent_version) <= 64),
    last_seen    timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pc.hosting_host_certs (
    id             uuid        PRIMARY KEY,
    host_id        uuid        NOT NULL REFERENCES pc.hosting_hosts (id),
    serial         bytea       NOT NULL CHECK (octet_length(serial) BETWEEN 1 AND 20),
    key_thumbprint text        NOT NULL CHECK (char_length(key_thumbprint) <= 64),
    state          text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
    issued_via     text        NOT NULL CHECK (issued_via IN ('ENROLL', 'RENEW')),
    previous_id    uuid        REFERENCES pc.hosting_host_certs (id),
    not_before     timestamptz NOT NULL,
    not_after      timestamptz NOT NULL CHECK (not_after > not_before),
    superseded_at  timestamptz,
    revoked_at     timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX hosting_host_certs_host ON pc.hosting_host_certs (host_id);

ALTER TABLE pc.hosting_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.hosting_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY hosting_purpose ON pc.hosting_hosts
    USING ((SELECT current_setting('app.purpose', true)) = 'hosting')
    WITH CHECK ((SELECT current_setting('app.purpose', true)) = 'hosting');
ALTER TABLE pc.hosting_host_certs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.hosting_host_certs FORCE ROW LEVEL SECURITY;
CREATE POLICY hosting_purpose ON pc.hosting_host_certs
    USING ((SELECT current_setting('app.purpose', true)) = 'hosting')
    WITH CHECK ((SELECT current_setting('app.purpose', true)) = 'hosting');

GRANT SELECT, INSERT ON pc.hosting_hosts TO pc_app;
GRANT UPDATE (state, capacity, milli_cpus, memory_mib, agent_version, last_seen) ON pc.hosting_hosts TO pc_app;
GRANT SELECT, INSERT ON pc.hosting_host_certs TO pc_app;
GRANT UPDATE (state, superseded_at, revoked_at) ON pc.hosting_host_certs TO pc_app;
GRANT SELECT ON pc.hosting_hosts, pc.hosting_host_certs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.hosting_host_certs;
DROP TABLE pc.hosting_hosts;
