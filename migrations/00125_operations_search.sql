-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Operations and search (G0 M10 coordinator decisions D33, D34; F301,
-- F317; HR-257, HR-258).
--
-- saved_queries holds structured searches people save and share. A saved
-- query is only its specification: an entity with typed filters, or a
-- built-in query with its parameters, never SQL and never results. It is
-- always re-run under the viewer's own permissions, so sharing it (TEAM or
-- ORG) never widens what anyone sees (HR-257). Only its owner changes or
-- deletes it.
--
-- metric_samples holds the hourly operating metrics (F301, Team). A sample
-- is either a collected value or an explicit "not collected" (value NULL),
-- never a silent zero (HR-258). Samples are written once per metric,
-- dimension and hour and never changed.

-- +goose Up
CREATE TABLE pc.saved_queries (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    id          uuid        NOT NULL,
    -- The owner's principal reference ("user:<id>" or "service_account:<id>").
    owner       text        NOT NULL CHECK (owner ~ '^(user|service_account):[0-9a-f-]{36}$'),
    name        text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 120),
    description text        NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    visibility  text        NOT NULL CHECK (visibility IN ('PRIVATE', 'TEAM', 'ORG')),
    -- The team a TEAM query is shared with.
    team_id     uuid,
    spec        jsonb       NOT NULL CHECK (jsonb_typeof(spec) = 'object' AND octet_length(spec::text) <= 8192),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, team_id) REFERENCES pc.teams (org_id, id),
    CHECK ((visibility = 'TEAM') = (team_id IS NOT NULL))
);
CREATE UNIQUE INDEX saved_queries_owner_name ON pc.saved_queries (org_id, owner, name);
CREATE INDEX saved_queries_visible ON pc.saved_queries (org_id, visibility, id DESC);

CREATE TABLE pc.metric_samples (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    metric     text        NOT NULL CHECK (metric ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- A breakdown key (for example a resource group), '' for the whole org.
    dimension  text        NOT NULL DEFAULT '' CHECK (char_length(dimension) <= 200),
    -- The start of the hour the sample covers (UTC).
    bucket     timestamptz NOT NULL CHECK (bucket = date_trunc('hour', bucket, 'UTC')),
    -- NULL when the source was not collected for that hour.
    value      double precision,
    collected  boolean     NOT NULL,
    sampled_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CHECK (collected = (value IS NOT NULL))
);
CREATE UNIQUE INDEX metric_samples_point ON pc.metric_samples (org_id, metric, dimension, bucket);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['saved_queries', 'metric_samples']
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

-- A saved query's owner and creation never change; updated_at is the
-- database's.
-- +goose StatementBegin
CREATE FUNCTION pc.saved_query_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER saved_queries_update BEFORE UPDATE ON pc.saved_queries
    FOR EACH ROW EXECUTE FUNCTION pc.saved_query_update();

GRANT SELECT, DELETE ON pc.saved_queries TO pc_app;
GRANT INSERT (org_id, id, owner, name, description, visibility, team_id, spec) ON pc.saved_queries TO pc_app;
GRANT UPDATE (name, description, visibility, team_id, spec) ON pc.saved_queries TO pc_app;
GRANT SELECT ON pc.metric_samples TO pc_app;
GRANT INSERT (org_id, id, metric, dimension, bucket, value, collected) ON pc.metric_samples TO pc_app;
GRANT SELECT ON pc.saved_queries, pc.metric_samples TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.metric_samples;
DROP TABLE pc.saved_queries;
DROP FUNCTION pc.saved_query_update();
