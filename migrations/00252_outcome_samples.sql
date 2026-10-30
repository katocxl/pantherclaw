-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Outcome metric samples (G0 M21 D303, F774; HR-537..540). A nightly rollup
-- writes one sample per metric, dimension and window. A sample holds a
-- distribution or a share, never a raw volume as a value. Not collected is
-- NULL here, never 0: without a measured case the sample has no value and
-- states why. outcome_collection records when an org's collection started;
-- a window that begins earlier is not collected (no backfill).
--
-- policy_rollout_stage_events keeps every stage a rollout reached, which
-- stage_changed_at overwrites. A trigger writes it, so every writer of a
-- stage is covered.

-- +goose Up
CREATE TABLE pc.outcome_collection (
    org_id     uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    started_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pc.outcome_metric_samples (
    org_id       uuid             NOT NULL REFERENCES pc.orgs (id),
    id           uuid             NOT NULL,
    metric       text             NOT NULL CHECK (metric ~ '^[a-z][a-z0-9_.]{0,63}$'),
    -- A breakdown key (for example an automation id), '' for the whole org.
    dimension    text             NOT NULL DEFAULT '' CHECK (char_length(dimension) <= 200),
    window_start timestamptz      NOT NULL CHECK (window_start = date_trunc('day', window_start, 'UTC')),
    window_end   timestamptz      NOT NULL CHECK (window_end = date_trunc('day', window_end, 'UTC')),
    -- What the sample covers (HR-540): only "organization" so far.
    scope        text             NOT NULL DEFAULT 'organization' CHECK (scope IN ('organization')),
    p50_seconds  double precision CHECK (p50_seconds >= 0),
    p90_seconds  double precision CHECK (p90_seconds >= 0),
    share        double precision CHECK (share BETWEEN 0 AND 1),
    -- Cases measured, and cases that could not be, with their reasons.
    measured     bigint           NOT NULL CHECK (measured >= 0),
    unmeasured   bigint           NOT NULL CHECK (unmeasured >= 0),
    reasons      jsonb            NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(reasons) = 'array'
                                                               AND octet_length(reasons::text) <= 4096),
    collected    boolean          NOT NULL,
    sampled_at   timestamptz      NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CONSTRAINT outcome_samples_window CHECK (window_end > window_start AND window_end - window_start <= interval '30 days'),
    -- HR-537: without a measured case there is no value, never a 0.
    CONSTRAINT outcome_samples_collected CHECK (collected = (measured > 0)),
    CONSTRAINT outcome_samples_value CHECK (collected = ((p50_seconds IS NOT NULL) <> (share IS NOT NULL))),
    CONSTRAINT outcome_samples_distribution CHECK ((p50_seconds IS NULL) = (p90_seconds IS NULL)),
    CONSTRAINT outcome_samples_says_why CHECK (collected OR jsonb_array_length(reasons) > 0)
);
CREATE UNIQUE INDEX outcome_metric_samples_point ON pc.outcome_metric_samples (org_id, metric, dimension, window_start, window_end);

CREATE TABLE pc.policy_rollout_stage_events (
    org_id     uuid        NOT NULL,
    rollout_id uuid        NOT NULL,
    from_stage text        CHECK (from_stage IN ('SHADOW', 'PILOT')),
    to_stage   text        NOT NULL CHECK (to_stage IN ('SHADOW', 'PILOT', 'COMPLETE', 'CANCELLED')),
    at         timestamptz NOT NULL DEFAULT now(),
    -- Stages only move forward (policy_rollouts_forward).
    PRIMARY KEY (org_id, rollout_id, to_stage),
    FOREIGN KEY (org_id, rollout_id) REFERENCES pc.policy_rollouts (org_id, id)
);

-- +goose StatementBegin
CREATE FUNCTION pc.policy_rollout_stage_event() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO pc.policy_rollout_stage_events (org_id, rollout_id, to_stage) VALUES (NEW.org_id, NEW.id, NEW.stage);
    ELSIF NEW.stage IS DISTINCT FROM OLD.stage THEN
        INSERT INTO pc.policy_rollout_stage_events (org_id, rollout_id, from_stage, to_stage)
        VALUES (NEW.org_id, NEW.id, OLD.stage, NEW.stage);
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_rollouts_stage_event AFTER INSERT OR UPDATE OF stage ON pc.policy_rollouts
    FOR EACH ROW EXECUTE FUNCTION pc.policy_rollout_stage_event();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['outcome_collection', 'outcome_metric_samples', 'policy_rollout_stage_events']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT ON pc.outcome_collection, pc.outcome_metric_samples, pc.policy_rollout_stage_events TO pc_app;
GRANT INSERT (org_id) ON pc.outcome_collection TO pc_app;
GRANT INSERT (org_id, id, metric, dimension, window_start, window_end, p50_seconds, p90_seconds, share, measured, unmeasured,
              reasons, collected) ON pc.outcome_metric_samples TO pc_app;
GRANT INSERT (org_id, rollout_id, from_stage, to_stage) ON pc.policy_rollout_stage_events TO pc_app;
GRANT SELECT ON pc.outcome_collection, pc.outcome_metric_samples, pc.policy_rollout_stage_events TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.outcome_collection, pc.outcome_metric_samples, pc.policy_rollout_stage_events TO pc_deleter;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER policy_rollouts_stage_event ON pc.policy_rollouts;
DROP FUNCTION pc.policy_rollout_stage_event();
DROP TABLE pc.policy_rollout_stage_events;
DROP TABLE pc.outcome_metric_samples;
DROP TABLE pc.outcome_collection;
