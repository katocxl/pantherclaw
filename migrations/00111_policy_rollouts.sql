-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Policy rollouts, pilot cohorts, per-agent target status and shadow
-- results (G0 M11.1, coordinator decisions D12 and D13; F200–F205, HR-232,
-- HR-233, HR-234, HR-237). A rollout takes one policy version through
-- SHADOW (replayed beside the published version, never enforced), PILOT
-- (enforced for the agents of its ENFORCE cohorts) and COMPLETE (published
-- for everyone), or is CANCELLED. At most one rollout per org is in SHADOW
-- or PILOT. Targets are agents (founder decision F3): CONFIGURED,
-- ACKNOWLEDGED (a live decision used the version), VERIFIED (its routes for
-- the version's operations are covered), FAILED (decided with the published
-- version because the rollout version could not be used) or EXCEPTION
-- (excluded by a person, stays on the published version).
--
-- The Authority only reads these tables, to select an agent's version; the
-- rollout sweeper writes target states and shadow results (HR-233). The
-- sweeper lists orgs through the audited cross-org lister (purpose
-- policy_rollouts_due): orgs with a rollout in SHADOW or PILOT, or one
-- completed less than 7 days ago with targets not VERIFIED.

-- +goose Up
CREATE TABLE pc.policy_cohorts (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    id         uuid        NOT NULL,
    name       text        NOT NULL CHECK (name ~ '^[a-z][a-z0-9-]{0,63}$'),
    -- Kept by the members trigger; at most 1 000 members per cohort.
    members    integer     NOT NULL DEFAULT 0 CHECK (members BETWEEN 0 AND 1000),
    created_by text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name)
);

CREATE TABLE pc.policy_cohort_members (
    org_id    uuid        NOT NULL,
    cohort_id uuid        NOT NULL,
    agent_id  uuid        NOT NULL,
    added_by  text        NOT NULL CHECK (char_length(added_by) BETWEEN 1 AND 100),
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, cohort_id, agent_id),
    FOREIGN KEY (org_id, cohort_id) REFERENCES pc.policy_cohorts (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id)
);
-- The Authority's selection reads cohorts by agent.
CREATE INDEX policy_cohort_members_agent ON pc.policy_cohort_members (org_id, agent_id);

CREATE TABLE pc.policy_rollouts (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    version_id       uuid        NOT NULL,
    -- The version published when the rollout started (or its pilot did);
    -- NULL when none was.
    base_version_id  uuid,
    stage            text        NOT NULL CHECK (stage IN ('SHADOW', 'PILOT', 'COMPLETE', 'CANCELLED')),
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 100),
    created_at       timestamptz NOT NULL DEFAULT now(),
    stage_changed_at timestamptz NOT NULL DEFAULT now(),
    completed_at     timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, version_id) REFERENCES pc.policy_versions (org_id, id),
    FOREIGN KEY (org_id, base_version_id) REFERENCES pc.policy_versions (org_id, id),
    CONSTRAINT policy_rollouts_completed CHECK ((stage = 'COMPLETE') = (completed_at IS NOT NULL))
);
-- One rollout per org in SHADOW or PILOT (D12).
CREATE UNIQUE INDEX policy_rollouts_open ON pc.policy_rollouts (org_id) WHERE stage IN ('SHADOW', 'PILOT');
CREATE INDEX policy_rollouts_org ON pc.policy_rollouts (org_id, created_at DESC);

CREATE TABLE pc.policy_rollout_cohorts (
    org_id     uuid NOT NULL,
    rollout_id uuid NOT NULL,
    cohort_id  uuid NOT NULL,
    mode       text NOT NULL CHECK (mode IN ('SHADOW', 'ENFORCE')),
    PRIMARY KEY (org_id, rollout_id, cohort_id),
    FOREIGN KEY (org_id, rollout_id) REFERENCES pc.policy_rollouts (org_id, id),
    FOREIGN KEY (org_id, cohort_id) REFERENCES pc.policy_cohorts (org_id, id)
);

CREATE TABLE pc.policy_rollout_targets (
    org_id     uuid        NOT NULL,
    rollout_id uuid        NOT NULL,
    agent_id   uuid        NOT NULL,
    state      text        NOT NULL CHECK (state IN ('CONFIGURED', 'ACKNOWLEDGED', 'VERIFIED', 'FAILED', 'EXCEPTION')),
    -- The agent's owner, who resolves a target that does not verify (F3).
    owner_id   uuid,
    -- The weakest coverage state seen for the version's operations.
    coverage   text        CHECK (coverage IN ('UNKNOWN', 'OBSERVE_ONLY', 'PARTIAL', 'ENFORCED')),
    reason     text        CHECK (char_length(reason) BETWEEN 1 AND 500),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, rollout_id, agent_id),
    FOREIGN KEY (org_id, rollout_id) REFERENCES pc.policy_rollouts (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, owner_id) REFERENCES pc.users (org_id, id)
);
CREATE INDEX policy_rollout_targets_state ON pc.policy_rollout_targets (org_id, rollout_id, state);

-- How far the sweeper has read an org's decisions for a rollout.
CREATE TABLE pc.policy_rollout_cursors (
    org_id          uuid        NOT NULL,
    rollout_id      uuid        NOT NULL,
    last_created_at timestamptz NOT NULL,
    last_txn        uuid        NOT NULL,
    PRIMARY KEY (org_id, rollout_id),
    FOREIGN KEY (org_id, rollout_id) REFERENCES pc.policy_rollouts (org_id, id)
);

-- One shadow evaluation (D13): the recorded decision and what the rollout
-- version would have decided, ids, decisions and reasons only (HR-237).
CREATE TABLE pc.policy_shadow_results (
    org_id            uuid        NOT NULL,
    rollout_id        uuid        NOT NULL,
    transaction_id    uuid        NOT NULL,
    evaluation        integer     NOT NULL CHECK (evaluation BETWEEN 1 AND 64),
    agent_id          uuid        NOT NULL,
    operation         text        NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 128),
    original_decision text        NOT NULL CHECK (original_decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS', 'REQUIRE_APPROVAL',
                                                                        'REQUIRE_STEP_UP', 'DENY', 'CANNOT_AUTHORIZE')),
    original_reason   text        NOT NULL CHECK (char_length(original_reason) BETWEEN 1 AND 64),
    shadow_decision   text        CHECK (shadow_decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS', 'REQUIRE_APPROVAL',
                                                             'REQUIRE_STEP_UP', 'DENY', 'CANNOT_AUTHORIZE')),
    shadow_reason     text        CHECK (char_length(shadow_reason) BETWEEN 1 AND 64),
    category          text        NOT NULL CHECK (category IN ('UNCHANGED', 'NEWLY_DENIED', 'NEWLY_HELD', 'NEWLY_CONSTRAINED',
                                                               'NEWLY_ALLOWED', 'REASON_CHANGED', 'UNEVALUABLE')),
    -- The limitation codes of an UNEVALUABLE replay, comma-separated.
    limitation        text        CHECK (char_length(limitation) BETWEEN 1 AND 500),
    created_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, rollout_id, transaction_id, evaluation),
    FOREIGN KEY (org_id, rollout_id) REFERENCES pc.policy_rollouts (org_id, id),
    CONSTRAINT policy_shadow_results_evaluable CHECK ((category = 'UNEVALUABLE') = (shadow_decision IS NULL)),
    CONSTRAINT policy_shadow_results_reason CHECK ((shadow_decision IS NULL) = (shadow_reason IS NULL))
);
CREATE INDEX policy_shadow_results_rollout ON pc.policy_shadow_results (org_id, rollout_id, created_at DESC);

-- Counts of every shadow evaluation by day and category, kept past the
-- 100 000 rows a rollout's results hold (D13).
CREATE TABLE pc.policy_shadow_counts (
    org_id     uuid    NOT NULL,
    rollout_id uuid    NOT NULL,
    day        date    NOT NULL,
    category   text    NOT NULL CHECK (category IN ('UNCHANGED', 'NEWLY_DENIED', 'NEWLY_HELD', 'NEWLY_CONSTRAINED',
                                                    'NEWLY_ALLOWED', 'REASON_CHANGED', 'UNEVALUABLE')),
    n          bigint  NOT NULL CHECK (n >= 0),
    PRIMARY KEY (org_id, rollout_id, day, category),
    FOREIGN KEY (org_id, rollout_id) REFERENCES pc.policy_rollouts (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['policy_cohorts', 'policy_cohort_members', 'policy_rollouts', 'policy_rollout_cohorts',
                             'policy_rollout_targets', 'policy_rollout_cursors', 'policy_shadow_results', 'policy_shadow_counts']
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

-- A cohort holds at most 1 000 agents: the member count is kept here, under
-- the cohort row's lock, so two concurrent additions cannot both pass.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_cohort_members_count() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = pc, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE pc.policy_cohorts SET members = members + 1
        WHERE org_id = NEW.org_id AND id = NEW.cohort_id AND members < 1000;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'cohort % holds at most 1000 agents', NEW.cohort_id USING ERRCODE = 'check_violation';
        END IF;
    ELSE
        UPDATE pc.policy_cohorts SET members = members - 1 WHERE org_id = OLD.org_id AND id = OLD.cohort_id;
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_cohort_members_count AFTER INSERT OR DELETE ON pc.policy_cohort_members
    FOR EACH ROW EXECUTE FUNCTION pc.policy_cohort_members_count();
REVOKE ALL ON FUNCTION pc.policy_cohort_members_count() FROM PUBLIC;

-- A rollout starts in SHADOW (Team), or is recorded COMPLETE when a version
-- is published without one (status only); completed_at is the database's.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_rollout_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.stage NOT IN ('SHADOW', 'COMPLETE') THEN
        RAISE EXCEPTION 'a rollout starts in SHADOW or is recorded COMPLETE' USING ERRCODE = 'check_violation';
    END IF;
    NEW.completed_at := CASE WHEN NEW.stage = 'COMPLETE' THEN now() END;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_rollouts_insert BEFORE INSERT ON pc.policy_rollouts
    FOR EACH ROW EXECUTE FUNCTION pc.policy_rollout_insert();

-- A rollout moves forward only: SHADOW to PILOT, COMPLETE or CANCELLED;
-- PILOT to COMPLETE or CANCELLED. Its times are the database's.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_rollout_forward() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.stage IS DISTINCT FROM OLD.stage THEN
        IF NOT ((OLD.stage = 'SHADOW' AND NEW.stage IN ('PILOT', 'COMPLETE', 'CANCELLED'))
                OR (OLD.stage = 'PILOT' AND NEW.stage IN ('COMPLETE', 'CANCELLED'))) THEN
            RAISE EXCEPTION 'rollout % cannot move from % to %', OLD.id, OLD.stage, NEW.stage USING ERRCODE = 'check_violation';
        END IF;
        NEW.stage_changed_at := now();
        IF NEW.stage = 'COMPLETE' THEN
            NEW.completed_at := now();
        END IF;
    ELSIF OLD.stage NOT IN ('SHADOW', 'PILOT') THEN
        RAISE EXCEPTION 'rollout % is %', OLD.id, OLD.stage USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_rollouts_forward BEFORE UPDATE ON pc.policy_rollouts
    FOR EACH ROW EXECUTE FUNCTION pc.policy_rollout_forward();

-- pc_app inserts no time. Shadow results and counts are written only by the
-- sweeper; targets change only their state columns.
GRANT SELECT ON pc.policy_cohorts, pc.policy_cohort_members, pc.policy_rollouts, pc.policy_rollout_cohorts,
    pc.policy_rollout_targets, pc.policy_rollout_cursors, pc.policy_shadow_results, pc.policy_shadow_counts TO pc_app;
GRANT INSERT (org_id, id, name, created_by) ON pc.policy_cohorts TO pc_app;
GRANT INSERT (org_id, cohort_id, agent_id, added_by), DELETE ON pc.policy_cohort_members TO pc_app;
GRANT INSERT (org_id, id, version_id, base_version_id, stage, created_by) ON pc.policy_rollouts TO pc_app;
GRANT UPDATE (stage, base_version_id) ON pc.policy_rollouts TO pc_app;
GRANT INSERT (org_id, rollout_id, cohort_id, mode) ON pc.policy_rollout_cohorts TO pc_app;
GRANT UPDATE (mode) ON pc.policy_rollout_cohorts TO pc_app;
GRANT INSERT (org_id, rollout_id, agent_id, state, owner_id, coverage, reason) ON pc.policy_rollout_targets TO pc_app;
GRANT UPDATE (state, owner_id, coverage, reason, updated_at) ON pc.policy_rollout_targets TO pc_app;
GRANT INSERT (org_id, rollout_id, last_created_at, last_txn), UPDATE (last_created_at, last_txn) ON pc.policy_rollout_cursors TO pc_app;
GRANT INSERT (org_id, rollout_id, transaction_id, evaluation, agent_id, operation, original_decision, original_reason,
    shadow_decision, shadow_reason, category, limitation) ON pc.policy_shadow_results TO pc_app;
GRANT INSERT (org_id, rollout_id, day, category, n), UPDATE (n) ON pc.policy_shadow_counts TO pc_app;
GRANT SELECT ON pc.policy_cohorts, pc.policy_cohort_members, pc.policy_rollouts, pc.policy_rollout_cohorts,
    pc.policy_rollout_targets, pc.policy_rollout_cursors, pc.policy_shadow_results, pc.policy_shadow_counts TO pc_audit_ro;

GRANT SELECT (org_id, id, stage, completed_at) ON pc.policy_rollouts TO pc_lister;
GRANT SELECT (org_id, rollout_id, state) ON pc.policy_rollout_targets TO pc_lister;

-- The lister below replaces the whole function, starting from 00087's.
-- Refuse to run if the current one has purposes it does not carry (a
-- migration merged before this one added them), rather than drop them:
-- add them below and to this list first.
-- +goose StatementBegin
DO $$
DECLARE
    found text[];
BEGIN
    SELECT array_agg(m[1] ORDER BY m[1]) INTO found
    FROM regexp_matches(
        (SELECT prosrc FROM pg_proc WHERE oid = 'pc.cross_org_list(text, integer)'::regprocedure),
        'WHEN ''([a-z_]+)'' THEN', 'g') AS m;
    IF found IS DISTINCT FROM ARRAY['budget_settle', 'checkpoints_due', 'coverage_reassess', 'integrity_due',
                                    'ledger_unchained', 'orgs', 'permits_sweep', 'retention_due', 'verifications_due'] THEN
        RAISE EXCEPTION '00111_policy_rollouts: pc.cross_org_list has purposes %; carry the new ones into this migration', found;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'coverage_reassess' THEN
            -- Active orgs with pending coverage invalidations, with
            -- transactions the route inventory has not read (a minute
            -- behind the clock), or with a current ENFORCED snapshot past
            -- its expiry (HR-211).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND (EXISTS (SELECT 1 FROM pc.coverage_invalidations i WHERE i.org_id = o.id AND i.reassessed_at IS NULL)
                       OR EXISTS (SELECT 1 FROM pc.transactions t
                                  WHERE t.org_id = o.id AND t.created_at < now() - interval '1 minute'
                                    AND t.id > coalesce((SELECT w.transactions_after FROM pc.coverage_inventory w
                                                         WHERE w.org_id = o.id), '00000000-0000-0000-0000-000000000000'))
                       OR EXISTS (SELECT 1 FROM pc.coverage_snapshots s
                                  WHERE s.org_id = o.id AND s.state = 'ENFORCED' AND s.expires_at <= now()
                                    AND NOT EXISTS (SELECT 1 FROM pc.coverage_snapshots n
                                                    WHERE n.org_id = s.org_id AND n.agent_id = s.agent_id
                                                      AND n.connection_id = s.connection_id
                                                      AND n.operation = s.operation AND n.id > s.id)))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'policy_rollouts_due' THEN
            -- Active orgs with a policy rollout in SHADOW or PILOT, or one
            -- completed less than 7 days ago with targets not VERIFIED (G0
            -- M11.1, D12).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND EXISTS (SELECT 1 FROM pc.policy_rollouts r
                              WHERE r.org_id = o.id
                                AND (r.stage IN ('SHADOW', 'PILOT')
                                     OR (r.stage = 'COMPLETE' AND r.completed_at > now() - interval '7 days'
                                         AND EXISTS (SELECT 1 FROM pc.policy_rollout_targets t
                                                     WHERE t.org_id = r.org_id AND t.rollout_id = r.id
                                                       AND t.state <> 'VERIFIED'))))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'coverage_reassess' THEN
            -- Active orgs with pending coverage invalidations, with
            -- transactions the route inventory has not read (a minute
            -- behind the clock), or with a current ENFORCED snapshot past
            -- its expiry (HR-211).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND (EXISTS (SELECT 1 FROM pc.coverage_invalidations i WHERE i.org_id = o.id AND i.reassessed_at IS NULL)
                       OR EXISTS (SELECT 1 FROM pc.transactions t
                                  WHERE t.org_id = o.id AND t.created_at < now() - interval '1 minute'
                                    AND t.id > coalesce((SELECT w.transactions_after FROM pc.coverage_inventory w
                                                         WHERE w.org_id = o.id), '00000000-0000-0000-0000-000000000000'))
                       OR EXISTS (SELECT 1 FROM pc.coverage_snapshots s
                                  WHERE s.org_id = o.id AND s.state = 'ENFORCED' AND s.expires_at <= now()
                                    AND NOT EXISTS (SELECT 1 FROM pc.coverage_snapshots n
                                                    WHERE n.org_id = s.org_id AND n.agent_id = s.agent_id
                                                      AND n.connection_id = s.connection_id
                                                      AND n.operation = s.operation AND n.id > s.id)))
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
REVOKE SELECT (org_id, rollout_id, state) ON pc.policy_rollout_targets FROM pc_lister;
REVOKE SELECT (org_id, id, stage, completed_at) ON pc.policy_rollouts FROM pc_lister;
DROP TABLE pc.policy_shadow_counts;
DROP TABLE pc.policy_shadow_results;
DROP TABLE pc.policy_rollout_cursors;
DROP TABLE pc.policy_rollout_targets;
DROP TABLE pc.policy_rollout_cohorts;
DROP TABLE pc.policy_rollouts;
DROP TABLE pc.policy_cohort_members;
DROP TABLE pc.policy_cohorts;
DROP FUNCTION pc.policy_rollout_insert();
DROP FUNCTION pc.policy_rollout_forward();
DROP FUNCTION pc.policy_cohort_members_count();
