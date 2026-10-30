-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Bulk simulation by cohort (G0 M18 D154; F602, HR-478, T-213). One
-- simulation may name a fleet cohort (NULL: the whole org, as before).
-- The cohort's agents the requester may read are snapshotted when it is
-- asked for (cohort_agents, at most 2 000), and only their recorded
-- decisions are replayed. Every simulation also counts its decisions per
-- cohort (by_cohort), and readers see only the cohorts they may read.
--
-- Nothing else changes: a cohort simulation is the same read-only replay
-- under the same caps (one queued or running per org, a window of at most
-- 30 days, at most 50 000 decisions), and it still writes only its own
-- rows (HR-232, HR-478). The cohort is named by id only: deleting it
-- later leaves the simulation as it ran.

-- +goose Up
ALTER TABLE pc.policy_simulations
    ADD COLUMN cohort_id     uuid,
    ADD COLUMN cohort_agents uuid[] CHECK (cardinality(cohort_agents) <= 2000 AND array_position(cohort_agents, NULL) IS NULL),
    ADD COLUMN by_cohort     jsonb  NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(by_cohort) = 'object' AND octet_length(by_cohort::text) <= 262144),
    ADD CONSTRAINT policy_simulations_cohort CHECK ((cohort_id IS NULL) = (cohort_agents IS NULL));

-- A cohort simulation starts with its snapshot, and the snapshot never
-- changes (pc_app has no UPDATE on either column; the grant below is the
-- old one plus by_cohort).
GRANT INSERT (cohort_id, cohort_agents) ON pc.policy_simulations TO pc_app;
GRANT UPDATE (by_cohort) ON pc.policy_simulations TO pc_app;

-- +goose Down
REVOKE UPDATE (by_cohort) ON pc.policy_simulations FROM pc_app;
REVOKE INSERT (cohort_id, cohort_agents) ON pc.policy_simulations FROM pc_app;
ALTER TABLE pc.policy_simulations
    DROP CONSTRAINT policy_simulations_cohort,
    DROP COLUMN by_cohort,
    DROP COLUMN cohort_agents,
    DROP COLUMN cohort_id;
