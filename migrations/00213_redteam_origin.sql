-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Customer range scenarios (G0 M17 D124, D126; PN-009.6; HR-466, HR-467).
-- A scenario is the PantherClaw library's (RT-###) or customer-authored
-- (CX-###), and the server derives which from the id. A range is all one or
-- all the other, so redteam_runs carries the range's origin and every
-- declared scenario id must agree with it; a result's origin is its id's.
-- Ranges and results recorded before this migration are all RT and keep
-- the default, library.
-- +goose Up
ALTER TABLE pc.redteam_runs ADD COLUMN origin text NOT NULL DEFAULT 'library';
ALTER TABLE pc.redteam_runs ADD CONSTRAINT redteam_runs_origin_check
    CHECK (origin IN ('library', 'customer')) NOT VALID;
ALTER TABLE pc.redteam_runs ADD CONSTRAINT redteam_runs_origin_ids CHECK (
    CASE origin
        WHEN 'customer' THEN NOT jsonb_path_exists(scenarios, '$[*].id ? (!(@ starts with "CX-"))')
        ELSE NOT jsonb_path_exists(scenarios, '$[*].id ? (@ starts with "CX-")')
    END) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.redteam_runs VALIDATE CONSTRAINT redteam_runs_origin_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.redteam_runs VALIDATE CONSTRAINT redteam_runs_origin_ids;

ALTER TABLE pc.redteam_results DROP CONSTRAINT redteam_results_scenario_id_check;
ALTER TABLE pc.redteam_results ADD CONSTRAINT redteam_results_scenario_id_check
    CHECK (scenario_id ~ '^(RT-[0-9]{3}|CX-[0-9]{3,5})$') NOT VALID;
ALTER TABLE pc.redteam_results ADD COLUMN origin text NOT NULL DEFAULT 'library';
ALTER TABLE pc.redteam_results ADD CONSTRAINT redteam_results_origin_check
    CHECK (origin IN ('library', 'customer')) NOT VALID;
ALTER TABLE pc.redteam_results ADD CONSTRAINT redteam_results_origin_id
    CHECK ((origin = 'customer') = (scenario_id LIKE 'CX-%')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.redteam_results VALIDATE CONSTRAINT redteam_results_scenario_id_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.redteam_results VALIDATE CONSTRAINT redteam_results_origin_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.redteam_results VALIDATE CONSTRAINT redteam_results_origin_id;

GRANT INSERT (origin) ON pc.redteam_runs TO pc_app;
GRANT INSERT (origin) ON pc.redteam_results TO pc_app;

-- +goose Down
REVOKE INSERT (origin) ON pc.redteam_results FROM pc_app;
REVOKE INSERT (origin) ON pc.redteam_runs FROM pc_app;
DELETE FROM pc.redteam_results WHERE origin = 'customer';
ALTER TABLE pc.redteam_results DROP CONSTRAINT redteam_results_origin_id;
ALTER TABLE pc.redteam_results DROP COLUMN origin;
ALTER TABLE pc.redteam_results DROP CONSTRAINT redteam_results_scenario_id_check;
ALTER TABLE pc.redteam_results ADD CONSTRAINT redteam_results_scenario_id_check
    CHECK (scenario_id ~ '^RT-[0-9]{3}$') NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.redteam_results VALIDATE CONSTRAINT redteam_results_scenario_id_check;
DELETE FROM pc.redteam_runs WHERE origin = 'customer';
ALTER TABLE pc.redteam_runs DROP CONSTRAINT redteam_runs_origin_ids;
ALTER TABLE pc.redteam_runs DROP COLUMN origin;
