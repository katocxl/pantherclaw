-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- G0 M24 D230, D234. Risk fields people state about an agent, and the index
-- the per-scope cap on open scan discoveries reads.
--
-- - risk_tier, data_classes, ai_act_role and ai_act_risk are what a person
--   states about an agent. They grant nothing and no decision reads them.
--   data_classes uses the vocabulary of definitions (format_m14.go).
-- - The cap on open scan discoveries is per (source, scope) (D234), so one
--   device's scan cannot fill another's room.

-- +goose Up
ALTER TABLE pc.agents
    ADD COLUMN risk_tier text NOT NULL DEFAULT 'UNSET'
        CHECK (risk_tier IN ('UNSET', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    ADD COLUMN data_classes text[] NOT NULL DEFAULT '{}'
        CHECK (data_classes <@ ARRAY['public', 'internal', 'pii', 'secret']::text[]),
    ADD COLUMN ai_act_role text NOT NULL DEFAULT 'UNSET'
        CHECK (ai_act_role IN ('UNSET', 'PROVIDER', 'DEPLOYER', 'NOT_APPLICABLE')),
    ADD COLUMN ai_act_risk text NOT NULL DEFAULT 'UNSET'
        CHECK (ai_act_risk IN ('UNSET', 'MINIMAL', 'LIMITED', 'HIGH'));
GRANT UPDATE (risk_tier, data_classes, ai_act_role, ai_act_risk) ON pc.agents TO pc_app;

-- squawk-ignore require-concurrent-index-creation
CREATE INDEX discoveries_open_scope ON pc.discoveries (org_id, source, scan_scope) WHERE state = 'OPEN';

-- +goose Down
DROP INDEX pc.discoveries_open_scope;
REVOKE UPDATE (risk_tier, data_classes, ai_act_role, ai_act_risk) ON pc.agents FROM pc_app;
ALTER TABLE pc.agents
    DROP COLUMN ai_act_risk,
    DROP COLUMN ai_act_role,
    DROP COLUMN data_classes,
    DROP COLUMN risk_tier;
