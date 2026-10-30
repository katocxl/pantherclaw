-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- A2A task and context ownership on shared state (G0 M19 D202, D211): the
-- gateway's A2A face remembers which run, through which connection,
-- created each task and context in pc.gateway_mcp_state, so a task created
-- through one gateway replica is served through another. key is the
-- SHA-256 of the binding and the peer's id (the ids themselves are never
-- stored). An A2A_TASK carries its context id sealed to the gateway's
-- broker key; an A2A_CONTEXT carries nothing. Both have M15's binding,
-- the TASK bounds and its one-hour lifetime (HR-411, HR-412). The names
-- are those PostgreSQL gave 00187's unnamed CHECK constraints.
-- +goose Up
ALTER TABLE pc.gateway_mcp_state DROP CONSTRAINT gateway_mcp_state_kind_check;
ALTER TABLE pc.gateway_mcp_state ADD CONSTRAINT gateway_mcp_state_kind_check
    CHECK (kind IN ('HOLD', 'TASK', 'SESSION', 'ELICITATION', 'A2A_TASK', 'A2A_CONTEXT'));
ALTER TABLE pc.gateway_mcp_state DROP CONSTRAINT gateway_mcp_state_check1;
ALTER TABLE pc.gateway_mcp_state ADD CONSTRAINT gateway_mcp_state_check1
    CHECK (kind IN ('TASK', 'ELICITATION', 'A2A_TASK') OR (sealed_body IS NULL AND status IS NULL AND NOT busy));
-- An A2A task carries its sealed context id and nothing of an MCP task's;
-- an A2A context carries no body (check1) and no action.
ALTER TABLE pc.gateway_mcp_state ADD CONSTRAINT gateway_mcp_state_a2a_task
    CHECK (kind <> 'A2A_TASK' OR (sealed_body IS NOT NULL AND action_id IS NULL AND status IS NULL AND NOT busy));
ALTER TABLE pc.gateway_mcp_state ADD CONSTRAINT gateway_mcp_state_a2a_context
    CHECK (kind <> 'A2A_CONTEXT' OR action_id IS NULL);

-- +goose Down
DELETE FROM pc.gateway_mcp_state WHERE kind IN ('A2A_TASK', 'A2A_CONTEXT');
ALTER TABLE pc.gateway_mcp_state DROP CONSTRAINT gateway_mcp_state_a2a_context;
ALTER TABLE pc.gateway_mcp_state DROP CONSTRAINT gateway_mcp_state_a2a_task;
ALTER TABLE pc.gateway_mcp_state DROP CONSTRAINT gateway_mcp_state_check1;
ALTER TABLE pc.gateway_mcp_state ADD CONSTRAINT gateway_mcp_state_check1
    CHECK (kind IN ('TASK', 'ELICITATION') OR (sealed_body IS NULL AND status IS NULL AND NOT busy));
ALTER TABLE pc.gateway_mcp_state DROP CONSTRAINT gateway_mcp_state_kind_check;
ALTER TABLE pc.gateway_mcp_state ADD CONSTRAINT gateway_mcp_state_kind_check
    CHECK (kind IN ('HOLD', 'TASK', 'SESSION', 'ELICITATION'));
