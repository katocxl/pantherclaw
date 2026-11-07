-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A connection's runtime target (G0 M34 D991; HR-762): the target of a cloud
-- agent runtime's gateway whose tool calls the gateway's runtime face
-- decides through this connection, "agentcore:<gateway ARN>/<target name>".
-- NULL: unbound. Only an mcp connection whose credential the agent holds
-- may have one; the format and the kind are checked in Go. A live target
-- names one connection per org. Setting or clearing it needs
-- connection.manage and is audited (connection.runtime_target_set /
-- _cleared). The unique index is built concurrently, outside a transaction,
-- so writes to pc.connections go on during the build; a build that failed
-- leaves an invalid index, which the first index statement drops before the
-- next try.

-- +goose NO TRANSACTION

-- +goose Up
ALTER TABLE pc.connections ADD COLUMN IF NOT EXISTS runtime_target text
    -- squawk-ignore constraint-missing-not-valid
    CHECK (runtime_target IS NULL OR char_length(runtime_target) BETWEEN 1 AND 512);
GRANT UPDATE (runtime_target) ON pc.connections TO pc_app;
-- squawk: this migration runs outside a transaction (goose NO TRANSACTION
-- above), which CONCURRENTLY needs; .squawk.toml assumes every migration
-- runs in one.
-- squawk-ignore ban-concurrent-index-creation-in-transaction
DROP INDEX CONCURRENTLY IF EXISTS pc.connections_runtime_target;
-- squawk-ignore ban-concurrent-index-creation-in-transaction
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS connections_runtime_target ON pc.connections (org_id, runtime_target)
    WHERE runtime_target IS NOT NULL AND state <> 'RETIRED';

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS pc.connections_runtime_target;
REVOKE UPDATE (runtime_target) ON pc.connections FROM pc_app;
ALTER TABLE pc.connections DROP COLUMN IF EXISTS runtime_target;
