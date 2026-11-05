-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The upstream MCP server's own name and version (G0 M38 D1104; HR-822):
-- what its initialize (or server/discover) answer said in serverInfo, as
-- the gateway reports it with the connection's inventory. NULL: never
-- reported. It is the upstream's UNTRUSTED word: indicator matching reads
-- it, and nothing uses it to identify a server on its own. Formats are also
-- checked in Go.

-- +goose Up
ALTER TABLE pc.connections ADD COLUMN IF NOT EXISTS upstream_server_info jsonb
    -- squawk-ignore constraint-missing-not-valid
    CHECK (upstream_server_info IS NULL OR (jsonb_typeof(upstream_server_info) = 'object'
        AND octet_length(upstream_server_info::text) <= 1024));
GRANT UPDATE (upstream_server_info) ON pc.connections TO pc_app;

-- +goose Down
REVOKE UPDATE (upstream_server_info) ON pc.connections FROM pc_app;
ALTER TABLE pc.connections DROP COLUMN IF EXISTS upstream_server_info;
