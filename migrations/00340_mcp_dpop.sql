-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- DPoP-bound MCP access tokens (RFC 9449; G0 M30 D910-D914).
--
-- pc.mcp_clients.dpop_bound: the client's metadata document asks for
-- DPoP-bound access tokens ("dpop_bound_access_tokens": true). It follows
-- the confirmed document, so pc_app writes it where it writes the rest of
-- the document: its column joins the UPDATE columns 00291 grants (D911).
--
-- pc.mcp_authorization_codes.dpop_jkt: the key thumbprint an authorization
-- request named (RFC 9449 §10); the code's token request must prove it.
-- pc.mcp_refresh_tokens.dpop_jkt: the key a refresh token is bound to; its
-- refresh must prove the same key. Both are written at insert only.
-- +goose Up
ALTER TABLE pc.mcp_clients ADD COLUMN dpop_bound boolean NOT NULL DEFAULT false;
ALTER TABLE pc.mcp_authorization_codes
    ADD COLUMN dpop_jkt text CONSTRAINT mcp_authorization_codes_dpop_jkt CHECK (dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');
ALTER TABLE pc.mcp_refresh_tokens
    ADD COLUMN dpop_jkt text CONSTRAINT mcp_refresh_tokens_dpop_jkt CHECK (dpop_jkt ~ '^[A-Za-z0-9_-]{43}$');

GRANT UPDATE (dpop_bound) ON pc.mcp_clients TO pc_app;

-- +goose Down
REVOKE UPDATE (dpop_bound) ON pc.mcp_clients FROM pc_app;
ALTER TABLE pc.mcp_refresh_tokens DROP COLUMN dpop_jkt;
ALTER TABLE pc.mcp_authorization_codes DROP COLUMN dpop_jkt;
ALTER TABLE pc.mcp_clients DROP COLUMN dpop_bound;
