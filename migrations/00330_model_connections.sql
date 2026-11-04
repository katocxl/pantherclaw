-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Model connections (G0 M29 D811; F980; HR-690). Connection kind model: an
-- agent reaches its model provider through the gateway, which holds the
-- provider key as the connection's sealed credential. A model connection
-- always has a base URL (it carries the API version path, such as
-- https://api.anthropic.com/v1). pc.agent_hosts_valid (00090) checks host
-- names only and takes no kind, so model connections' agent hosts need no
-- change there; the service accepts them for kind model.
--
-- pc.model_connections keeps each model connection's settings, kept by the
-- model kind store in the transaction that creates or changes the
-- connection: the max output tokens the gateway adds to a request that has
-- none, the provider-side tool types an admin allowed (D813, HR-696), and an
-- optional price per million tokens for estimates only (Team, D829, HR-698).
-- No price list ships: a price is the organization's own.

-- +goose Up
-- squawk: each new CHECK only widens the old one; NOT VALID then VALIDATE
-- keeps the lock short, and goose runs the migration in one transaction.
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a', 'model')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.connections VALIDATE CONSTRAINT connections_kind_check;
-- A model connection has a base URL like http, mcp and a2a connections: the
-- constraint's kind list is unchanged, so it is restated as it is (00150).

CREATE TABLE pc.model_connections (
    org_id               uuid          NOT NULL REFERENCES pc.orgs (id),
    connection_id        uuid          NOT NULL,
    max_output_tokens    bigint        NOT NULL CHECK (max_output_tokens BETWEEN 1 AND 1000000),
    allowed_server_tools text[]        NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_server_tools) <= 32),
    price_currency       text          CHECK (price_currency ~ '^[A-Z]{3}$'),
    price_input          numeric(26,8) CHECK (price_input >= 0),
    price_output         numeric(26,8) CHECK (price_output >= 0),
    price_cache_read     numeric(26,8) CHECK (price_cache_read >= 0),
    price_cache_write    numeric(26,8) CHECK (price_cache_write >= 0),
    updated_at           timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    -- A price is a currency with an input and an output price, all three or
    -- none; cache prices only beside them (empty means the input price).
    CONSTRAINT model_connections_price CHECK (
        (price_currency IS NULL) = (price_input IS NULL) AND (price_currency IS NULL) = (price_output IS NULL)),
    CONSTRAINT model_connections_cache_price CHECK (
        price_currency IS NOT NULL OR (price_cache_read IS NULL AND price_cache_write IS NULL))
);

ALTER TABLE pc.model_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.model_connections FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.model_connections
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.model_connections TO pc_app;
GRANT UPDATE (max_output_tokens, allowed_server_tools, price_currency, price_input, price_output, price_cache_read,
    price_cache_write, updated_at) ON pc.model_connections TO pc_app;
GRANT SELECT ON pc.model_connections TO pc_audit_ro;

-- +goose Down
-- The rollback refuses while a model connection exists, and never deletes
-- one: the old kind CHECK has no place for it.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pc.connections WHERE kind = 'model') THEN
        RAISE EXCEPTION '00330 down: model connections exist; delete them first';
    END IF;
END
$$;
-- +goose StatementEnd
DROP TABLE pc.model_connections;
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a'));
