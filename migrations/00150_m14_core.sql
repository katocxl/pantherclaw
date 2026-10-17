-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- M14 core (coordinator decisions D4 and D6). Connection kinds postgres (a
-- structured, read-only database query connector) and a2a (a peer agent
-- reached over the A2A protocol); channels authzen (an external
-- enforcement point asking for a decision) and a2a (a call to a peer
-- agent) on transactions and coverage routes; notification channel kind
-- slack_app (a Slack bot posting approval cards), whose bot token is
-- sealed in secret like a Slack webhook URL.
--
-- A grant's bounds are already a document (bytea, 00022), so the data
-- scope a grant may carry (D11) needs no column.

-- +goose Up
-- squawk: each CHECK only widens a value list; goose runs each migration
-- in one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check
        CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container', 'postgres', 'a2a')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.connections VALIDATE CONSTRAINT connections_kind_check;

ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_channel_check,
    ADD CONSTRAINT transactions_channel_check
        CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook', 'authzen', 'a2a')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.transactions VALIDATE CONSTRAINT transactions_channel_check;

ALTER TABLE pc.coverage_routes
    DROP CONSTRAINT coverage_routes_channel_check,
    ADD CONSTRAINT coverage_routes_channel_check
        CHECK (channel IN ('http', 'mcp', 'sdk', 'hook', 'authzen', 'a2a')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.coverage_routes VALIDATE CONSTRAINT coverage_routes_channel_check;

-- The secret check of 00031 was named by Postgres; find it by its text.
-- +goose StatementBegin
DO $$
DECLARE
    c text;
BEGIN
    SELECT conname INTO STRICT c FROM pg_constraint
    WHERE conrelid = 'pc.notification_channels'::regclass AND contype = 'c'
      AND pg_get_constraintdef(oid) = 'CHECK (((kind = ANY (ARRAY[''slack''::text, ''webhook''::text])) = (secret IS NOT NULL)))';
    IF c <> 'notification_channels_secret_kind' THEN
        EXECUTE format('ALTER TABLE pc.notification_channels RENAME CONSTRAINT %I TO notification_channels_secret_kind', c);
    END IF;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.notification_channels
    DROP CONSTRAINT notification_channels_kind_check,
    ADD CONSTRAINT notification_channels_kind_check
        CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app')) NOT VALID,
    DROP CONSTRAINT notification_channels_secret_kind,
    ADD CONSTRAINT notification_channels_secret_kind
        CHECK ((kind IN ('slack', 'webhook', 'slack_app')) = (secret IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.notification_channels VALIDATE CONSTRAINT notification_channels_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.notification_channels VALIDATE CONSTRAINT notification_channels_secret_kind;

ALTER TABLE pc.deliveries
    DROP CONSTRAINT deliveries_kind_check,
    ADD CONSTRAINT deliveries_kind_check
        CHECK (kind IN ('log', 'email', 'slack', 'webhook', 'slack_app')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.deliveries VALIDATE CONSTRAINT deliveries_kind_check;

-- +goose Down
ALTER TABLE pc.deliveries
    DROP CONSTRAINT deliveries_kind_check,
    ADD CONSTRAINT deliveries_kind_check CHECK (kind IN ('log', 'email', 'slack', 'webhook'));
ALTER TABLE pc.notification_channels
    DROP CONSTRAINT notification_channels_secret_kind,
    ADD CONSTRAINT notification_channels_secret_kind CHECK ((kind IN ('slack', 'webhook')) = (secret IS NOT NULL)),
    DROP CONSTRAINT notification_channels_kind_check,
    ADD CONSTRAINT notification_channels_kind_check CHECK (kind IN ('log', 'email', 'slack', 'webhook'));
ALTER TABLE pc.coverage_routes
    DROP CONSTRAINT coverage_routes_channel_check,
    ADD CONSTRAINT coverage_routes_channel_check CHECK (channel IN ('http', 'mcp', 'sdk', 'hook'));
ALTER TABLE pc.transactions
    DROP CONSTRAINT transactions_channel_check,
    ADD CONSTRAINT transactions_channel_check CHECK (channel IS NULL OR channel IN ('mcp', 'http', 'sdk', 'hook'));
ALTER TABLE pc.connections
    DROP CONSTRAINT connections_kind_check,
    ADD CONSTRAINT connections_kind_check CHECK (kind IN ('http', 'mcp', 'local', 'mcp_container'));
