-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- G0 M24 D230, D232, D234, D247. Risk fields people state about an agent, the
-- a2a_card signing key's purpose, the public URL a card is signed for, and the
-- index the per-scope cap on open scan discoveries reads.
--
-- - risk_tier, data_classes, ai_act_role and ai_act_risk are what a person
--   states about an agent. They grant nothing and no decision reads them.
--   data_classes uses the vocabulary of definitions (format_m14.go).
-- - a2a_card keys sign the A2A cards gateways serve, and are published in the
--   JWKS.
-- - The cap on open scan discoveries is per (source, scope) (D234), so one
--   device's scan cannot fill another's room.
-- - public_url is the URL a person says a pin's card is served at. It is part
--   of what a pin is: pc_app may not update it. The server signs a card only
--   for this URL, so a gateway cannot name its own host (D247). NULL signs
--   nothing.

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

ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks', 'a2a_card')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.keys VALIDATE CONSTRAINT keys_purpose_check;

ALTER TABLE pc.a2a_pins
    ADD COLUMN public_url text
        CHECK (public_url IS NULL OR (char_length(public_url) BETWEEN 9 AND 2048 AND public_url ~ '^https?://'));

-- squawk-ignore require-concurrent-index-creation
CREATE INDEX discoveries_open_scope ON pc.discoveries (org_id, source, scan_scope) WHERE state = 'OPEN';

-- +goose Down
DROP INDEX pc.discoveries_open_scope;
ALTER TABLE pc.a2a_pins DROP COLUMN public_url;
ALTER TABLE pc.keys NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.keys WHERE purpose = 'a2a_card';
ALTER TABLE pc.keys FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.keys DROP CONSTRAINT keys_purpose_check;
ALTER TABLE pc.keys ADD CONSTRAINT keys_purpose_check
    CHECK (purpose IN ('receipts', 'permits', 'workload_tokens', 'checkpoints', 'access_tokens', 'gateway_ca',
                       'action_tokens', 'anchors', 'evidence_packs', 'checkpoints_pq', 'webhooks'));
REVOKE UPDATE (risk_tier, data_classes, ai_act_role, ai_act_risk) ON pc.agents FROM pc_app;
ALTER TABLE pc.agents
    DROP COLUMN ai_act_risk,
    DROP COLUMN ai_act_role,
    DROP COLUMN data_classes,
    DROP COLUMN risk_tier;
