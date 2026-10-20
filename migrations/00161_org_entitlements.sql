-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-org entitlements (G0 UI D9, D85, D87; PN-012.2, PN-026; HR-354..361).
-- A self-hosted server derives every org's entitlements from the installed
-- licence and reads no row here. A hosted server keeps one row per org with
-- two parts that never overwrite each other (D87): the billing state,
-- written only by the plan writer the billing extension calls (idempotent
-- by event id, older events ignored, HR-355), and the operator's comp
-- override (at most a year, with a reason, HR-358). The effective plan is
-- the comp plan while it is in force, else the billing state. Neither is
-- ever written by an API or browser call (HR-354), and COMP and DEV never
-- come from the billing extension (HR-361): DEV is development mode's,
-- computed, never stored. Every change is also recorded in the org's
-- evidence ledger.
--
-- entitlement_events records each billing event an org's plan was applied
-- from, so a replayed event changes nothing.

-- +goose Up
-- A plan's limits: an object of at most the five known keys, each a whole
-- number from 0 (unlimited) to 10^9 (L3).
-- +goose StatementBegin
CREATE FUNCTION pc.valid_plan_limits(l jsonb) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT AS $$
    SELECT jsonb_typeof(l) = 'object'
       AND l - ARRAY['max_agents', 'max_environments', 'retention_days', 'instance_allowance', 'max_members'] = '{}'::jsonb
       AND NOT EXISTS (SELECT 1 FROM jsonb_each(l) e
                       WHERE jsonb_typeof(e.value) <> 'number'
                          OR (e.value #>> '{}')::numeric < 0
                          OR (e.value #>> '{}')::numeric > 1000000000
                          OR (e.value #>> '{}')::numeric <> trunc((e.value #>> '{}')::numeric))
$$;
-- +goose StatementEnd

CREATE TABLE pc.org_entitlements (
    org_id        uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    -- The billing state (source BILLING), or none yet (source NONE: a row
    -- that holds only a comp override).
    plan_id       text        NOT NULL DEFAULT '' CHECK (plan_id ~ '^([a-z0-9][a-z0-9_-]{0,63})?$'),
    edition       text        NOT NULL CHECK (edition IN ('community', 'team', 'business', 'enterprise')),
    -- {max_agents, max_environments, retention_days, instance_allowance,
    -- max_members}: non-negative integers, 0 = unlimited.
    limits        jsonb       NOT NULL DEFAULT '{}' CHECK (pc.valid_plan_limits(limits)),
    features      text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(features) <= 128 AND array_position(features, NULL) IS NULL),
    -- Only billing statuses: COMP and DEV are never stored here (HR-361).
    status        text        NOT NULL CHECK (status IN ('NONE', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED', 'LAPSED')),
    source        text        NOT NULL CHECK (source IN ('BILLING', 'NONE')),
    period_end    timestamptz,
    -- The newest billing event applied; older ones are ignored (HR-355).
    last_event_at timestamptz,
    -- The comp override (HR-358): in force from comp_at until comp_until;
    -- a revoke moves comp_until to the revoke.
    comp_plan_id  text        CHECK (comp_plan_id IS NULL OR comp_plan_id ~ '^[a-z0-9][a-z0-9_-]{0,63}$'),
    comp_edition  text        CHECK (comp_edition IS NULL OR comp_edition IN ('team', 'business', 'enterprise')),
    comp_until    timestamptz,
    comp_reason   text        CHECK (comp_reason IS NULL OR char_length(comp_reason) BETWEEN 1 AND 500),
    -- Who granted the comp plan (the operator command's actor).
    comp_by       text        CHECK (comp_by IS NULL OR char_length(comp_by) BETWEEN 1 AND 256),
    comp_at       timestamptz,
    version       bigint      NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (source <> 'BILLING' OR last_event_at IS NOT NULL),
    CHECK (source <> 'NONE' OR (status = 'NONE' AND last_event_at IS NULL)),
    -- A comp override is whole: plan, edition, expiry, reason, grantor.
    CHECK ((comp_until IS NULL) = (comp_plan_id IS NULL) AND (comp_until IS NULL) = (comp_edition IS NULL)
           AND (comp_until IS NULL) = (comp_reason IS NULL) AND (comp_until IS NULL) = (comp_by IS NULL)
           AND (comp_until IS NULL) = (comp_at IS NULL)),
    -- Within a year of its grant (HR-358).
    CHECK (comp_until IS NULL OR (comp_until > comp_at AND comp_until <= comp_at + interval '1 year')),
    -- A row holds a billing state or a comp override.
    CHECK (source = 'BILLING' OR comp_until IS NOT NULL)
);

CREATE TABLE pc.entitlement_events (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    event_id    text        NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 128),
    -- What the event did to the billing state: APPLIED, or IGNORED as older
    -- than the newest event applied. A comp override never stops billing
    -- events from applying (D87).
    kind        text        NOT NULL CHECK (kind IN ('APPLIED', 'IGNORED_STALE')),
    status      text        NOT NULL CHECK (status IN ('NONE', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED', 'LAPSED')),
    event_at    timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, event_id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_entitlements', 'entitlement_events'] LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.org_entitlements, pc.entitlement_events TO pc_app;
GRANT UPDATE (plan_id, edition, limits, features, status, source, period_end, last_event_at, comp_plan_id, comp_edition,
    comp_until, comp_reason, comp_by, comp_at, version, updated_at) ON pc.org_entitlements TO pc_app;
GRANT SELECT ON pc.org_entitlements, pc.entitlement_events TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.entitlement_events;
DROP TABLE pc.org_entitlements;
DROP FUNCTION pc.valid_plan_limits(jsonb);
