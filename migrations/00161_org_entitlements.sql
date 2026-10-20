-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Per-org entitlements (G0 UI D9; PN-012.2, PN-026; HR-354..361). A
-- self-hosted server keeps deriving every org's entitlements from the
-- installed licence and writes no row here. A hosted server keeps one row
-- per org, written only by the plan writer the billing extension calls
-- (idempotent by event id, older events ignored, HR-355), by the operator's
-- comp command (COMP, at most a year, with a reason, HR-358) or by
-- development mode (DEV) — never by an API or browser call (HR-354). COMP
-- and DEV never come from the billing extension (HR-361). Every change is
-- also recorded in the org's evidence ledger.
--
-- entitlement_events records each billing event an org's plan was applied
-- from, so a replayed event changes nothing.

-- +goose Up
CREATE TABLE pc.org_entitlements (
    org_id        uuid        PRIMARY KEY REFERENCES pc.orgs (id),
    plan_id       text        NOT NULL DEFAULT '' CHECK (plan_id ~ '^([a-z0-9][a-z0-9_-]{0,63})?$'),
    edition       text        NOT NULL CHECK (edition IN ('community', 'team', 'business', 'enterprise', 'development')),
    -- {max_agents, max_environments, retention_days, instance_allowance,
    -- max_members}: non-negative integers, 0 = unlimited.
    limits        jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(limits) = 'object' AND octet_length(limits::text) <= 1024),
    features      text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(features) <= 128 AND array_position(features, NULL) IS NULL),
    status        text        NOT NULL CHECK (status IN ('NONE', 'TRIALING', 'ACTIVE', 'PAST_DUE', 'PAUSED', 'CANCELED',
                                                         'LAPSED', 'COMP', 'DEV')),
    source        text        NOT NULL CHECK (source IN ('LICENCE', 'BILLING', 'COMP', 'DEV')),
    period_end    timestamptz,
    comp_until    timestamptz,
    comp_reason   text        CHECK (comp_reason IS NULL OR char_length(comp_reason) BETWEEN 1 AND 500),
    -- Who granted a comp plan (the operator command's actor).
    comp_by       text        CHECK (comp_by IS NULL OR char_length(comp_by) BETWEEN 1 AND 256),
    comp_at       timestamptz,
    version       bigint      NOT NULL DEFAULT 1 CHECK (version >= 1),
    -- The newest billing event applied; older ones are ignored (HR-355).
    last_event_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- COMP and DEV come only from their own writers (HR-361).
    CHECK ((status = 'COMP') = (source = 'COMP')),
    CHECK ((status = 'DEV') = (source = 'DEV')),
    CHECK (source <> 'LICENCE'),
    -- A comp plan has an expiry within a year of its grant and a reason (HR-358).
    CHECK ((source = 'COMP') = (comp_until IS NOT NULL AND comp_reason IS NOT NULL AND comp_by IS NOT NULL AND comp_at IS NOT NULL)),
    CHECK (comp_until IS NULL OR comp_until <= comp_at + interval '1 year'),
    CHECK (source <> 'BILLING' OR last_event_at IS NOT NULL)
);

CREATE TABLE pc.entitlement_events (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    event_id    text        NOT NULL CHECK (char_length(event_id) BETWEEN 1 AND 128),
    -- What the event did to the plan: APPLIED, or IGNORED as older than
    -- the plan's newest event.
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
GRANT UPDATE (plan_id, edition, limits, features, status, source, period_end, comp_until, comp_reason, comp_by, comp_at,
    version, last_event_at, updated_at) ON pc.org_entitlements TO pc_app;
GRANT SELECT ON pc.org_entitlements, pc.entitlement_events TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.entitlement_events;
DROP TABLE pc.org_entitlements;
