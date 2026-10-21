-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Daily usage meters (G0 M13 D10, F6; HR-377). One row per org and UTC
-- day, written only by the server's job usage.meter_daily from the org's
-- own records, never from anything a client reports. The job recomputes
-- today and yesterday every hour:
--
--   agents          agents that existed during the day and were not
--                   retired before it began (range agents excluded);
--   instances_peak  the highest number of ADMITTED agent instances the
--                   job saw during the day (sampled at each run, so the
--                   peak is the highest hourly sample);
--   runs            runs started during the day (range agents excluded);
--   stored_bytes    an approximation of the org's stored data at the end
--                   of the day: the sum of the stored byte columns of its
--                   evidence ledger entries (body), decision receipts
--                   (receipt_jws), payload captures (content) and evidence
--                   packs (manifest and content) — never a share of
--                   relation sizes.
--
-- Nothing enforces these numbers in M13 (limits.usage.enforce refuses
-- true); they are shown with the plan.

-- +goose Up
CREATE TABLE pc.usage_daily (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    day            date        NOT NULL,
    agents         integer     NOT NULL CHECK (agents >= 0),
    instances_peak integer     NOT NULL CHECK (instances_peak >= 0),
    runs           integer     NOT NULL CHECK (runs >= 0),
    stored_bytes   bigint      NOT NULL CHECK (stored_bytes >= 0),
    computed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, day)
);

ALTER TABLE pc.usage_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.usage_daily FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.usage_daily
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.usage_daily TO pc_app;
GRANT UPDATE (agents, instances_peak, runs, stored_bytes, computed_at) ON pc.usage_daily TO pc_app;
GRANT SELECT ON pc.usage_daily TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.usage_daily;
