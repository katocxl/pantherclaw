-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Daily usage meters (G0 M13 D10, D45, F6; HR-377). One row per org and
-- UTC day, written only by the server from the org's own records, never
-- from anything a client reports. The job usage.meter_daily recomputes
-- today and yesterday every hour, each from that day's rows only:
--
--   agents          agents that existed during the day and were not
--                   retired before it began (range agents excluded);
--   instances_peak  the highest number of ADMITTED agent instances the
--                   job saw during the day (sampled at each run, so the
--                   peak is the highest hourly sample);
--   runs            runs started during the day (range agents excluded);
--   bytes_written   the stored byte columns of the rows created that day:
--                   evidence ledger entries (body), decision receipts
--                   (receipt_jws), payload captures (content) and evidence
--                   packs (manifest and content);
--   bytes_removed   the ledger-entry body bytes the retention remover
--                   removed that day (it reports them after each batch;
--                   it may not read receipt or capture contents, HR-198,
--                   so their removals reach stored_bytes at the weekly
--                   recount);
--   stored_bytes    the previous day's stored_bytes + bytes_written −
--                   bytes_removed (at least 0) — never a share of relation
--                   sizes.
--
-- The weekly job usage.recount_weekly re-baselines stored_bytes one org at
-- a time from a full sum of those columns, so drift (packs expiring, rows
-- removed on the day they were written, the first days after deployment)
-- does not accumulate.
--
-- Nothing enforces these numbers in M13 (limits.usage.enforce refuses
-- true); they are shown with the plan.

-- +goose Up
CREATE TABLE pc.usage_daily (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    day            date        NOT NULL,
    agents         integer     NOT NULL DEFAULT 0 CHECK (agents >= 0),
    instances_peak integer     NOT NULL DEFAULT 0 CHECK (instances_peak >= 0),
    runs           integer     NOT NULL DEFAULT 0 CHECK (runs >= 0),
    bytes_written  bigint      NOT NULL DEFAULT 0 CHECK (bytes_written >= 0),
    bytes_removed  bigint      NOT NULL DEFAULT 0 CHECK (bytes_removed >= 0),
    stored_bytes   bigint      NOT NULL DEFAULT 0 CHECK (stored_bytes >= 0),
    computed_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, day)
);

ALTER TABLE pc.usage_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.usage_daily FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.usage_daily
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.usage_daily TO pc_app;
GRANT UPDATE (agents, instances_peak, runs, bytes_written, bytes_removed, stored_bytes, computed_at) ON pc.usage_daily TO pc_app;
GRANT SELECT ON pc.usage_daily TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.usage_daily;
