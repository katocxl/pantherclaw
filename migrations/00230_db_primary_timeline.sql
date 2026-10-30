-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The acknowledged primary timeline (G0 M19 D202, D207, HR-496). A
-- promotion moves PostgreSQL to a new timeline. After an asynchronous
-- promotion, committed revocations, containment changes or budget
-- reservations may be lost, so a server that finds a timeline other than
-- the acknowledged one, without synchronous replication verified both on
-- the acknowledged timeline and on the new primary, starts
-- in the maintenance hold until `keys bump-epochs` raises every epoch and
-- records the new timeline. One global row, no tenant data, visible only
-- in a global transaction of the purpose "failover" (app.purpose). The
-- timeline is NULL until the first server start records it.

-- +goose Up
CREATE TABLE pc.db_primary_timeline (
    singleton     boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
    timeline      bigint      CHECK (timeline IS NULL OR timeline > 0),
    -- Whether a starting server verified synchronous replication on this
    -- timeline (D218): a promotion from it counts as sync only when it did.
    sync_verified boolean     NOT NULL DEFAULT false,
    update_time   timestamptz NOT NULL DEFAULT now()
);
INSERT INTO pc.db_primary_timeline (singleton) VALUES (true);

ALTER TABLE pc.db_primary_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.db_primary_timeline FORCE ROW LEVEL SECURITY;
CREATE POLICY failover_purpose ON pc.db_primary_timeline
    USING ((SELECT current_setting('app.purpose', true)) = 'failover')
    WITH CHECK ((SELECT current_setting('app.purpose', true)) = 'failover');

GRANT SELECT ON pc.db_primary_timeline TO pc_app;
GRANT UPDATE (timeline, sync_verified, update_time) ON pc.db_primary_timeline TO pc_app;

-- +goose Down
DROP TABLE pc.db_primary_timeline;
