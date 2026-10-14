-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The range boundary (G0 M12 W1a, HR-220, HR-221, coordinator decisions
-- D1 to D3, 2026-10-14). An agent is marked a range agent when it is
-- created and never again; every run of a range agent is simulated, a
-- transaction takes the flag from its run, and a simulated connection
-- points only at a simulator. The four flags are NOT NULL DEFAULT false and
-- are left out of every column UPDATE grant, so pc_app can set them at
-- insert and can never change them afterwards: a real agent cannot become a
-- range agent, a real run cannot become simulated, and the reverse.

-- +goose Up
ALTER TABLE pc.agents       ADD COLUMN range_agent boolean NOT NULL DEFAULT false;
ALTER TABLE pc.runs         ADD COLUMN simulated   boolean NOT NULL DEFAULT false;
ALTER TABLE pc.transactions ADD COLUMN simulated   boolean NOT NULL DEFAULT false;
ALTER TABLE pc.connections  ADD COLUMN simulated   boolean NOT NULL DEFAULT false;

-- Range agents are counted against their own cap of 5 per organization.
CREATE INDEX agents_range ON pc.agents (org_id) WHERE range_agent AND state <> 'RETIRED';

-- +goose Down
DROP INDEX pc.agents_range;
ALTER TABLE pc.connections  DROP COLUMN simulated;
ALTER TABLE pc.transactions DROP COLUMN simulated;
ALTER TABLE pc.runs         DROP COLUMN simulated;
ALTER TABLE pc.agents       DROP COLUMN range_agent;
