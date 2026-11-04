-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Signals carry techniques (G0 M28 D718; F964, HR-684). An alert keeps the
-- MITRE ATT&CK techniques of the rule that raised it beside its ATLAS ones,
-- set by the first raise like atlas. An incident and a case list the union
-- of their alerts' techniques: the sorted distinct ids, capped at 64 (the 64
-- smallest are kept, so attaching another alert never fails on the cap).
-- No new indexes.
--
-- * Incidents: the application widens the union wherever an alert opens or
--   attaches to an incident (pc.technique_union), so pc_app updates the two
--   columns.
-- * Cases: a case changes only by its newest entry (HR-245), so the union is
--   set on open from the alert or incident it was opened from, and widened by
--   the entry trigger on each LINK entry to an alert or an incident. The
--   trigger runs as pc_app, which therefore updates the two columns; the case
--   update trigger still refuses any update that no new entry carries.

-- +goose Up
ALTER TABLE pc.alerts
    ADD COLUMN attack text[] NOT NULL DEFAULT '{}' CHECK (cardinality(attack) <= 16);

ALTER TABLE pc.incidents
    ADD COLUMN atlas  text[] NOT NULL DEFAULT '{}' CHECK (cardinality(atlas) <= 64),
    ADD COLUMN attack text[] NOT NULL DEFAULT '{}' CHECK (cardinality(attack) <= 64);
GRANT UPDATE (atlas, attack) ON pc.incidents TO pc_app;

ALTER TABLE pc.cases
    ADD COLUMN atlas  text[] NOT NULL DEFAULT '{}' CHECK (cardinality(atlas) <= 64),
    ADD COLUMN attack text[] NOT NULL DEFAULT '{}' CHECK (cardinality(attack) <= 64);
GRANT UPDATE (atlas, attack) ON pc.cases TO pc_app;

-- The sorted (byte order, as Go sorts) distinct union of two technique
-- lists, at most 64: the 64 smallest ids.
-- +goose StatementBegin
CREATE FUNCTION pc.technique_union(a text[], b text[]) RETURNS text[]
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pc, pg_temp
AS $$
    SELECT coalesce(array_agg(u.t ORDER BY u.t), '{}')
    FROM (SELECT DISTINCT x.t COLLATE "C" AS t
          FROM unnest(coalesce(a, '{}') || coalesce(b, '{}')) AS x(t)
          ORDER BY 1
          LIMIT 64) AS u
$$;
-- +goose StatementEnd

-- The entry trigger of 00122 with one change: a LINK entry to an alert or an
-- incident widens the case's techniques by that subject's (G0 M28 D718). An
-- id that is not a UUID or names no row of this organization adds nothing.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.case_entry_apply() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    ref     uuid;
    l_atlas text[] := '{}';
    l_attack text[] := '{}';
BEGIN
    IF NEW.kind = 'LINK' AND NEW.ref_kind IN ('alert', 'incident')
       AND NEW.ref_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        ref := NEW.ref_id::uuid;
        IF NEW.ref_kind = 'alert' THEN
            SELECT a.atlas, a.attack INTO l_atlas, l_attack FROM pc.alerts a WHERE a.org_id = NEW.org_id AND a.id = ref;
        ELSE
            SELECT i.atlas, i.attack INTO l_atlas, l_attack FROM pc.incidents i WHERE i.org_id = NEW.org_id AND i.id = ref;
        END IF;
    END IF;
    UPDATE pc.cases SET
        head_seq = NEW.seq,
        head_hash = NEW.entry_hash,
        owner_id = CASE WHEN NEW.kind = 'OWNER' AND NEW.owner_role = 'OWNER' THEN NEW.owner_id ELSE owner_id END,
        follow_up_owner_id = CASE WHEN NEW.kind = 'OWNER' AND NEW.owner_role = 'FOLLOW_UP' THEN NEW.owner_id
                                  ELSE follow_up_owner_id END,
        state = CASE WHEN NEW.kind = 'STATE' THEN NEW.to_state ELSE state END,
        disposition = CASE WHEN NEW.kind = 'STATE' THEN NEW.disposition ELSE disposition END,
        impact = CASE WHEN NEW.kind = 'STATE' THEN NEW.case_impact ELSE impact END,
        atlas = CASE WHEN cardinality(l_atlas) > 0 THEN pc.technique_union(atlas, l_atlas) ELSE atlas END,
        attack = CASE WHEN cardinality(l_attack) > 0 THEN pc.technique_union(attack, l_attack) ELSE attack END
    WHERE org_id = NEW.org_id AND id = NEW.case_id;
    RETURN NULL;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.case_entry_apply() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    UPDATE pc.cases SET
        head_seq = NEW.seq,
        head_hash = NEW.entry_hash,
        owner_id = CASE WHEN NEW.kind = 'OWNER' AND NEW.owner_role = 'OWNER' THEN NEW.owner_id ELSE owner_id END,
        follow_up_owner_id = CASE WHEN NEW.kind = 'OWNER' AND NEW.owner_role = 'FOLLOW_UP' THEN NEW.owner_id
                                  ELSE follow_up_owner_id END,
        state = CASE WHEN NEW.kind = 'STATE' THEN NEW.to_state ELSE state END,
        disposition = CASE WHEN NEW.kind = 'STATE' THEN NEW.disposition ELSE disposition END,
        impact = CASE WHEN NEW.kind = 'STATE' THEN NEW.case_impact ELSE impact END
    WHERE org_id = NEW.org_id AND id = NEW.case_id;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
DROP FUNCTION pc.technique_union(text[], text[]);
REVOKE UPDATE (atlas, attack) ON pc.cases FROM pc_app;
ALTER TABLE pc.cases DROP COLUMN attack, DROP COLUMN atlas;
REVOKE UPDATE (atlas, attack) ON pc.incidents FROM pc_app;
ALTER TABLE pc.incidents DROP COLUMN attack, DROP COLUMN atlas;
ALTER TABLE pc.alerts DROP COLUMN attack;
