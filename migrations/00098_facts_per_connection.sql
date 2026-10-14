-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Gateway facts belong to their connection (G0 M12 D43, HR-222, HR-160).
-- A fact name has one provider per source scope: a service-account provider
-- is org-scoped, a gateway provider is scoped to its connection, so several
-- connections (a real one and its simulated twin) may each supply the same
-- github.* names, while a name an org-scoped provider supplies is never also
-- supplied by a connection-scoped one, and the reverse (a trigger). pc.facts
-- keeps one value per (name, subject) for each scope: connection_id is NULL
-- for service-account facts and the reporting provider's connection for
-- gateway facts, so a twin's values never overwrite a real connection's. The
-- pipeline reads a gateway-provided name only from its action's own
-- connection. connection_id is set at insert and, like the keys, is left out
-- of the column UPDATE grants. Row-level security is lifted on the tables the
-- backfill and the new foreign keys read while it runs, and forced again.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connections', 'fact_providers', 'fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I NO FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

ALTER TABLE pc.fact_declarations ADD COLUMN connection_id uuid;
ALTER TABLE pc.facts ADD COLUMN connection_id uuid;

UPDATE pc.fact_declarations d SET connection_id = p.connection_id
  FROM pc.fact_providers p WHERE p.org_id = d.org_id AND p.id = d.provider_id AND p.connection_id IS NOT NULL;
UPDATE pc.facts f SET connection_id = p.connection_id
  FROM pc.fact_providers p WHERE p.org_id = f.org_id AND p.id = f.provider_id AND p.connection_id IS NOT NULL;

ALTER TABLE pc.fact_declarations
    ADD CONSTRAINT fact_declarations_connection_fk FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id);
ALTER TABLE pc.facts
    ADD CONSTRAINT facts_connection_fk FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id);

-- One active provider per name and scope.
DROP INDEX pc.fact_declarations_one_provider;
CREATE UNIQUE INDEX fact_declarations_one_provider ON pc.fact_declarations (org_id, replace(name, '.', '_'))
    WHERE active AND connection_id IS NULL;
CREATE UNIQUE INDEX fact_declarations_one_provider_per_connection ON pc.fact_declarations (org_id, connection_id, replace(name, '.', '_'))
    WHERE active AND connection_id IS NOT NULL;

-- A name is supplied from one scope only.
-- +goose StatementBegin
CREATE FUNCTION pc.fact_declarations_one_scope() RETURNS trigger LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    -- Two registrations of one name in different scopes take turns, so both
    -- cannot pass the check below.
    IF NEW.active THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.org_id::text || ':' || replace(NEW.name, '.', '_'), 0));
    END IF;
    IF NEW.active AND EXISTS (
        SELECT 1 FROM pc.fact_declarations d
        WHERE d.org_id = NEW.org_id AND replace(d.name, '.', '_') = replace(NEW.name, '.', '_') AND d.active
          AND (d.connection_id IS NULL) <> (NEW.connection_id IS NULL)) THEN
        RAISE EXCEPTION 'fact % is supplied from another scope', NEW.name USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER fact_declarations_one_scope BEFORE INSERT OR UPDATE OF active ON pc.fact_declarations
    FOR EACH ROW EXECUTE FUNCTION pc.fact_declarations_one_scope();

-- One value per (name, subject) in each scope.
ALTER TABLE pc.facts DROP CONSTRAINT facts_org_id_name_subject_type_subject_id_key;
CREATE UNIQUE INDEX facts_org_scope ON pc.facts (org_id, name, subject_type, subject_id) WHERE connection_id IS NULL;
CREATE UNIQUE INDEX facts_connection_scope ON pc.facts (org_id, connection_id, name, subject_type, subject_id) WHERE connection_id IS NOT NULL;

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['connections', 'fact_providers', 'fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I NO FORCE ROW LEVEL SECURITY', t);
    END LOOP;
    -- Back to one value per (name, subject) and one provider per name: keep
    -- the newest fact and the earliest declaration of each.
    DELETE FROM pc.facts f USING pc.facts g
     WHERE f.org_id = g.org_id AND f.name = g.name AND f.subject_type = g.subject_type AND f.subject_id = g.subject_id
       AND f.id <> g.id AND (f.observed_at, f.id) < (g.observed_at, g.id);
    UPDATE pc.fact_declarations d SET active = false
     WHERE d.active AND EXISTS (
        SELECT 1 FROM pc.fact_declarations e
        WHERE e.org_id = d.org_id AND e.active AND replace(e.name, '.', '_') = replace(d.name, '.', '_')
          AND (e.provider_id, e.name) < (d.provider_id, d.name));
    FOREACH t IN ARRAY ARRAY['fact_declarations', 'facts']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
-- +goose StatementEnd
DROP INDEX pc.facts_connection_scope;
DROP INDEX pc.facts_org_scope;
ALTER TABLE pc.facts ADD CONSTRAINT facts_org_id_name_subject_type_subject_id_key UNIQUE (org_id, name, subject_type, subject_id);
DROP TRIGGER fact_declarations_one_scope ON pc.fact_declarations;
DROP FUNCTION pc.fact_declarations_one_scope();
DROP INDEX pc.fact_declarations_one_provider_per_connection;
DROP INDEX pc.fact_declarations_one_provider;
CREATE UNIQUE INDEX fact_declarations_one_provider ON pc.fact_declarations (org_id, replace(name, '.', '_')) WHERE active;
ALTER TABLE pc.facts DROP CONSTRAINT facts_connection_fk, DROP COLUMN connection_id;
ALTER TABLE pc.fact_declarations DROP CONSTRAINT fact_declarations_connection_fk, DROP COLUMN connection_id;
