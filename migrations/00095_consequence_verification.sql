-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The deployment a merge starts is verified on its own (G0 M8 W1c, HR-206,
-- coordinator decision 2026-10-13). When the merge's effect is confirmed,
-- the server opens a consequence transaction for each deployment the
-- decision predicted: never dispatched, linked to the merge (link kind
-- consequence), and verified by M7's machinery under a verification task
-- of purpose consequence. Such a task has no permit, so it carries the
-- definition it verifies and the time its window starts. A status that
-- suggests the deployment did not take effect, or no deployment by the
-- deadline, opens a reconciliation of kind consequence_unconfirmed: only a
-- person decides that something did not happen (HR-192).

-- +goose Up
ALTER TABLE pc.transaction_links
    DROP CONSTRAINT transaction_links_kind_check,
    ADD CONSTRAINT transaction_links_kind_check CHECK (kind IN ('compensates', 'recovers', 'consequence'));

ALTER TABLE pc.reconciliation_tasks
    DROP CONSTRAINT reconciliation_tasks_kind_check,
    ADD CONSTRAINT reconciliation_tasks_kind_check CHECK (kind IN ('unknown_outcome', 'conflicting_effect', 'consequence_unconfirmed'));

ALTER TABLE pc.verifications
    ADD COLUMN definition_digest text CHECK (definition_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD COLUMN basis_at          timestamptz,
    ADD CONSTRAINT verifications_basis CHECK ((purpose = 'consequence') = (definition_digest IS NOT NULL AND basis_at IS NOT NULL));

-- The purpose checks gain consequence, whatever their names (00081 and
-- 00084 rewrote them); any other shape fails the migration.
-- +goose StatementBegin
DO $$
DECLARE
    c        record;
    purposes text;
    n        integer := 0;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%purpose%' AND pg_get_constraintdef(oid) LIKE '%follow_up%'
               AND pg_get_constraintdef(oid) NOT LIKE '%transaction_id IS NULL%' LOOP
        SELECT string_agg(quote_literal(m.v[1]), ', ' ORDER BY m.i) INTO purposes
          FROM regexp_matches(c.def, '''([a-z_]+)''', 'g') WITH ORDINALITY AS m (v, i);
        IF purposes IS NULL OR purposes LIKE '%consequence%' THEN
            RAISE EXCEPTION '00095: unexpected check % on pc.verifications: %', c.conname, c.def;
        END IF;
        EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (purpose IN (%s))',
                       c.conname, c.conname, purposes || ', ''consequence''');
        n := n + 1;
    END LOOP;
    IF n <> 1 THEN
        RAISE EXCEPTION '00095: found % purpose lists on pc.verifications, not 1', n;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE pc.observations NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.reconciliation_tasks NO FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.transaction_links NO FORCE ROW LEVEL SECURITY;
DELETE FROM pc.observations o USING pc.verifications v
 WHERE o.org_id = v.org_id AND o.verification_id = v.id AND v.purpose = 'consequence';
DELETE FROM pc.verifications WHERE purpose = 'consequence';
DELETE FROM pc.reconciliation_tasks WHERE kind = 'consequence_unconfirmed';
ALTER TABLE pc.observations FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.verifications FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.reconciliation_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE pc.transaction_links FORCE ROW LEVEL SECURITY;
-- +goose StatementBegin
DO $$
DECLARE
    c record;
BEGIN
    FOR c IN SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint
             WHERE conrelid = 'pc.verifications'::regclass AND contype = 'c'
               AND pg_get_constraintdef(oid) LIKE '%''consequence''%' AND pg_get_constraintdef(oid) LIKE '%follow_up%' LOOP
        EXECUTE format('ALTER TABLE pc.verifications DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK (%s)', c.conname, c.conname,
                       replace(regexp_replace(c.def, '^CHECK \((.*)\)$', '\1'), ', ''consequence''::text', ''));
    END LOOP;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.verifications DROP CONSTRAINT verifications_basis, DROP COLUMN basis_at, DROP COLUMN definition_digest;
ALTER TABLE pc.reconciliation_tasks
    DROP CONSTRAINT reconciliation_tasks_kind_check,
    ADD CONSTRAINT reconciliation_tasks_kind_check CHECK (kind IN ('unknown_outcome', 'conflicting_effect'));
DELETE FROM pc.transaction_links WHERE kind = 'consequence';
ALTER TABLE pc.transaction_links
    DROP CONSTRAINT transaction_links_kind_check,
    ADD CONSTRAINT transaction_links_kind_check CHECK (kind IN ('compensates', 'recovers'));
