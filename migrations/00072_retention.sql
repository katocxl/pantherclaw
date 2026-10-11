-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Retention and legal holds (G0 M7 track B slice B8, design decision 9,
-- founder decision 4; HR-198, HR-055, T-075). Numbered after 00070 (ADR-0015)
-- and A11's 00071, founder decision 2026-10-10.
--
-- retention_policies keeps every revision of each category's period,
-- immutable. The revision in effect at a time is the newest one that took
-- effect by then and that no later revision cancelled: a revision recorded
-- before an earlier one took effect cancels it (pc.retention_current). A
-- shortening takes effect 7 days after it was recorded, which a trigger
-- enforces on top of the application. Revision 1 of a category is its
-- default, recorded by the system (set_by NULL).
--
-- legal_holds block removal inside their scope while ACTIVE: the org, an
-- agent, a run, a transaction or a time range. pc.retention_held decides
-- whether an item is inside an active hold from the item's time and the id
-- it relates to (its transaction, an approval request, or an audit event's
-- object), following transactions to runs and runs to agents.
--
-- Bodies are removed by pc_retention, a login role of its own (bootstrap)
-- used only by the worker's retention job. It can null exactly the body
-- columns of the evidence tables and set their tombstone, delete replay
-- inputs, read what it needs to choose them, and append its own audit
-- entry; nothing else. A trigger refuses any other change of an evidence
-- row by a role other than the schema owner (who could drop the trigger
-- anyway): a row is never inserted removed, a removal sets the tombstone
-- and nulls the body and changes nothing else, and a removed body is never
-- rebuilt. Ledger entries lose their body only once chained and covered by
-- a checkpoint, so every body was checked against its hash before it went;
-- chain hashes, Merkle leaves and checkpoints are never touched. pc_app
-- keeps no UPDATE or DELETE on evidence (HR-055).
--
-- retention_status is the job's per-org bookkeeping; the lister's
-- retention_due purpose lists active orgs without a successful run in the
-- last day.

-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_retention') THEN
        RAISE EXCEPTION '00072_retention: role pc_retention is missing; run pantherclaw-server db bootstrap with --retention-password-file first';
    END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE pc.retention_policies (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    category       text        NOT NULL CHECK (category IN ('payloads', 'normalized_facts', 'receipts', 'approvals',
                                                            'security_audit')),
    revision       integer     NOT NULL CHECK (revision BETWEEN 1 AND 100000),
    days           integer     NOT NULL,
    set_by         uuid,
    effective_from timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, category, revision),
    FOREIGN KEY (org_id, set_by) REFERENCES pc.users (org_id, id),
    -- The bounds of design decision 9.
    CONSTRAINT retention_policies_days CHECK (CASE category
        WHEN 'payloads' THEN days BETWEEN 1 AND 30
        WHEN 'normalized_facts' THEN days BETWEEN 7 AND 730
        WHEN 'receipts' THEN days BETWEEN 30 AND 3650
        ELSE days BETWEEN 365 AND 3650 END),
    -- Never earlier than recorded; the system's default at once.
    CHECK (effective_from >= created_at),
    CHECK (set_by IS NOT NULL OR effective_from = created_at)
);

CREATE TABLE pc.legal_holds (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    scope          text        NOT NULL CHECK (scope IN ('org', 'agent', 'run', 'transaction', 'time_range')),
    scope_id       uuid,
    range_start    timestamptz,
    range_end      timestamptz,
    reason         text        NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 2000),
    state          text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'RELEASED')),
    created_by     uuid        NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    released_by    uuid,
    released_at    timestamptz,
    release_reason text        CHECK (char_length(release_reason) BETWEEN 1 AND 2000),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, released_by) REFERENCES pc.users (org_id, id),
    CHECK ((scope IN ('agent', 'run', 'transaction')) = (scope_id IS NOT NULL)),
    CHECK ((scope = 'time_range') = (range_start IS NOT NULL AND range_end IS NOT NULL)),
    CHECK (range_start IS NULL OR range_start < range_end),
    CHECK ((state = 'RELEASED') = (released_by IS NOT NULL AND released_at IS NOT NULL AND release_reason IS NOT NULL))
);
CREATE INDEX legal_holds_active ON pc.legal_holds (org_id, scope) WHERE state = 'ACTIVE';

CREATE TABLE pc.retention_status (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    last_attempt_at timestamptz NOT NULL,
    last_run_at     timestamptz,
    last_error      text        CHECK (last_error IS NULL OR last_error ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    removed         bigint      NOT NULL DEFAULT 0 CHECK (removed >= 0),
    PRIMARY KEY (org_id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['retention_policies', 'legal_holds', 'retention_status']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- The revision of category in effect for the current org at p_at.
-- +goose StatementBegin
CREATE FUNCTION pc.retention_current(p_category text, p_at timestamptz)
RETURNS TABLE (id uuid, revision integer, days integer)
LANGUAGE sql STABLE
SET search_path = pc, pg_temp
AS $$
    SELECT p.id, p.revision, p.days
    FROM pc.retention_policies p
    WHERE p.category = p_category AND p.effective_from <= p_at
      AND NOT EXISTS (SELECT 1 FROM pc.retention_policies n
                      WHERE n.org_id = p.org_id AND n.category = p.category
                        AND n.revision > p.revision AND n.created_at < p.effective_from)
    ORDER BY p.revision DESC
    LIMIT 1
$$;
-- +goose StatementEnd

-- Revisions are consecutive, and a revision shorter than the one in
-- effect (or than the default, before any) takes effect at least 7 days
-- after it is recorded (HR-198).
-- +goose StatementBegin
CREATE FUNCTION pc.retention_policies_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    cur integer;
    last integer;
BEGIN
    SELECT max(p.revision) INTO last FROM pc.retention_policies p
    WHERE p.org_id = NEW.org_id AND p.category = NEW.category;
    IF NEW.revision <> coalesce(last, 0) + 1 THEN
        RAISE EXCEPTION 'retention_policies: revision % of % is not the next one', NEW.revision, NEW.category
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT c.days INTO cur FROM pc.retention_current(NEW.category, now()) c;
    cur := coalesce(cur, CASE NEW.category WHEN 'payloads' THEN 7 WHEN 'normalized_facts' THEN 90 ELSE 365 END);
    IF NEW.days < cur AND NEW.effective_from < now() + interval '7 days' THEN
        RAISE EXCEPTION 'retention_policies: a shorter retention takes effect 7 days after it is recorded'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER retention_policies_guard BEFORE INSERT ON pc.retention_policies
    FOR EACH ROW EXECUTE FUNCTION pc.retention_policies_guard();

-- Whether an item recorded at p_at and related to p_ref (a transaction, a
-- run, an agent, an approval request, or an audit event's object) is
-- inside an active legal hold of the current org.
-- +goose StatementBegin
CREATE FUNCTION pc.retention_held(p_at timestamptz, p_ref uuid)
RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pc, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1 FROM pc.legal_holds h
        WHERE h.state = 'ACTIVE'
          AND (h.scope = 'org'
            OR (h.scope = 'time_range' AND p_at >= h.range_start AND p_at < h.range_end)
            OR (p_ref IS NOT NULL AND h.scope_id IN (
                SELECT p_ref
                UNION ALL SELECT t.run_id FROM pc.transactions t WHERE t.id = p_ref
                UNION ALL SELECT r.agent_id FROM pc.transactions t
                    JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id WHERE t.id = p_ref
                UNION ALL SELECT r.agent_id FROM pc.runs r WHERE r.id = p_ref
                UNION ALL SELECT q.transaction_id FROM pc.approval_requests q WHERE q.id = p_ref
                UNION ALL SELECT q.run_id FROM pc.approval_requests q WHERE q.id = p_ref
                UNION ALL SELECT q.agent_id FROM pc.approval_requests q WHERE q.id = p_ref))))
$$;
-- +goose StatementEnd

-- The object an audit entry's body names, when it is an id.
-- +goose StatementBegin
CREATE FUNCTION pc.ledger_object(p_body bytea)
RETURNS uuid
LANGUAGE plpgsql IMMUTABLE
SET search_path = pc, pg_temp
AS $$
DECLARE
    o text;
BEGIN
    o := convert_from(p_body, 'UTF8')::jsonb #>> '{object,id}';
    IF o ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
        RETURN o::uuid;
    END IF;
    RETURN NULL;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- The only change of an evidence row a role other than the schema owner
-- may make: removing its body (TG_ARGV[0]) under a policy, once.
-- +goose StatementBegin
CREATE FUNCTION pc.evidence_body_removal()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    tomb text[] := ARRAY[TG_ARGV[0], 'body_removed_at', 'removed_by_policy'];
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.body_removed_at IS NOT NULL OR NEW.removed_by_policy IS NOT NULL THEN
            RAISE EXCEPTION '%: a row is never recorded removed', TG_TABLE_NAME USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF pg_has_role(current_user, 'pc_migrator', 'USAGE') THEN
        RETURN NEW;
    END IF;
    IF OLD.body_removed_at IS NOT NULL THEN
        RAISE EXCEPTION '%: a removed body is never rebuilt', TG_TABLE_NAME USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.body_removed_at IS NULL OR NEW.removed_by_policy IS NULL
        OR (to_jsonb(NEW) -> TG_ARGV[0]) <> 'null'::jsonb
        OR (to_jsonb(NEW) - tomb) IS DISTINCT FROM (to_jsonb(OLD) - tomb) THEN
        RAISE EXCEPTION '%: only removing the body under a policy is allowed', TG_TABLE_NAME
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Tombstones on the evidence rows not yet carrying one (00065 added them to
-- the ledger and the receipts), and bodies that can be removed.
ALTER TABLE pc.observations
    ADD COLUMN body_removed_at   timestamptz,
    ADD COLUMN removed_by_policy uuid,
    ADD CONSTRAINT observations_removal CHECK ((body_removed_at IS NULL) = (removed_by_policy IS NULL)),
    ADD CONSTRAINT observations_removed_fields CHECK (body_removed_at IS NULL OR fields IS NULL);
ALTER TABLE pc.approval_evidence
    ADD COLUMN body_removed_at   timestamptz,
    ADD COLUMN removed_by_policy uuid,
    ADD CONSTRAINT approval_evidence_removal CHECK ((body_removed_at IS NULL) = (removed_by_policy IS NULL)),
    ALTER COLUMN note DROP NOT NULL,
    ADD CONSTRAINT approval_evidence_note CHECK ((note IS NULL) = (body_removed_at IS NOT NULL));
ALTER TABLE pc.ledger_entries
    ALTER COLUMN body DROP NOT NULL,
    ADD CONSTRAINT ledger_entries_body CHECK ((body IS NULL) = (body_removed_at IS NOT NULL));
ALTER TABLE pc.decision_receipts
    ALTER COLUMN receipt_jws DROP NOT NULL,
    ADD CONSTRAINT decision_receipts_body CHECK ((receipt_jws IS NULL) = (body_removed_at IS NOT NULL));
ALTER TABLE pc.execution_receipts
    ALTER COLUMN receipt_jws DROP NOT NULL,
    ADD CONSTRAINT execution_receipts_body CHECK ((receipt_jws IS NULL) = (body_removed_at IS NOT NULL));
ALTER TABLE pc.effect_receipts
    ALTER COLUMN receipt_jws DROP NOT NULL,
    ADD CONSTRAINT effect_receipts_body CHECK ((receipt_jws IS NULL) = (body_removed_at IS NOT NULL));

CREATE TRIGGER ledger_entries_body_removal BEFORE INSERT OR UPDATE ON pc.ledger_entries
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_body_removal('body');
CREATE TRIGGER decision_receipts_body_removal BEFORE INSERT OR UPDATE ON pc.decision_receipts
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_body_removal('receipt_jws');
CREATE TRIGGER execution_receipts_body_removal BEFORE INSERT OR UPDATE ON pc.execution_receipts
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_body_removal('receipt_jws');
CREATE TRIGGER effect_receipts_body_removal BEFORE INSERT OR UPDATE ON pc.effect_receipts
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_body_removal('receipt_jws');
CREATE TRIGGER observations_body_removal BEFORE INSERT OR UPDATE ON pc.observations
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_body_removal('fields');
CREATE TRIGGER approval_evidence_body_removal BEFORE INSERT OR UPDATE ON pc.approval_evidence
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_body_removal('note');

-- The job finds what is due, oldest first.
CREATE INDEX ledger_entries_retention ON pc.ledger_entries (org_id, occurred_at) WHERE body_removed_at IS NULL;
CREATE INDEX decision_receipts_retention ON pc.decision_receipts (org_id, created_at) WHERE body_removed_at IS NULL;
CREATE INDEX execution_receipts_retention ON pc.execution_receipts (org_id, created_at) WHERE body_removed_at IS NULL;
CREATE INDEX effect_receipts_retention ON pc.effect_receipts (org_id, created_at) WHERE body_removed_at IS NULL;
CREATE INDEX observations_retention ON pc.observations (org_id, observed_at) WHERE body_removed_at IS NULL;
CREATE INDEX approval_evidence_retention ON pc.approval_evidence (org_id, created_at) WHERE body_removed_at IS NULL;
CREATE INDEX evaluation_inputs_retention ON pc.evaluation_inputs (org_id, created_at);

-- The application: policies are immutable revisions, holds change only
-- their state, and the job's bookkeeping. No evidence grant changes
-- (HR-055).
GRANT SELECT, INSERT ON pc.retention_policies, pc.legal_holds, pc.retention_status TO pc_app;
GRANT UPDATE (state, released_by, released_at, release_reason) ON pc.legal_holds TO pc_app;
GRANT UPDATE (last_attempt_at, last_run_at, last_error, removed) ON pc.retention_status TO pc_app;
GRANT SELECT ON pc.retention_policies, pc.legal_holds, pc.retention_status TO pc_audit_ro;
GRANT EXECUTE ON FUNCTION pc.retention_current(text, timestamptz) TO pc_app;

-- The retention role (design decision 9): the body columns and tombstones,
-- replay inputs, what it reads to choose them, and its own audit entry.
GRANT SELECT (org_id, id, kind, occurred_at, body, body_removed_at) ON pc.ledger_entries TO pc_retention;
GRANT INSERT (org_id, id, kind, actor_type, actor_id, body) ON pc.ledger_entries TO pc_retention;
GRANT UPDATE (body, body_removed_at, removed_by_policy) ON pc.ledger_entries TO pc_retention;
GRANT SELECT (org_id, entry_id, seq) ON pc.ledger_chain TO pc_retention;
GRANT SELECT (org_id, tree_size) ON pc.checkpoints TO pc_retention;
GRANT SELECT (org_id, transaction_id, evaluation, ledger_entry_id, created_at, body_removed_at)
    ON pc.decision_receipts TO pc_retention;
GRANT UPDATE (receipt_jws, body_removed_at, removed_by_policy) ON pc.decision_receipts TO pc_retention;
GRANT SELECT (org_id, attempt_id, transaction_id, ledger_entry_id, created_at, body_removed_at)
    ON pc.execution_receipts TO pc_retention;
GRANT UPDATE (receipt_jws, body_removed_at, removed_by_policy) ON pc.execution_receipts TO pc_retention;
GRANT SELECT (org_id, transaction_id, seq, ledger_entry_id, created_at, body_removed_at)
    ON pc.effect_receipts TO pc_retention;
GRANT UPDATE (receipt_jws, body_removed_at, removed_by_policy) ON pc.effect_receipts TO pc_retention;
GRANT SELECT (org_id, id, transaction_id, observed_at, body_removed_at) ON pc.observations TO pc_retention;
GRANT UPDATE (fields, body_removed_at, removed_by_policy) ON pc.observations TO pc_retention;
GRANT SELECT (org_id, id, request_id, created_at, body_removed_at) ON pc.approval_evidence TO pc_retention;
GRANT UPDATE (note, body_removed_at, removed_by_policy) ON pc.approval_evidence TO pc_retention;
GRANT SELECT (org_id, transaction_id, evaluation, created_at) ON pc.evaluation_inputs TO pc_retention;
GRANT DELETE ON pc.evaluation_inputs TO pc_retention;
GRANT SELECT ON pc.retention_policies TO pc_retention;
GRANT SELECT (org_id, scope, scope_id, range_start, range_end, state) ON pc.legal_holds TO pc_retention;
GRANT SELECT (org_id, id, run_id) ON pc.transactions TO pc_retention;
GRANT SELECT (org_id, id, agent_id) ON pc.runs TO pc_retention;
GRANT SELECT (org_id, id, transaction_id, run_id, agent_id) ON pc.approval_requests TO pc_retention;
GRANT EXECUTE ON FUNCTION pc.retention_current(text, timestamptz), pc.retention_held(timestamptz, uuid),
    pc.ledger_object(bytea) TO pc_retention;

GRANT SELECT (org_id, last_run_at) ON pc.retention_status TO pc_lister;

-- The lister below replaces the whole function, starting from 00070's.
-- Refuse to run if the current one has purposes it does not carry (a
-- migration merged before this one added them), rather than drop them:
-- add them below and to this list first.
-- +goose StatementBegin
DO $$
DECLARE
    found text[];
BEGIN
    SELECT array_agg(m[1] ORDER BY m[1]) INTO found
    FROM regexp_matches(
        (SELECT prosrc FROM pg_proc WHERE oid = 'pc.cross_org_list(text, integer)'::regprocedure),
        'WHEN ''([a-z_]+)'' THEN', 'g') AS m;
    IF found IS DISTINCT FROM ARRAY['budget_settle', 'checkpoints_due', 'integrity_due', 'ledger_unchained', 'orgs',
                                    'permits_sweep', 'verifications_due'] THEN
        RAISE EXCEPTION '00072_retention: pc.cross_org_list has purposes %; carry the new ones into this migration', found;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'retention_due' THEN
            -- Active orgs whose retention job has not run successfully in
            -- the last day (HR-198).
            RETURN QUERY
                SELECT o.id, o.id
                FROM pc.orgs o
                WHERE o.state = 'ACTIVE'
                  AND NOT EXISTS (SELECT 1 FROM pc.retention_status s WHERE s.org_id = o.id
                                  AND s.last_run_at > now() - interval '1 day')
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'verifications_due' THEN
            RETURN QUERY
                SELECT DISTINCT v.org_id, v.org_id
                FROM pc.verifications v
                WHERE (v.state IN ('PENDING', 'LEASED') AND v.deadline_at <= now())
                   OR (v.state = 'LEASED' AND v.lease_expires_at <= now())
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'checkpoints_due' THEN
            -- Orgs whose chain grew past their latest checkpoint and whose
            -- checkpointing has not stopped.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE h.seq > coalesce((SELECT max(c.tree_size) FROM pc.checkpoints c WHERE c.org_id = h.org_id), 0)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id AND i.state = 'FAILED')
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'integrity_due' THEN
            -- Orgs with a checkpoint whose chain was not re-verified in the
            -- last day.
            RETURN QUERY
                SELECT h.org_id, h.org_id
                FROM pc.ledger_heads h
                WHERE EXISTS (SELECT 1 FROM pc.checkpoints c WHERE c.org_id = h.org_id)
                  AND NOT EXISTS (SELECT 1 FROM pc.evidence_integrity i WHERE i.org_id = h.org_id
                                  AND (i.state = 'FAILED' OR i.verified_at > now() - interval '1 day'))
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'budget_settle' THEN
            RETURN QUERY
                SELECT DISTINCT r.org_id, r.org_id
                FROM pc.reservations r
                WHERE r.pending
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
REVOKE SELECT (org_id, last_run_at) ON pc.retention_status FROM pc_lister;
REVOKE ALL ON pc.ledger_entries, pc.ledger_chain, pc.checkpoints, pc.decision_receipts, pc.execution_receipts,
    pc.effect_receipts, pc.observations, pc.approval_evidence, pc.evaluation_inputs, pc.transactions, pc.runs,
    pc.approval_requests FROM pc_retention;
DROP INDEX pc.evaluation_inputs_retention;
DROP INDEX pc.approval_evidence_retention;
DROP INDEX pc.observations_retention;
DROP INDEX pc.effect_receipts_retention;
DROP INDEX pc.execution_receipts_retention;
DROP INDEX pc.decision_receipts_retention;
DROP INDEX pc.ledger_entries_retention;
DROP TRIGGER approval_evidence_body_removal ON pc.approval_evidence;
DROP TRIGGER observations_body_removal ON pc.observations;
DROP TRIGGER effect_receipts_body_removal ON pc.effect_receipts;
DROP TRIGGER execution_receipts_body_removal ON pc.execution_receipts;
DROP TRIGGER decision_receipts_body_removal ON pc.decision_receipts;
DROP TRIGGER ledger_entries_body_removal ON pc.ledger_entries;
-- A removed body cannot come back: these fail once retention removed one.
ALTER TABLE pc.effect_receipts DROP CONSTRAINT effect_receipts_body, ALTER COLUMN receipt_jws SET NOT NULL;
ALTER TABLE pc.execution_receipts DROP CONSTRAINT execution_receipts_body, ALTER COLUMN receipt_jws SET NOT NULL;
ALTER TABLE pc.decision_receipts DROP CONSTRAINT decision_receipts_body, ALTER COLUMN receipt_jws SET NOT NULL;
ALTER TABLE pc.ledger_entries DROP CONSTRAINT ledger_entries_body, ALTER COLUMN body SET NOT NULL;
ALTER TABLE pc.approval_evidence DROP CONSTRAINT approval_evidence_note, ALTER COLUMN note SET NOT NULL,
    DROP CONSTRAINT approval_evidence_removal, DROP COLUMN removed_by_policy, DROP COLUMN body_removed_at;
ALTER TABLE pc.observations DROP CONSTRAINT observations_removed_fields, DROP CONSTRAINT observations_removal,
    DROP COLUMN removed_by_policy, DROP COLUMN body_removed_at;
DROP FUNCTION pc.evidence_body_removal();
DROP FUNCTION pc.ledger_object(bytea);
DROP FUNCTION pc.retention_held(timestamptz, uuid);
DROP TABLE pc.retention_status;
DROP TABLE pc.legal_holds;
DROP TABLE pc.retention_policies;
DROP FUNCTION pc.retention_policies_guard();
DROP FUNCTION pc.retention_current(text, timestamptz);
