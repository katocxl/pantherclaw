-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Ticket sync: external refs and field ownership (G0 M20 D255; F545,
-- HR-527, HR-528, T-227).
--
-- A case or an incident may be linked to one ticket in an outside ticket
-- system (Jira first, G15): pc.external_refs holds the link, the
-- connection the ticket lives behind and the newest change time the sync
-- has seen of it, so an older or replayed change is never applied after a
-- newer one.
--
-- Field ownership is per organization and per field
-- (pc.ticket_field_owners). PantherClaw always owns state, severity,
-- containment and restoration: no row can give one of them to the ticket
-- system. The other fields (assignee, labels, the ticket's own priority and
-- its comments) belong to the ticket system unless the organization takes
-- them back; a missing row means that default. A change of owner is a
-- protected change in the application.
--
-- An inbound change to a PantherClaw-owned field is dropped and written as
-- a case entry of the new kind EXTERNAL (and audited
-- ticket.owned_field_ignored). EXTERNAL entries are written by the sync
-- actor only (author type system), carry a text and nothing else, and may
-- land on a closed case, so a change seen after closure is still recorded.
-- They move nothing: the case's state, owners and containment change only
-- by the entries that did before (00122). A ticket status never restores
-- authority (HR-527): nothing here reaches a containment control, a
-- restoration plan or an approval.

-- +goose Up
ALTER TABLE pc.case_entries
    DROP CONSTRAINT case_entries_kind_check,
    ADD CONSTRAINT case_entries_kind_check
        CHECK (kind IN ('FACT', 'HYPOTHESIS', 'QUESTION', 'ANSWER', 'NOTE', 'IMPACT', 'LINK', 'OWNER', 'STATE', 'EXTERNAL')) NOT VALID,
    DROP CONSTRAINT case_entries_check8,
    ADD CONSTRAINT case_entries_check8
        CHECK ((kind IN ('FACT', 'HYPOTHESIS', 'QUESTION', 'ANSWER', 'NOTE', 'IMPACT', 'EXTERNAL')) = (text IS NOT NULL AND btrim(text) <> '')) NOT VALID,
    ADD CONSTRAINT case_entries_external_author CHECK (kind <> 'EXTERNAL' OR author_type = 'system') NOT VALID;
ALTER TABLE pc.case_entries VALIDATE CONSTRAINT case_entries_kind_check;
ALTER TABLE pc.case_entries VALIDATE CONSTRAINT case_entries_check8;
ALTER TABLE pc.case_entries VALIDATE CONSTRAINT case_entries_external_author;

-- The entry trigger of 00122 with one change: a closed case also takes
-- EXTERNAL entries.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.case_entry_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    b      jsonb;
    c      pc.cases%ROWTYPE;
    l      pc.ledger_entries%ROWTYPE;
    r      jsonb;
    target pc.case_entries%ROWTYPE;
    ok     boolean;
BEGIN
    BEGIN
        b := convert_from(NEW.body, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'a case entry body is a JSON object' USING ERRCODE = 'check_violation';
    END;
    IF jsonb_typeof(b) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'a case entry body is a JSON object' USING ERRCODE = 'check_violation';
    END IF;
    IF b->>'v' IS DISTINCT FROM '1' OR b->>'case' IS DISTINCT FROM NEW.case_id::text
       OR b->>'id' IS DISTINCT FROM NEW.id::text THEN
        RAISE EXCEPTION 'the case entry body names another case or entry' USING ERRCODE = 'check_violation';
    END IF;

    SELECT * INTO c FROM pc.cases WHERE org_id = NEW.org_id AND id = NEW.case_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'case not found' USING ERRCODE = 'foreign_key_violation';
    END IF;

    -- Every column comes from the body.
    NEW.seq := (b->>'seq')::bigint;
    NEW.kind := b->>'kind';
    NEW.author_type := b#>>'{author,type}';
    NEW.author_id := b#>>'{author,id}';
    NEW.text := b->>'text';
    NEW.basis := b->>'basis';
    NEW.evidence := coalesce(b->'evidence', '[]'::jsonb);
    NEW.confidence := b->>'confidence';
    NEW.alternatives := coalesce(ARRAY(SELECT jsonb_array_elements_text(b->'alternatives')), '{}');
    NEW.question_id := (b->>'question')::uuid;
    NEW.unresolved := coalesce((b->>'unresolved')::boolean, false);
    NEW.owner_id := (b->>'owner')::uuid;
    NEW.owner_role := b->>'owner_role';
    NEW.impact_kind := b->>'impact';
    NEW.ref_kind := b#>>'{ref,kind}';
    NEW.ref_id := b#>>'{ref,id}';
    NEW.to_state := b->>'state';
    NEW.no_containment_needed := coalesce((b->>'no_containment_needed')::boolean, false);
    NEW.disposition := b->>'disposition';
    NEW.case_impact := b->>'case_impact';
    NEW.reason := b->>'reason';
    NEW.supersedes := (b->>'supersedes')::uuid;
    NEW.created_at := now();

    IF NEW.seq IS DISTINCT FROM c.head_seq + 1 THEN
        RAISE EXCEPTION 'case entry % is out of order (head %)', NEW.seq, c.head_seq USING ERRCODE = 'check_violation';
    END IF;
    NEW.prev_hash := c.head_hash;
    NEW.entry_hash := sha256(c.head_hash || NEW.body);

    -- The same body is in the org's evidence ledger, by the same actor.
    SELECT * INTO l FROM pc.ledger_entries WHERE org_id = NEW.org_id AND id = NEW.ledger_entry_id;
    IF NOT FOUND OR l.kind <> 'reflex.case' OR l.body IS DISTINCT FROM NEW.body
       OR l.actor_type IS DISTINCT FROM NEW.author_type OR l.actor_id IS DISTINCT FROM NEW.author_id THEN
        RAISE EXCEPTION 'a case entry is recorded in the ledger with the same body and actor' USING ERRCODE = 'check_violation';
    END IF;

    -- Only some kinds may land on a closed case.
    IF c.state = 'CLOSED' AND NOT (NEW.kind IN ('FACT', 'ANSWER', 'NOTE', 'EXTERNAL')
                                   OR (NEW.kind = 'OWNER' AND NEW.owner_role = 'FOLLOW_UP')) THEN
        RAISE EXCEPTION 'a closed case takes only facts, answers, notes, external changes and a follow-up owner' USING ERRCODE = 'check_violation';
    END IF;

    -- Fields that belong to other kinds stay empty.
    IF (NEW.kind <> 'FACT' AND NEW.evidence <> '[]'::jsonb AND NEW.kind <> 'IMPACT')
       OR (NEW.kind <> 'HYPOTHESIS' AND (NEW.confidence IS NOT NULL OR cardinality(NEW.alternatives) > 0))
       OR (NEW.kind NOT IN ('FACT', 'HYPOTHESIS') AND NEW.basis IS NOT NULL)
       OR (NEW.kind <> 'ANSWER' AND (NEW.question_id IS NOT NULL OR NEW.unresolved))
       OR (NEW.kind NOT IN ('QUESTION', 'OWNER') AND NEW.owner_id IS NOT NULL)
       OR (NEW.kind <> 'OWNER' AND NEW.owner_role IS NOT NULL)
       OR (NEW.kind <> 'IMPACT' AND NEW.impact_kind IS NOT NULL)
       OR (NEW.kind <> 'LINK' AND (NEW.ref_kind IS NOT NULL OR NEW.ref_id IS NOT NULL))
       OR (NEW.kind <> 'STATE' AND (NEW.to_state IS NOT NULL OR NEW.disposition IS NOT NULL OR NEW.case_impact IS NOT NULL))
       OR (NEW.kind NOT IN ('STATE', 'LINK') AND NEW.reason IS NOT NULL) THEN
        RAISE EXCEPTION 'the case entry carries fields of another kind' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.kind = 'OWNER' AND NEW.owner_id IS NULL THEN
        RAISE EXCEPTION 'an owner entry names the owner' USING ERRCODE = 'check_violation';
    END IF;
    -- A person's question has an owner (D19, D62); the product's seeded
    -- questions are owned once a person takes them on.
    IF NEW.kind = 'QUESTION' AND NEW.owner_id IS NULL AND NEW.author_type = 'user' THEN
        RAISE EXCEPTION 'a question names its owner' USING ERRCODE = 'check_violation';
    END IF;
    -- At most 1000 links per case, so the case's scope is always read whole.
    IF NEW.kind = 'LINK' AND (SELECT count(*) FROM pc.case_entries x
                              WHERE x.org_id = NEW.org_id AND x.case_id = NEW.case_id AND x.kind = 'LINK') >= 1000 THEN
        RAISE EXCEPTION 'CASE_LINKS_EXHAUSTED: a case links at most 1000 subjects' USING ERRCODE = 'check_violation';
    END IF;
    IF cardinality(NEW.alternatives) > 8 OR EXISTS (
        SELECT 1 FROM unnest(NEW.alternatives) a WHERE char_length(btrim(a)) NOT BETWEEN 1 AND 500) THEN
        RAISE EXCEPTION 'a hypothesis has at most 8 alternatives of 1 to 500 characters' USING ERRCODE = 'check_violation';
    END IF;

    -- Evidence refs exist in the org (HR-245).
    IF jsonb_array_length(NEW.evidence) > 32 THEN
        RAISE EXCEPTION 'at most 32 evidence refs' USING ERRCODE = 'check_violation';
    END IF;
    FOR r IN SELECT * FROM jsonb_array_elements(NEW.evidence) LOOP
        BEGIN
            ok := CASE r->>'kind'
                WHEN 'transaction' THEN EXISTS (SELECT 1 FROM pc.transactions t WHERE t.org_id = NEW.org_id AND t.id = (r->>'id')::uuid)
                WHEN 'run' THEN EXISTS (SELECT 1 FROM pc.runs x WHERE x.org_id = NEW.org_id AND x.id = (r->>'id')::uuid)
                WHEN 'ledger' THEN EXISTS (SELECT 1 FROM pc.ledger_entries e WHERE e.org_id = NEW.org_id AND e.id = (r->>'id')::uuid)
                WHEN 'receipt' THEN EXISTS (SELECT 1 FROM pc.ledger_entries e WHERE e.org_id = NEW.org_id AND e.id = (r->>'id')::uuid
                                                AND e.kind LIKE 'receipt.%')
                WHEN 'case_entry' THEN EXISTS (SELECT 1 FROM pc.case_entries e WHERE e.org_id = NEW.org_id AND e.id = (r->>'id')::uuid)
                ELSE false
            END;
        EXCEPTION WHEN invalid_text_representation THEN
            ok := false;
        END;
        IF NOT ok OR (SELECT count(*) FROM jsonb_object_keys(r)) <> 2 THEN
            RAISE EXCEPTION 'evidence ref % is not in the organization', r USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;

    -- An answer answers a question of this case.
    IF NEW.kind = 'ANSWER' AND NOT EXISTS (
        SELECT 1 FROM pc.case_entries q
        WHERE q.org_id = NEW.org_id AND q.case_id = NEW.case_id AND q.id = NEW.question_id AND q.kind = 'QUESTION') THEN
        RAISE EXCEPTION 'an answer refers to a question of the same case' USING ERRCODE = 'check_violation';
    END IF;

    -- Supersession replaces a standing entry of the same kind and case.
    IF NEW.supersedes IS NOT NULL THEN
        SELECT * INTO target FROM pc.case_entries
        WHERE org_id = NEW.org_id AND case_id = NEW.case_id AND id = NEW.supersedes;
        IF NOT FOUND OR target.kind <> NEW.kind OR NEW.kind IN ('STATE', 'OWNER') THEN
            RAISE EXCEPTION 'an entry supersedes an earlier entry of the same kind in the same case (not a state or owner)'
                USING ERRCODE = 'check_violation';
        END IF;
        -- A link is replaced only by a link to the same kind of subject, and
        -- says why (D62): unlinking never quietly drops a containment action
        -- or narrows who may read the case.
        IF NEW.kind = 'LINK' AND (target.ref_kind IS DISTINCT FROM NEW.ref_kind OR NEW.reason IS NULL) THEN
            RAISE EXCEPTION 'a link supersedes a link of the same kind, with a reason' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TABLE pc.external_refs (
    org_id            uuid        NOT NULL REFERENCES pc.orgs (id),
    id                uuid        NOT NULL,
    -- Exactly one of a case or an incident.
    case_id           uuid,
    incident_id       uuid,
    system            text        NOT NULL CHECK (system IN ('jira')),
    -- The connection the ticket lives behind: its credential stays sealed
    -- to the gateway (HR-060), the server only names it.
    connection_id     uuid        NOT NULL,
    external_key      text        NOT NULL CHECK (external_key ~ '^[A-Z][A-Z0-9_]{1,9}-[1-9][0-9]{0,9}$'),
    external_id       text        CHECK (external_id IS NULL OR external_id ~ '^[0-9]{1,20}$'),
    created_by        text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 300),
    created_at        timestamptz NOT NULL DEFAULT now(),
    -- The newest change time of the ticket the sync applied or recorded;
    -- an inbound change at or before it is a replay and changes nothing.
    remote_updated_at timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, case_id) REFERENCES pc.cases (org_id, id),
    FOREIGN KEY (org_id, incident_id) REFERENCES pc.incidents (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    CHECK ((case_id IS NULL) <> (incident_id IS NULL))
);
CREATE UNIQUE INDEX external_refs_case ON pc.external_refs (org_id, system, case_id) WHERE case_id IS NOT NULL;
CREATE UNIQUE INDEX external_refs_incident ON pc.external_refs (org_id, system, incident_id) WHERE incident_id IS NOT NULL;
CREATE UNIQUE INDEX external_refs_ticket ON pc.external_refs (org_id, system, connection_id, external_key);

-- A ref keeps what it links; its change time only moves forward.
-- +goose StatementBegin
CREATE FUNCTION pc.external_ref_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.remote_updated_at IS NULL OR (OLD.remote_updated_at IS NOT NULL AND NEW.remote_updated_at <= OLD.remote_updated_at) THEN
        RAISE EXCEPTION 'an external ref''s change time only moves forward' USING ERRCODE = 'check_violation';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER external_refs_guard BEFORE INSERT OR UPDATE ON pc.external_refs
    FOR EACH ROW EXECUTE FUNCTION pc.external_ref_guard();

CREATE TABLE pc.ticket_field_owners (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    field      text        NOT NULL CHECK (field IN ('state', 'severity', 'containment', 'restoration',
                                                     'assignee', 'labels', 'priority', 'comments')),
    owner      text        NOT NULL CHECK (owner IN ('PANTHERCLAW', 'TICKET')),
    changed_by text        NOT NULL CHECK (char_length(changed_by) BETWEEN 1 AND 300),
    changed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, field),
    -- PantherClaw always owns what decides authority (HR-527, HR-528).
    CHECK (field NOT IN ('state', 'severity', 'containment', 'restoration') OR owner = 'PANTHERCLAW')
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['external_refs', 'ticket_field_owners']
    LOOP
        EXECUTE format('ALTER TABLE pc.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE pc.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.%I FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard()', t);
        EXECUTE format($p$CREATE POLICY tenant_isolation ON pc.%I
            USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
            WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))$p$, t);
    END LOOP;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON pc.external_refs, pc.ticket_field_owners TO pc_app;
GRANT UPDATE (remote_updated_at, updated_at) ON pc.external_refs TO pc_app;
GRANT UPDATE (owner, changed_by, changed_at) ON pc.ticket_field_owners TO pc_app;
GRANT SELECT ON pc.external_refs, pc.ticket_field_owners TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.ticket_field_owners;
DROP TABLE pc.external_refs;
DROP FUNCTION pc.external_ref_guard();
-- EXTERNAL entries are hash-chained into their cases and the ledger
-- (00122), so none can be removed without breaking a chain: going back
-- refuses while any exists.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pc.case_entries WHERE kind = 'EXTERNAL') THEN
        RAISE EXCEPTION '00242 down: EXTERNAL case entries exist and are part of hash chains';
    END IF;
END
$$;
-- +goose StatementEnd
ALTER TABLE pc.case_entries
    DROP CONSTRAINT case_entries_external_author,
    DROP CONSTRAINT case_entries_check8,
    ADD CONSTRAINT case_entries_check8
        CHECK ((kind IN ('FACT', 'HYPOTHESIS', 'QUESTION', 'ANSWER', 'NOTE', 'IMPACT')) = (text IS NOT NULL AND btrim(text) <> '')),
    DROP CONSTRAINT case_entries_kind_check,
    ADD CONSTRAINT case_entries_kind_check
        CHECK (kind IN ('FACT', 'HYPOTHESIS', 'QUESTION', 'ANSWER', 'NOTE', 'IMPACT', 'LINK', 'OWNER', 'STATE'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.case_entry_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    b      jsonb;
    c      pc.cases%ROWTYPE;
    l      pc.ledger_entries%ROWTYPE;
    r      jsonb;
    target pc.case_entries%ROWTYPE;
    ok     boolean;
BEGIN
    BEGIN
        b := convert_from(NEW.body, 'UTF8')::jsonb;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'a case entry body is a JSON object' USING ERRCODE = 'check_violation';
    END;
    IF jsonb_typeof(b) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'a case entry body is a JSON object' USING ERRCODE = 'check_violation';
    END IF;
    IF b->>'v' IS DISTINCT FROM '1' OR b->>'case' IS DISTINCT FROM NEW.case_id::text
       OR b->>'id' IS DISTINCT FROM NEW.id::text THEN
        RAISE EXCEPTION 'the case entry body names another case or entry' USING ERRCODE = 'check_violation';
    END IF;

    SELECT * INTO c FROM pc.cases WHERE org_id = NEW.org_id AND id = NEW.case_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'case not found' USING ERRCODE = 'foreign_key_violation';
    END IF;

    -- Every column comes from the body.
    NEW.seq := (b->>'seq')::bigint;
    NEW.kind := b->>'kind';
    NEW.author_type := b#>>'{author,type}';
    NEW.author_id := b#>>'{author,id}';
    NEW.text := b->>'text';
    NEW.basis := b->>'basis';
    NEW.evidence := coalesce(b->'evidence', '[]'::jsonb);
    NEW.confidence := b->>'confidence';
    NEW.alternatives := coalesce(ARRAY(SELECT jsonb_array_elements_text(b->'alternatives')), '{}');
    NEW.question_id := (b->>'question')::uuid;
    NEW.unresolved := coalesce((b->>'unresolved')::boolean, false);
    NEW.owner_id := (b->>'owner')::uuid;
    NEW.owner_role := b->>'owner_role';
    NEW.impact_kind := b->>'impact';
    NEW.ref_kind := b#>>'{ref,kind}';
    NEW.ref_id := b#>>'{ref,id}';
    NEW.to_state := b->>'state';
    NEW.no_containment_needed := coalesce((b->>'no_containment_needed')::boolean, false);
    NEW.disposition := b->>'disposition';
    NEW.case_impact := b->>'case_impact';
    NEW.reason := b->>'reason';
    NEW.supersedes := (b->>'supersedes')::uuid;
    NEW.created_at := now();

    IF NEW.seq IS DISTINCT FROM c.head_seq + 1 THEN
        RAISE EXCEPTION 'case entry % is out of order (head %)', NEW.seq, c.head_seq USING ERRCODE = 'check_violation';
    END IF;
    NEW.prev_hash := c.head_hash;
    NEW.entry_hash := sha256(c.head_hash || NEW.body);

    -- The same body is in the org's evidence ledger, by the same actor.
    SELECT * INTO l FROM pc.ledger_entries WHERE org_id = NEW.org_id AND id = NEW.ledger_entry_id;
    IF NOT FOUND OR l.kind <> 'reflex.case' OR l.body IS DISTINCT FROM NEW.body
       OR l.actor_type IS DISTINCT FROM NEW.author_type OR l.actor_id IS DISTINCT FROM NEW.author_id THEN
        RAISE EXCEPTION 'a case entry is recorded in the ledger with the same body and actor' USING ERRCODE = 'check_violation';
    END IF;

    -- Only some kinds may land on a closed case.
    IF c.state = 'CLOSED' AND NOT (NEW.kind IN ('FACT', 'ANSWER', 'NOTE')
                                   OR (NEW.kind = 'OWNER' AND NEW.owner_role = 'FOLLOW_UP')) THEN
        RAISE EXCEPTION 'a closed case takes only facts, answers, notes and a follow-up owner' USING ERRCODE = 'check_violation';
    END IF;

    -- Fields that belong to other kinds stay empty.
    IF (NEW.kind <> 'FACT' AND NEW.evidence <> '[]'::jsonb AND NEW.kind <> 'IMPACT')
       OR (NEW.kind <> 'HYPOTHESIS' AND (NEW.confidence IS NOT NULL OR cardinality(NEW.alternatives) > 0))
       OR (NEW.kind NOT IN ('FACT', 'HYPOTHESIS') AND NEW.basis IS NOT NULL)
       OR (NEW.kind <> 'ANSWER' AND (NEW.question_id IS NOT NULL OR NEW.unresolved))
       OR (NEW.kind NOT IN ('QUESTION', 'OWNER') AND NEW.owner_id IS NOT NULL)
       OR (NEW.kind <> 'OWNER' AND NEW.owner_role IS NOT NULL)
       OR (NEW.kind <> 'IMPACT' AND NEW.impact_kind IS NOT NULL)
       OR (NEW.kind <> 'LINK' AND (NEW.ref_kind IS NOT NULL OR NEW.ref_id IS NOT NULL))
       OR (NEW.kind <> 'STATE' AND (NEW.to_state IS NOT NULL OR NEW.disposition IS NOT NULL OR NEW.case_impact IS NOT NULL))
       OR (NEW.kind NOT IN ('STATE', 'LINK') AND NEW.reason IS NOT NULL) THEN
        RAISE EXCEPTION 'the case entry carries fields of another kind' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.kind = 'OWNER' AND NEW.owner_id IS NULL THEN
        RAISE EXCEPTION 'an owner entry names the owner' USING ERRCODE = 'check_violation';
    END IF;
    -- A person's question has an owner (D19, D62); the product's seeded
    -- questions are owned once a person takes them on.
    IF NEW.kind = 'QUESTION' AND NEW.owner_id IS NULL AND NEW.author_type = 'user' THEN
        RAISE EXCEPTION 'a question names its owner' USING ERRCODE = 'check_violation';
    END IF;
    -- At most 1000 links per case, so the case's scope is always read whole.
    IF NEW.kind = 'LINK' AND (SELECT count(*) FROM pc.case_entries x
                              WHERE x.org_id = NEW.org_id AND x.case_id = NEW.case_id AND x.kind = 'LINK') >= 1000 THEN
        RAISE EXCEPTION 'CASE_LINKS_EXHAUSTED: a case links at most 1000 subjects' USING ERRCODE = 'check_violation';
    END IF;
    IF cardinality(NEW.alternatives) > 8 OR EXISTS (
        SELECT 1 FROM unnest(NEW.alternatives) a WHERE char_length(btrim(a)) NOT BETWEEN 1 AND 500) THEN
        RAISE EXCEPTION 'a hypothesis has at most 8 alternatives of 1 to 500 characters' USING ERRCODE = 'check_violation';
    END IF;

    -- Evidence refs exist in the org (HR-245).
    IF jsonb_array_length(NEW.evidence) > 32 THEN
        RAISE EXCEPTION 'at most 32 evidence refs' USING ERRCODE = 'check_violation';
    END IF;
    FOR r IN SELECT * FROM jsonb_array_elements(NEW.evidence) LOOP
        BEGIN
            ok := CASE r->>'kind'
                WHEN 'transaction' THEN EXISTS (SELECT 1 FROM pc.transactions t WHERE t.org_id = NEW.org_id AND t.id = (r->>'id')::uuid)
                WHEN 'run' THEN EXISTS (SELECT 1 FROM pc.runs x WHERE x.org_id = NEW.org_id AND x.id = (r->>'id')::uuid)
                WHEN 'ledger' THEN EXISTS (SELECT 1 FROM pc.ledger_entries e WHERE e.org_id = NEW.org_id AND e.id = (r->>'id')::uuid)
                WHEN 'receipt' THEN EXISTS (SELECT 1 FROM pc.ledger_entries e WHERE e.org_id = NEW.org_id AND e.id = (r->>'id')::uuid
                                                AND e.kind LIKE 'receipt.%')
                WHEN 'case_entry' THEN EXISTS (SELECT 1 FROM pc.case_entries e WHERE e.org_id = NEW.org_id AND e.id = (r->>'id')::uuid)
                ELSE false
            END;
        EXCEPTION WHEN invalid_text_representation THEN
            ok := false;
        END;
        IF NOT ok OR (SELECT count(*) FROM jsonb_object_keys(r)) <> 2 THEN
            RAISE EXCEPTION 'evidence ref % is not in the organization', r USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;

    -- An answer answers a question of this case.
    IF NEW.kind = 'ANSWER' AND NOT EXISTS (
        SELECT 1 FROM pc.case_entries q
        WHERE q.org_id = NEW.org_id AND q.case_id = NEW.case_id AND q.id = NEW.question_id AND q.kind = 'QUESTION') THEN
        RAISE EXCEPTION 'an answer refers to a question of the same case' USING ERRCODE = 'check_violation';
    END IF;

    -- Supersession replaces a standing entry of the same kind and case.
    IF NEW.supersedes IS NOT NULL THEN
        SELECT * INTO target FROM pc.case_entries
        WHERE org_id = NEW.org_id AND case_id = NEW.case_id AND id = NEW.supersedes;
        IF NOT FOUND OR target.kind <> NEW.kind OR NEW.kind IN ('STATE', 'OWNER') THEN
            RAISE EXCEPTION 'an entry supersedes an earlier entry of the same kind in the same case (not a state or owner)'
                USING ERRCODE = 'check_violation';
        END IF;
        -- A link is replaced only by a link to the same kind of subject, and
        -- says why (D62): unlinking never quietly drops a containment action
        -- or narrows who may read the case.
        IF NEW.kind = 'LINK' AND (target.ref_kind IS DISTINCT FROM NEW.ref_kind OR NEW.reason IS NULL) THEN
            RAISE EXCEPTION 'a link supersedes a link of the same kind, with a reason' USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
