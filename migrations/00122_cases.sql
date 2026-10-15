-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Cases (G0 M10 D19; F237, F244, F248, F249, F251, F571, F299; HR-245,
-- HR-246, T-107).
--
-- A case holds what investigators know about an action, a run or an alert:
-- facts with their evidence, hypotheses with confidence and alternatives,
-- open questions with their owner, answers, notes, impact, links and every
-- owner and state change. Each of those is one entry in pc.case_entries,
-- which is append-only (HR-245): pc_app has no UPDATE or DELETE on it and a
-- trigger refuses both for everyone. A later entry may supersede an earlier
-- one of the same kind; nothing is ever changed in place.
--
-- An entry is the canonical JSON body the application builds; the database
-- derives every column from it and checks it:
--   * the body is also the body of a reflex.case ledger entry with the same
--     actor, so each case entry is in the org's evidence chain (D6);
--   * entries are numbered 1, 2, … per case and hash-chained:
--     entry_hash = sha256(prev_hash || body), where prev_hash is the case's
--     head (the genesis head is sha256('pantherclaw/case/v1/' || case id));
--   * a FACT names 1 to 32 evidence refs that exist in the org.
--
-- The case row changes only by the entry the trigger just appended: the
-- head advances by one, and only the fields that entry's kind sets may
-- change. A STATE entry is the only way to move a case, and the closure
-- rules are checked here, in SQL (HR-246):
--   * CONTAINED (operational close): every linked containment action is
--     CONFIRMED (at least one), or the STATE entry says no containment is
--     needed and why;
--   * CLOSED: impact and a disposition are given, at least one FACT stands,
--     and a follow-up owner is named while any QUESTION is still open
--     (F571: forensic questions stay open and owned after containment);
--     straight from OPEN it also needs the CONTAINED rule, whose reason
--     may come with the closing entry.
-- Superseded entries do not count. A closed case takes only facts, answers,
-- notes and a follow-up owner, and no entry may leave it with an open
-- question and no follow-up owner. A link is superseded only by a link to
-- the same kind of subject, with a reason; a case has at most 1000 links.
-- A person's question names its owner.
--
-- A case's containment actions (D43) are its standing LINK entries to
-- response actions plus the pc.response_actions rows whose case_id is the
-- case (M10 response, migration 00123; PL/pgSQL binds that table at run
-- time, so this migration applies first). A missing or unknown action is
-- not confirmed.

-- +goose Up
CREATE TABLE pc.cases (
    org_id                uuid        NOT NULL REFERENCES pc.orgs (id),
    id                    uuid        NOT NULL,
    title                 text        NOT NULL CHECK (char_length(btrim(title)) BETWEEN 1 AND 200),
    -- Who raised what opened it (reflexdomain Signal sources, or a person).
    source                text        NOT NULL CHECK (source IN ('detection', 'response', 'siem', 'signals', 'coverage',
                                                                 'system', 'manual')),
    opened_by_type        text        NOT NULL CHECK (char_length(opened_by_type) BETWEEN 1 AND 32),
    opened_by_id          text        NOT NULL CHECK (char_length(opened_by_id) BETWEEN 1 AND 256),
    -- The alert or incident it was opened from (M10 core; no foreign key so
    -- either side can be retained on its own schedule).
    alert_id              uuid,
    incident_id           uuid,
    state                 text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'CONTAINED', 'CLOSED')),
    owner_id              uuid,
    follow_up_owner_id    uuid,
    disposition           text        CHECK (disposition IN ('TRUE_POSITIVE', 'BENIGN', 'FALSE_POSITIVE', 'INCONCLUSIVE')),
    impact                text        CHECK (impact IN ('CONFIRMED', 'EXPLICITLY_UNRESOLVED', 'NONE_FOUND')),
    head_seq              bigint      NOT NULL DEFAULT 0 CHECK (head_seq >= 0),
    head_hash             bytea       NOT NULL CHECK (octet_length(head_hash) = 32),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    operational_closed_at timestamptz,
    closed_at             timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, owner_id) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, follow_up_owner_id) REFERENCES pc.users (org_id, id),
    CHECK ((state = 'CLOSED') = (closed_at IS NOT NULL)),
    CHECK (state <> 'CLOSED' OR (disposition IS NOT NULL AND impact IS NOT NULL)),
    CHECK (state <> 'CONTAINED' OR operational_closed_at IS NOT NULL)
);
CREATE INDEX cases_open ON pc.cases (org_id, updated_at DESC, id) WHERE state <> 'CLOSED';
CREATE INDEX cases_by_alert ON pc.cases (org_id, alert_id) WHERE alert_id IS NOT NULL;
CREATE INDEX cases_by_incident ON pc.cases (org_id, incident_id) WHERE incident_id IS NOT NULL;

CREATE TABLE pc.case_entries (
    org_id                uuid        NOT NULL,
    case_id               uuid        NOT NULL,
    id                    uuid        NOT NULL,
    seq                   bigint      NOT NULL CHECK (seq > 0),
    -- The canonical JSON the application built; every column below is
    -- derived from it by the insert trigger.
    body                  bytea       NOT NULL CHECK (octet_length(body) BETWEEN 2 AND 8192),
    ledger_entry_id       uuid        NOT NULL,
    prev_hash             bytea       NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash            bytea       NOT NULL CHECK (octet_length(entry_hash) = 32),
    kind                  text        NOT NULL CHECK (kind IN ('FACT', 'HYPOTHESIS', 'QUESTION', 'ANSWER', 'NOTE', 'IMPACT',
                                                               'LINK', 'OWNER', 'STATE')),
    author_type           text        NOT NULL CHECK (char_length(author_type) BETWEEN 1 AND 32),
    author_id             text        NOT NULL CHECK (char_length(author_id) BETWEEN 1 AND 256),
    text                  text        CHECK (char_length(text) <= 4000),
    basis                 text        CHECK (basis IN ('OBSERVED', 'RULE_MATCH', 'INFERRED', 'HYPOTHESIS')),
    evidence              jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(evidence) = 'array'),
    confidence            text        CHECK (confidence IN ('LOW', 'MEDIUM', 'HIGH')),
    alternatives          text[]      NOT NULL DEFAULT '{}',
    question_id           uuid,
    unresolved            boolean     NOT NULL DEFAULT false,
    owner_id              uuid,
    owner_role            text        CHECK (owner_role IN ('OWNER', 'FOLLOW_UP')),
    impact_kind           text        CHECK (impact_kind IN ('OBSERVED', 'POTENTIAL')),
    ref_kind              text        CHECK (char_length(ref_kind) BETWEEN 1 AND 32),
    ref_id                text        CHECK (char_length(ref_id) BETWEEN 1 AND 256),
    to_state              text        CHECK (to_state IN ('OPEN', 'CONTAINED', 'CLOSED')),
    no_containment_needed boolean     NOT NULL DEFAULT false,
    disposition           text        CHECK (disposition IN ('TRUE_POSITIVE', 'BENIGN', 'FALSE_POSITIVE', 'INCONCLUSIVE')),
    case_impact           text        CHECK (case_impact IN ('CONFIRMED', 'EXPLICITLY_UNRESOLVED', 'NONE_FOUND')),
    reason                text        CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    supersedes            uuid,
    created_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, case_id, seq),
    UNIQUE (org_id, ledger_entry_id),
    FOREIGN KEY (org_id, case_id) REFERENCES pc.cases (org_id, id),
    FOREIGN KEY (org_id, ledger_entry_id) REFERENCES pc.ledger_entries (org_id, id),
    FOREIGN KEY (org_id, owner_id) REFERENCES pc.users (org_id, id),
    CHECK (kind <> 'FACT' OR (jsonb_array_length(evidence) BETWEEN 1 AND 32 AND basis IN ('OBSERVED', 'RULE_MATCH', 'INFERRED'))),
    CHECK (kind <> 'HYPOTHESIS' OR (confidence IS NOT NULL AND basis = 'HYPOTHESIS')),
    CHECK (kind <> 'ANSWER' OR question_id IS NOT NULL),
    CHECK (kind <> 'IMPACT' OR impact_kind IS NOT NULL),
    CHECK (kind <> 'LINK' OR (ref_kind IS NOT NULL AND ref_id IS NOT NULL)),
    CHECK (kind <> 'OWNER' OR (owner_role IS NOT NULL AND owner_id IS NOT NULL)),
    CHECK (kind <> 'STATE' OR to_state IS NOT NULL),
    CHECK (NOT no_containment_needed OR (to_state IN ('CONTAINED', 'CLOSED') AND reason IS NOT NULL)),
    CHECK ((kind IN ('FACT', 'HYPOTHESIS', 'QUESTION', 'ANSWER', 'NOTE', 'IMPACT')) = (text IS NOT NULL AND btrim(text) <> ''))
);
CREATE INDEX case_entries_kind ON pc.case_entries (org_id, case_id, kind, seq);
CREATE UNIQUE INDEX case_entries_superseded ON pc.case_entries (org_id, supersedes) WHERE supersedes IS NOT NULL;
CREATE INDEX case_entries_question ON pc.case_entries (org_id, question_id) WHERE question_id IS NOT NULL;
CREATE INDEX case_entries_ref ON pc.case_entries (org_id, ref_kind, ref_id) WHERE ref_kind IS NOT NULL;

-- A case is inserted OPEN, with nothing decided and the genesis head.
-- +goose StatementBegin
CREATE FUNCTION pc.case_insert() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF NEW.state IS DISTINCT FROM 'OPEN' OR NEW.disposition IS NOT NULL OR NEW.impact IS NOT NULL
       OR NEW.follow_up_owner_id IS NOT NULL OR NEW.head_seq IS DISTINCT FROM 0 THEN
        RAISE EXCEPTION 'a case is inserted OPEN with no entries' USING ERRCODE = 'check_violation';
    END IF;
    NEW.head_hash := sha256(convert_to('pantherclaw/case/v1/' || NEW.id::text, 'UTF8'));
    NEW.created_at := now();
    NEW.updated_at := now();
    NEW.operational_closed_at := NULL;
    NEW.closed_at := NULL;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER cases_insert BEFORE INSERT ON pc.cases
    FOR EACH ROW EXECUTE FUNCTION pc.case_insert();

-- Is entry e of case c superseded by a later entry?
-- +goose StatementBegin
CREATE FUNCTION pc.case_entry_superseded(p_org uuid, p_entry uuid) RETURNS boolean
LANGUAGE sql STABLE
SET search_path = pc, pg_temp
AS $$
    SELECT EXISTS (SELECT 1 FROM pc.case_entries s WHERE s.org_id = p_org AND s.supersedes = p_entry)
$$;
-- +goose StatementEnd

-- The case's open questions: standing QUESTION entries with no standing
-- ANSWER that resolves them (an ANSWER marked unresolved keeps it open).
-- +goose StatementBegin
CREATE FUNCTION pc.case_open_questions(p_org uuid, p_case uuid) RETURNS bigint
LANGUAGE sql STABLE
SET search_path = pc, pg_temp
AS $$
    SELECT count(*) FROM pc.case_entries q
    WHERE q.org_id = p_org AND q.case_id = p_case AND q.kind = 'QUESTION'
      AND NOT pc.case_entry_superseded(q.org_id, q.id)
      AND NOT EXISTS (
          SELECT 1 FROM pc.case_entries a
          WHERE a.org_id = q.org_id AND a.case_id = q.case_id AND a.kind = 'ANSWER' AND a.question_id = q.id
            AND NOT a.unresolved AND NOT pc.case_entry_superseded(a.org_id, a.id))
$$;
-- +goose StatementEnd

-- An entry is derived from its body, numbered and chained onto the case's
-- head, and checked against the case, the ledger and the evidence (HR-245).
-- +goose StatementBegin
CREATE FUNCTION pc.case_entry_insert() RETURNS trigger
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
CREATE TRIGGER case_entries_insert BEFORE INSERT ON pc.case_entries
    FOR EACH ROW EXECUTE FUNCTION pc.case_entry_insert();

-- Each entry advances the case's head; owner and state entries also set
-- what they name. The case update trigger checks the move.
-- +goose StatementBegin
CREATE FUNCTION pc.case_entry_apply() RETURNS trigger
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
CREATE TRIGGER case_entries_apply AFTER INSERT ON pc.case_entries
    FOR EACH ROW EXECUTE FUNCTION pc.case_entry_apply();

-- A case changes only by its newest entry, and only as that entry says;
-- the closure rules hold here (HR-246).
-- +goose StatementBegin
CREATE FUNCTION pc.case_transition() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    e       pc.case_entries%ROWTYPE;
    links   bigint;
    pending bigint;
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.title IS DISTINCT FROM OLD.title
       OR NEW.source IS DISTINCT FROM OLD.source OR NEW.opened_by_type IS DISTINCT FROM OLD.opened_by_type
       OR NEW.opened_by_id IS DISTINCT FROM OLD.opened_by_id OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
       OR NEW.incident_id IS DISTINCT FROM OLD.incident_id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a case keeps its identity and origin' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.head_seq IS DISTINCT FROM OLD.head_seq + 1 THEN
        RAISE EXCEPTION 'a case changes only by appending an entry' USING ERRCODE = 'check_violation';
    END IF;
    SELECT * INTO e FROM pc.case_entries
    WHERE org_id = NEW.org_id AND case_id = NEW.id AND seq = NEW.head_seq AND entry_hash = NEW.head_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'a case changes only by appending an entry' USING ERRCODE = 'check_violation';
    END IF;

    -- Only an owner entry moves the owners; only a state entry moves the
    -- state, the disposition and the impact.
    IF (e.kind <> 'OWNER' OR e.owner_role <> 'OWNER') AND NEW.owner_id IS DISTINCT FROM OLD.owner_id
       OR (e.kind = 'OWNER' AND e.owner_role = 'OWNER') AND NEW.owner_id IS DISTINCT FROM e.owner_id
       OR (e.kind <> 'OWNER' OR e.owner_role <> 'FOLLOW_UP') AND NEW.follow_up_owner_id IS DISTINCT FROM OLD.follow_up_owner_id
       OR (e.kind = 'OWNER' AND e.owner_role = 'FOLLOW_UP') AND NEW.follow_up_owner_id IS DISTINCT FROM e.owner_id
       OR e.kind <> 'STATE' AND (NEW.state IS DISTINCT FROM OLD.state OR NEW.disposition IS DISTINCT FROM OLD.disposition
                                 OR NEW.impact IS DISTINCT FROM OLD.impact)
       OR e.kind = 'STATE' AND (NEW.state IS DISTINCT FROM e.to_state OR NEW.disposition IS DISTINCT FROM e.disposition
                                OR NEW.impact IS DISTINCT FROM e.case_impact) THEN
        RAISE EXCEPTION 'the case update does not match its newest entry' USING ERRCODE = 'check_violation';
    END IF;

    NEW.updated_at := now();
    NEW.operational_closed_at := OLD.operational_closed_at;
    NEW.closed_at := OLD.closed_at;
    IF e.kind <> 'STATE' THEN
        -- A closed case keeps an owner for every question still open
        -- (F571): no entry may leave one without (HR-246).
        IF NEW.state = 'CLOSED' AND NEW.follow_up_owner_id IS NULL AND pc.case_open_questions(NEW.org_id, NEW.id) > 0 THEN
            RAISE EXCEPTION 'CASE_CLOSURE_RULES: open questions of a closed case need a follow-up owner'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;

    IF NOT ((OLD.state = 'OPEN' AND NEW.state IN ('CONTAINED', 'CLOSED'))
            OR (OLD.state = 'CONTAINED' AND NEW.state IN ('OPEN', 'CLOSED'))) THEN
        RAISE EXCEPTION 'a case cannot go from % to %', OLD.state, NEW.state USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state <> 'CLOSED' AND (e.disposition IS NOT NULL OR e.case_impact IS NOT NULL) THEN
        RAISE EXCEPTION 'only closing sets a disposition and an impact' USING ERRCODE = 'check_violation';
    END IF;

    -- Operational close, also on the way from OPEN straight to CLOSED
    -- (F251): confirmed containment or a reason none is needed.
    IF (NEW.state = 'CONTAINED' OR (NEW.state = 'CLOSED' AND OLD.state = 'OPEN')) AND NOT e.no_containment_needed THEN
        -- The case's actions (D43): standing LINK entries to response
        -- actions and the actions that name the case. A missing or
        -- unknown action is not confirmed.
        IF to_regclass('pc.response_actions') IS NULL THEN
            SELECT count(*), count(*) INTO links, pending FROM pc.case_entries l
            WHERE l.org_id = NEW.org_id AND l.case_id = NEW.id AND l.kind = 'LINK' AND l.ref_kind = 'response_action'
              AND NOT pc.case_entry_superseded(l.org_id, l.id);
        ELSE
            WITH acts AS (
                SELECT l.ref_id AS id FROM pc.case_entries l
                WHERE l.org_id = NEW.org_id AND l.case_id = NEW.id AND l.kind = 'LINK' AND l.ref_kind = 'response_action'
                  AND NOT pc.case_entry_superseded(l.org_id, l.id)
                UNION
                SELECT a.id::text FROM pc.response_actions a WHERE a.org_id = NEW.org_id AND a.case_id = NEW.id
            )
            SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (
                       SELECT 1 FROM pc.response_actions a
                       WHERE a.org_id = NEW.org_id AND a.id::text = acts.id AND a.status = 'CONFIRMED'))
            INTO links, pending FROM acts;
        END IF;
        IF links = 0 THEN
            RAISE EXCEPTION 'CASE_NOT_CONTAINED: no containment action is linked and no reason says none is needed'
                USING ERRCODE = 'check_violation';
        END IF;
        IF pending > 0 THEN
            RAISE EXCEPTION 'CASE_NOT_CONTAINED: % linked containment actions are not confirmed', pending
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;

    IF NEW.state = 'OPEN' THEN
        NEW.operational_closed_at := NULL;
    ELSIF NEW.state = 'CONTAINED' THEN
        NEW.operational_closed_at := now();
    ELSE
        -- Closure (F251): impact, disposition, a standing fact, and an owner
        -- for the questions that stay open (F571).
        IF NEW.disposition IS NULL OR NEW.impact IS NULL THEN
            RAISE EXCEPTION 'CASE_CLOSURE_RULES: closing needs an impact and a disposition' USING ERRCODE = 'check_violation';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pc.case_entries f
                       WHERE f.org_id = NEW.org_id AND f.case_id = NEW.id AND f.kind = 'FACT'
                         AND NOT pc.case_entry_superseded(f.org_id, f.id)) THEN
            RAISE EXCEPTION 'CASE_CLOSURE_RULES: closing needs at least one fact' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.follow_up_owner_id IS NULL AND pc.case_open_questions(NEW.org_id, NEW.id) > 0 THEN
            RAISE EXCEPTION 'CASE_CLOSURE_RULES: open questions need a follow-up owner' USING ERRCODE = 'check_violation';
        END IF;
        IF OLD.state = 'OPEN' THEN
            NEW.operational_closed_at := now();
        END IF;
        NEW.closed_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER cases_transition BEFORE UPDATE ON pc.cases
    FOR EACH ROW EXECUTE FUNCTION pc.case_transition();

-- Entries are never changed or removed, whoever asks (HR-245).
-- +goose StatementBegin
CREATE FUNCTION pc.case_entry_immutable() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'case entries are append-only' USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER case_entries_immutable BEFORE UPDATE OR DELETE ON pc.case_entries
    FOR EACH ROW EXECUTE FUNCTION pc.case_entry_immutable();
CREATE TRIGGER case_entries_no_truncate BEFORE TRUNCATE ON pc.case_entries
    FOR EACH STATEMENT EXECUTE FUNCTION pc.case_entry_immutable();
CREATE TRIGGER cases_no_delete BEFORE DELETE ON pc.cases
    FOR EACH ROW EXECUTE FUNCTION pc.case_entry_immutable();

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['cases', 'case_entries']
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

GRANT SELECT, INSERT ON pc.cases, pc.case_entries TO pc_app;
GRANT UPDATE (head_seq, head_hash, owner_id, follow_up_owner_id, state, disposition, impact, updated_at,
              operational_closed_at, closed_at) ON pc.cases TO pc_app;
GRANT SELECT ON pc.cases, pc.case_entries TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.case_entries;
DROP TABLE pc.cases;
DROP FUNCTION pc.case_entry_immutable();
DROP FUNCTION pc.case_transition();
DROP FUNCTION pc.case_entry_apply();
DROP FUNCTION pc.case_entry_insert();
DROP FUNCTION pc.case_open_questions(uuid, uuid);
DROP FUNCTION pc.case_entry_superseded(uuid, uuid);
DROP FUNCTION pc.case_insert();
