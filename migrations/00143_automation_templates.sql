-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Governed automations, templates (G0 M11 part 2 D31, D32; HR-284..286,
-- T-126).
--
-- An automation's intake and review steps never act on what they find:
-- they record proposals (F692, F599, HR-286). A proposal names the
-- execution that made it, what it is about (an agent, or the policy draft a
-- restriction was written into) and a bounded body; a person accepts or
-- declines it, which only records the decision. Issuing a grant, claiming
-- an agent or publishing a policy stays on its own human paths. PROPOSED is
-- the only state that changes, once, to ACCEPTED, DECLINED or SUPERSEDED;
-- the body never changes.
--
-- Contain steps (D61) record the automation as the response action's actor
-- with source PLAYBOOK; pc.response_actions already allows both. A digest
-- step's evidence pack (D85) is created by the automation's execution
-- identity within the agents its version declared, so pc.evidence_packs
-- takes an automation creator besides a person.

-- +goose Up
CREATE TABLE pc.automation_proposals (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    execution_id  uuid        NOT NULL,
    -- The step that made it, for idempotency (one proposal per execution,
    -- step and subject).
    step_id       text        NOT NULL CHECK (step_id ~ '^[a-z][a-z0-9_-]{0,62}$'),
    kind          text        NOT NULL CHECK (kind IN ('OWNER', 'BASELINE', 'TESTS', 'RESTRICTION')),
    subject_type  text        NOT NULL CHECK (subject_type IN ('agent', 'policy_version')),
    subject_id    uuid        NOT NULL,
    body          jsonb       NOT NULL CHECK (jsonb_typeof(body) = 'object' AND octet_length(body::text) <= 16384),
    state         text        NOT NULL DEFAULT 'PROPOSED'
                              CHECK (state IN ('PROPOSED', 'ACCEPTED', 'DECLINED', 'SUPERSEDED')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_by    uuid,
    decided_at    timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, execution_id, step_id, subject_id),
    FOREIGN KEY (org_id, execution_id) REFERENCES pc.automation_executions (org_id, id),
    FOREIGN KEY (org_id, decided_by) REFERENCES pc.users (org_id, id),
    -- A restriction is about a policy draft; the others about an agent.
    CONSTRAINT automation_proposals_subject CHECK ((kind = 'RESTRICTION') = (subject_type = 'policy_version')),
    -- A person decides ACCEPTED and DECLINED; SUPERSEDED is the server's.
    CONSTRAINT automation_proposals_decided CHECK (
        (state = 'PROPOSED' AND decided_by IS NULL AND decided_at IS NULL)
        OR (state IN ('ACCEPTED', 'DECLINED') AND decided_by IS NOT NULL AND decided_at IS NOT NULL)
        OR (state = 'SUPERSEDED' AND decided_by IS NULL AND decided_at IS NOT NULL))
);

CREATE INDEX automation_proposals_open ON pc.automation_proposals (org_id, subject_type, subject_id, created_at)
    WHERE state = 'PROPOSED';
CREATE INDEX automation_proposals_execution ON pc.automation_proposals (org_id, execution_id);

-- +goose StatementBegin
CREATE FUNCTION pc.automation_proposal_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'PROPOSED' THEN
            RAISE EXCEPTION 'automation_proposals: a proposal starts PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state <> 'PROPOSED' THEN
        RAISE EXCEPTION 'automation_proposals: a decided proposal is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.org_id <> OLD.org_id OR NEW.id <> OLD.id OR NEW.execution_id <> OLD.execution_id
        OR NEW.step_id <> OLD.step_id OR NEW.kind <> OLD.kind OR NEW.subject_type <> OLD.subject_type
        OR NEW.subject_id <> OLD.subject_id OR NEW.body <> OLD.body OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'automation_proposals: only the decision changes' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER automation_proposals_guard BEFORE INSERT OR UPDATE ON pc.automation_proposals
    FOR EACH ROW EXECUTE FUNCTION pc.automation_proposal_guard();

ALTER TABLE pc.automation_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.automation_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.automation_proposals
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.automation_proposals TO pc_app;
GRANT UPDATE (state, decided_by, decided_at) ON pc.automation_proposals TO pc_app;
GRANT SELECT ON pc.automation_proposals TO pc_audit_ro;

-- A digest step's evidence pack (D85) is created by the automation's own
-- execution identity, never borrowed from a person: created_by is then
-- that service account, automation_id names the automation, and
-- automation_agents the agents its version declared (NULL: all of the
-- org's). Every other pack is still a person's.
ALTER TABLE pc.evidence_packs
    ADD COLUMN automation_id     uuid,
    ADD COLUMN automation_agents uuid[] CHECK (automation_agents IS NULL OR (cardinality(automation_agents) BETWEEN 1 AND 50
                                               AND array_position(automation_agents, NULL) IS NULL)),
    ADD CONSTRAINT evidence_packs_automation_fk FOREIGN KEY (org_id, automation_id) REFERENCES pc.automations (org_id, id),
    ADD CONSTRAINT evidence_packs_automation_agents CHECK (automation_agents IS NULL OR automation_id IS NOT NULL),
    DROP CONSTRAINT evidence_packs_org_id_created_by_fkey;

-- +goose StatementBegin
CREATE FUNCTION pc.evidence_pack_creator_guard() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.automation_id IS NULL THEN
        IF NOT EXISTS (SELECT 1 FROM pc.users WHERE org_id = NEW.org_id AND id = NEW.created_by) THEN
            RAISE EXCEPTION 'evidence_packs: created_by must be a person of the org' USING ERRCODE = 'foreign_key_violation';
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM pc.service_accounts
                      WHERE org_id = NEW.org_id AND id = NEW.created_by AND automation_id = NEW.automation_id) THEN
        RAISE EXCEPTION 'evidence_packs: an automation''s pack is created by its own execution identity'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd

CREATE TRIGGER evidence_packs_creator BEFORE INSERT ON pc.evidence_packs
    FOR EACH ROW EXECUTE FUNCTION pc.evidence_pack_creator_guard();

GRANT SELECT (automation_id, automation_agents) ON pc.evidence_packs TO pc_audit_ro;

-- +goose Down
DELETE FROM pc.evidence_packs WHERE automation_id IS NOT NULL;
DROP TRIGGER evidence_packs_creator ON pc.evidence_packs;
DROP FUNCTION pc.evidence_pack_creator_guard();
ALTER TABLE pc.evidence_packs
    DROP COLUMN automation_agents,
    DROP COLUMN automation_id,
    ADD CONSTRAINT evidence_packs_org_id_created_by_fkey FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id);
DROP TABLE pc.automation_proposals;
DROP FUNCTION pc.automation_proposal_guard();
