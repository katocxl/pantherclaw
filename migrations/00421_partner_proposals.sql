-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- MSSP partner rollout proposals (G0 M38 D1102; FQ38-1; ADR-0065;
-- HR-814, HR-815). A partner proposes a policy version or a reference pack
-- to a customer over a link with the PROPOSE scope: from a partner session,
-- or from the partner org to many linked customers at once (template_id
-- groups the rows of one such send). A proposal never changes anything by
-- itself. A customer person holding policy.author accepts it, which makes
-- a DRAFT policy version through the existing draft path (draft_ref); from
-- there the existing publish and rollout flow applies, and a change request
-- for a version whose draft_ref is an accepted proposal always needs two
-- distinct customer people (policy/app/change.go). The customer declines,
-- the partner withdraws; a proposal nobody decided expires after 30 days.
--
-- Like pc.partner_links, a proposal is visible to its two orgs only.

-- +goose Up

CREATE TABLE pc.partner_proposals (
    id           uuid        PRIMARY KEY,
    link_id      uuid        NOT NULL REFERENCES pc.partner_links (id),
    partner_org  uuid        NOT NULL REFERENCES pc.orgs (id),
    customer_org uuid        NOT NULL REFERENCES pc.orgs (id),
    kind         text        NOT NULL CHECK (kind IN ('POLICY_VERSION', 'PACK')),
    title        text        NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200 AND title !~ '[[:cntrl:]]'),
    -- A policy document (POLICY_VERSION) or {pack, environment, agents,
    -- cohort, parameters} (PACK), as JSON.
    body         bytea       NOT NULL CHECK (octet_length(body) BETWEEN 2 AND 262144),
    template_id  uuid,
    state        text        NOT NULL DEFAULT 'PROPOSED'
                             CHECK (state IN ('PROPOSED', 'ACCEPTED', 'DECLINED', 'WITHDRAWN', 'EXPIRED')),
    -- partner/<partner org>/<user>.
    proposed_by  text        NOT NULL CHECK (char_length(proposed_by) BETWEEN 1 AND 256),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    decided_by   text        CHECK (decided_by IS NULL OR char_length(decided_by) BETWEEN 1 AND 256),
    decided_at   timestamptz,
    decline_reason text      CHECK (decline_reason IS NULL OR char_length(decline_reason) <= 500
                                    AND decline_reason !~ '[[:cntrl:]]'),
    -- The DRAFT policy version an acceptance made.
    draft_ref    uuid,
    CHECK (partner_org <> customer_org),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days'),
    CHECK ((state = 'PROPOSED') = (decided_at IS NULL)),
    CHECK ((state = 'ACCEPTED') = (draft_ref IS NOT NULL))
);
CREATE INDEX partner_proposals_customer ON pc.partner_proposals (customer_org, created_at DESC, id DESC);
CREATE INDEX partner_proposals_partner ON pc.partner_proposals (partner_org, created_at DESC, id DESC);
CREATE INDEX partner_proposals_draft ON pc.partner_proposals (customer_org, draft_ref) WHERE draft_ref IS NOT NULL;

-- A proposal is inserted PROPOSED over an ACTIVE link of its two orgs with
-- the PROPOSE scope; it is decided once while PROPOSED and unexpired, and
-- nothing else ever changes (HR-814).
-- +goose StatementBegin
CREATE FUNCTION pc.partner_proposal_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
DECLARE
    l pc.partner_links;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT * INTO l FROM pc.partner_links WHERE id = NEW.link_id;
        IF l.id IS NULL OR l.state IS DISTINCT FROM 'ACTIVE' OR now() < l.starts_at OR now() >= l.ends_at
                OR l.partner_org IS DISTINCT FROM NEW.partner_org OR l.customer_org IS DISTINCT FROM NEW.customer_org
                OR NOT ('PROPOSE' = ANY (l.scopes)) THEN
            RAISE EXCEPTION 'a proposal needs an active link with the PROPOSE scope' USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.state IS DISTINCT FROM 'PROPOSED' OR NEW.decided_at IS NOT NULL OR NEW.draft_ref IS NOT NULL THEN
            RAISE EXCEPTION 'a proposal is inserted PROPOSED' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.expires_at := now() + interval '30 days';
        RETURN NEW;
    END IF;
    IF OLD.state <> 'PROPOSED' THEN
        RAISE EXCEPTION 'a decided proposal is final' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.link_id IS DISTINCT FROM OLD.link_id
            OR NEW.partner_org IS DISTINCT FROM OLD.partner_org OR NEW.customer_org IS DISTINCT FROM OLD.customer_org
            OR NEW.kind IS DISTINCT FROM OLD.kind OR NEW.title IS DISTINCT FROM OLD.title
            OR NEW.body IS DISTINCT FROM OLD.body OR NEW.template_id IS DISTINCT FROM OLD.template_id
            OR NEW.proposed_by IS DISTINCT FROM OLD.proposed_by OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'a proposal is never rewritten' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IN ('ACCEPTED', 'DECLINED', 'WITHDRAWN') AND now() >= OLD.expires_at THEN
        RAISE EXCEPTION 'an expired proposal cannot be decided' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state <> 'PROPOSED' THEN
        NEW.decided_at := now();
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER partner_proposals_guard BEFORE INSERT OR UPDATE ON pc.partner_proposals
    FOR EACH ROW EXECUTE FUNCTION pc.partner_proposal_guard();

ALTER TABLE pc.partner_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.partner_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY partner_proposal_parties ON pc.partner_proposals
    USING (partner_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)
           OR customer_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (partner_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid)
                OR customer_org = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.partner_proposals TO pc_app;
GRANT UPDATE (state, decided_by, decided_at, decline_reason, draft_ref) ON pc.partner_proposals TO pc_app;
GRANT SELECT ON pc.partner_proposals TO pc_audit_ro;

-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.partner_proposals TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.partner_proposals;
DROP FUNCTION pc.partner_proposal_guard();
