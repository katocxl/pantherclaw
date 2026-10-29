-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M16 evidence-backed suggestions (G0 M16 D90–D92; F185; HR-442..445):
-- an unused-authority posture finding becomes a suggestion that carries its
-- evidence: the 30-day window, the operations observed in it, the routes
-- that were not ENFORCED (coverage limits), the proposed restriction, the
-- expected effect counted from recorded transactions only, and how
-- uncertain all of that is. A suggestion never changes policy: a person
-- dismisses it, or turns it into a policy DRAFT that goes through the M11.1
-- publication gate (HR-442).
--
-- * At most one OPEN suggestion per posture finding.
-- * Uncertainty is never LOW while a coverage limit is PARTIAL or UNKNOWN,
--   and a MEDIUM or HIGH one names its reasons (HR-443).
-- * The expected effect's counts are present only when recorded data was
--   collected; what was not collected is listed, never counted as zero
--   (HR-445).
-- * OPEN refreshes its evidence; DRAFTED, DISMISSED and STALE are frozen.
--   OPEN -> DRAFTED (with the draft's id), OPEN -> DISMISSED (with who and
--   why), OPEN or DRAFTED -> STALE (the finding was resolved).
-- * A dismissal lasts until the finding is next remediated: the
--   remediation is recorded once on the DISMISSED row
--   (finding_remediated_at), and a later reopening gets a new OPEN one.
-- +goose Up
CREATE TABLE pc.policy_suggestions (
    org_id                  uuid        NOT NULL REFERENCES pc.orgs (id),
    id                      uuid        NOT NULL,
    kind                    text        NOT NULL CHECK (kind IN ('UNUSED_AUTHORITY')),
    posture_finding_id      uuid        NOT NULL,
    grant_id                uuid        NOT NULL,
    agent_id                uuid        NOT NULL,
    -- The agent's owners when the suggestion was last refreshed.
    owners                  uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(owners) <= 8),
    window_from             timestamptz NOT NULL,
    window_to               timestamptz NOT NULL,
    -- operation -> recorded transactions of the grant in the window (at
    -- most 100 operations).
    observed                jsonb       NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(observed) = 'object'
                                                                     AND jsonb_array_length(jsonb_path_query_array(observed, '$.keyvalue()')) <= 100
                                                                     AND octet_length(observed::text) <= 16384),
    -- The routes that were not ENFORCED for the whole window, worst first:
    -- [{agent, connection, operation, state}] (at most 100).
    coverage_limits         jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(coverage_limits) = 'array'
                                                                     AND jsonb_array_length(coverage_limits) <= 100
                                                                     AND octet_length(coverage_limits::text) <= 32768),
    -- The restriction draft's rules (securitysteps.RestrictionDraft).
    proposed                jsonb       NOT NULL CHECK (jsonb_typeof(proposed) = 'array'
                                                        AND jsonb_array_length(proposed) BETWEEN 1 AND 8
                                                        AND octet_length(proposed::text) <= 32768),
    -- {collected, matching_actions, newly_denied, newly_held, not_collected}.
    expected_effect         jsonb       NOT NULL CHECK (jsonb_typeof(expected_effect) = 'object'
                                                        AND octet_length(expected_effect::text) <= 16384),
    uncertainty             text        NOT NULL CHECK (uncertainty IN ('LOW', 'MEDIUM', 'HIGH')),
    uncertainty_reasons     text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(uncertainty_reasons) <= 32),
    state                   text        NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN', 'DRAFTED', 'DISMISSED', 'STALE')),
    draft_policy_version_id uuid,
    dismissed_by            text        CHECK (char_length(dismissed_by) BETWEEN 1 AND 128),
    dismiss_reason          text        CHECK (char_length(btrim(dismiss_reason)) BETWEEN 10 AND 1000),
    -- When the finding was remediated after the dismissal (set once).
    finding_remediated_at   timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, posture_finding_id) REFERENCES pc.posture_findings (org_id, id),
    FOREIGN KEY (org_id, grant_id) REFERENCES pc.grants (org_id, id),
    FOREIGN KEY (org_id, agent_id) REFERENCES pc.agents (org_id, id),
    FOREIGN KEY (org_id, draft_policy_version_id) REFERENCES pc.policy_versions (org_id, id),
    CHECK (window_to > window_from),
    -- HR-443: never LOW with a PARTIAL or UNKNOWN route; MEDIUM and HIGH say why.
    CHECK (uncertainty <> 'LOW' OR NOT jsonb_path_exists(coverage_limits,
        '$[*] ? (@.state == "PARTIAL" || @.state == "UNKNOWN")')),
    CHECK (uncertainty = 'LOW' OR cardinality(uncertainty_reasons) >= 1),
    CHECK (uncertainty <> 'MEDIUM' OR NOT jsonb_path_exists(coverage_limits, '$[*] ? (@.state == "UNKNOWN")')),
    -- HR-445: counts only from collected data; uncollected data is listed.
    CHECK (jsonb_typeof(expected_effect -> 'collected') = 'boolean'),
    CHECK ((expected_effect -> 'collected') = 'true'::jsonb
        OR NOT (expected_effect ?| ARRAY['matching_actions', 'newly_denied', 'newly_held'])),
    CHECK ((expected_effect -> 'collected') = 'true'::jsonb
        OR jsonb_array_length(COALESCE(expected_effect -> 'not_collected', '[]'::jsonb)) >= 1),
    CHECK ((state = 'DRAFTED') = (draft_policy_version_id IS NOT NULL) OR state = 'STALE'),
    CHECK ((state = 'DISMISSED') = (dismissed_by IS NOT NULL AND dismiss_reason IS NOT NULL)),
    CHECK (finding_remediated_at IS NULL OR state = 'DISMISSED')
);
CREATE UNIQUE INDEX policy_suggestions_open ON pc.policy_suggestions (org_id, posture_finding_id) WHERE state = 'OPEN';
CREATE INDEX policy_suggestions_finding ON pc.policy_suggestions (org_id, posture_finding_id, id DESC);
CREATE INDEX policy_suggestions_list ON pc.policy_suggestions (org_id, state, id DESC);

ALTER TABLE pc.policy_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.policy_suggestions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.policy_suggestions
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- A suggestion starts OPEN, undrafted and undismissed, its times the
-- database's; it keeps its identity, refreshes its evidence only while
-- OPEN, and moves only along its lifecycle.
-- +goose StatementBegin
CREATE FUNCTION pc.policy_suggestion_insert() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.state <> 'OPEN' OR NEW.draft_policy_version_id IS NOT NULL OR NEW.dismissed_by IS NOT NULL
        OR NEW.dismiss_reason IS NOT NULL OR NEW.finding_remediated_at IS NOT NULL THEN
        RAISE EXCEPTION 'a policy suggestion starts open' USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := now();
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_suggestions_insert BEFORE INSERT ON pc.policy_suggestions
    FOR EACH ROW EXECUTE FUNCTION pc.policy_suggestion_insert();

-- +goose StatementBegin
CREATE FUNCTION pc.policy_suggestion_update() RETURNS trigger
    LANGUAGE plpgsql SET search_path = pc, pg_temp AS $$
BEGIN
    IF NEW.kind <> OLD.kind OR NEW.posture_finding_id <> OLD.posture_finding_id OR NEW.grant_id <> OLD.grant_id
        OR NEW.agent_id <> OLD.agent_id OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'policy suggestion % keeps its identity', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state <> 'OPEN' AND (NEW.owners IS DISTINCT FROM OLD.owners OR NEW.window_from <> OLD.window_from
        OR NEW.window_to <> OLD.window_to OR NEW.observed <> OLD.observed OR NEW.coverage_limits <> OLD.coverage_limits
        OR NEW.proposed <> OLD.proposed OR NEW.expected_effect <> OLD.expected_effect
        OR NEW.uncertainty <> OLD.uncertainty OR NEW.uncertainty_reasons IS DISTINCT FROM OLD.uncertainty_reasons) THEN
        RAISE EXCEPTION 'policy suggestion % refreshes its evidence only while open', OLD.id USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state THEN
        IF NOT ((OLD.state = 'OPEN' AND NEW.state IN ('DRAFTED', 'DISMISSED', 'STALE'))
            OR (OLD.state = 'DRAFTED' AND NEW.state = 'STALE')) THEN
            RAISE EXCEPTION 'policy suggestion % cannot move from % to %', OLD.id, OLD.state, NEW.state
                USING ERRCODE = 'check_violation';
        END IF;
    END IF;
    IF (NEW.draft_policy_version_id IS DISTINCT FROM OLD.draft_policy_version_id AND NOT (OLD.state = 'OPEN' AND NEW.state = 'DRAFTED'))
        OR ((NEW.dismissed_by IS DISTINCT FROM OLD.dismissed_by OR NEW.dismiss_reason IS DISTINCT FROM OLD.dismiss_reason)
            AND NOT (OLD.state = 'OPEN' AND NEW.state = 'DISMISSED')) THEN
        RAISE EXCEPTION 'policy suggestion % records its draft or dismissal only with that move', OLD.id
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.finding_remediated_at IS DISTINCT FROM OLD.finding_remediated_at THEN
        IF OLD.finding_remediated_at IS NOT NULL OR OLD.state <> 'DISMISSED' OR NEW.state <> 'DISMISSED' THEN
            RAISE EXCEPTION 'policy suggestion % records the remediation once, while dismissed', OLD.id
                USING ERRCODE = 'check_violation';
        END IF;
        NEW.finding_remediated_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER policy_suggestions_update BEFORE UPDATE ON pc.policy_suggestions
    FOR EACH ROW EXECUTE FUNCTION pc.policy_suggestion_update();

GRANT SELECT, INSERT ON pc.policy_suggestions TO pc_app;
GRANT UPDATE (owners, window_from, window_to, observed, coverage_limits, proposed, expected_effect, uncertainty,
    uncertainty_reasons, state, draft_policy_version_id, dismissed_by, dismiss_reason, finding_remediated_at, updated_at)
    ON pc.policy_suggestions TO pc_app;
GRANT SELECT ON pc.policy_suggestions TO pc_audit_ro;

-- The tenant write freeze of an org being deleted (00181, HR-391).
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.policy_suggestions
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
-- The login role is optional until db bootstrap --deleter-password-file.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.policy_suggestions TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.policy_suggestions;
DROP FUNCTION pc.policy_suggestion_update();
DROP FUNCTION pc.policy_suggestion_insert();
