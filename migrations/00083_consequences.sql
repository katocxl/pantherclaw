-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Consequences of decisions (G0 M8 track P: P1; F405, HR-206). Numbered
-- after track P's 00082 (release controls), design decision 16.
--
-- decision_consequences keeps, for each evaluation, what the action's
-- consequence rules said: the consequence each rule predicted, could not
-- rule out (UNKNOWN, with why each fact could not be used) or ruled out,
-- its operation, target and environments, and the digest of the facts the
-- rule read. A rule that could not be evaluated is not a consequence: the
-- evaluation's checklist says why it was CANNOT_AUTHORIZE. Rows are
-- evidence, written in the evaluation's finalization next to its decision
-- receipt, and never changed or deleted. They hold no payload, so
-- retention keeps them with their receipt.
--
-- The rules themselves are read from the pinned package version the
-- pipeline decodes for the definition, not from consequence_rules (M8.md,
-- P1b).

-- +goose Up
CREATE TABLE pc.decision_consequences (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    transaction_id uuid        NOT NULL,
    evaluation     integer     NOT NULL CHECK (evaluation BETWEEN 1 AND 64),
    position       integer     NOT NULL CHECK (position BETWEEN 0 AND 255),
    rule_id        text        NOT NULL CHECK (rule_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    operation      text        NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 200),
    target_type    text        NOT NULL CHECK (char_length(target_type) BETWEEN 1 AND 200),
    target_id      text        NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 512),
    environments   text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(environments) <= 32),
    state          text        NOT NULL CHECK (state IN ('PREDICTED', 'UNKNOWN', 'NOT_TRIGGERED')),
    -- Why each fact an UNKNOWN consequence needed could not be used.
    unknown        jsonb       NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(unknown) = 'array' AND octet_length(unknown::text) <= 16384),
    facts_digest   text        NOT NULL CHECK (facts_digest ~ '^sha256:[0-9a-f]{64}$'),
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, transaction_id, evaluation, position),
    FOREIGN KEY (org_id, transaction_id, evaluation) REFERENCES pc.decision_receipts (org_id, transaction_id, evaluation),
    CHECK ((state = 'UNKNOWN') = (jsonb_array_length(unknown) > 0)),
    CHECK (state = 'PREDICTED' OR cardinality(environments) = 0)
);

ALTER TABLE pc.decision_consequences ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.decision_consequences FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.decision_consequences
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.decision_consequences TO pc_app;
GRANT SELECT ON pc.decision_consequences TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.decision_consequences;
