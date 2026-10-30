-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Consequence chains (G0 M17 D109; F411, F412, HR-455). A predicted
-- consequence can itself have consequences: each row of
-- pc.decision_consequences now says how far down the chain it is (depth 1
-- is a consequence of the action itself), which earlier consequence of the
-- same evaluation it follows from (parent_position, none at depth 1), and
-- whether the rule came from a signed package or is one of the org's
-- reviewed customer rules (source, D106). Rows written before this
-- migration are depth-1 package consequences, which is what the defaults
-- say. A parent always comes before its children, so the check on
-- parent_position below is enough to keep a chain acyclic.

-- +goose Up
ALTER TABLE pc.decision_consequences
    ADD COLUMN depth           smallint NOT NULL DEFAULT 1,
    ADD COLUMN parent_position smallint NULL,
    ADD COLUMN source          text     NOT NULL DEFAULT 'package';
-- A customer rule's id starts with cx. (00207), and its consequence is
-- always a customer one; a package rule's below it is one too (D145).
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_rule_id_check;
ALTER TABLE pc.decision_consequences
    ADD CONSTRAINT decision_consequences_depth CHECK (depth BETWEEN 1 AND 4) NOT VALID,
    ADD CONSTRAINT decision_consequences_parent_position CHECK (parent_position BETWEEN 0 AND 254) NOT VALID,
    ADD CONSTRAINT decision_consequences_source_check CHECK (source IN ('package', 'customer')) NOT VALID,
    ADD CONSTRAINT decision_consequences_chain
        CHECK ((depth = 1) = (parent_position IS NULL) AND (parent_position IS NULL OR parent_position < position)) NOT VALID,
    ADD CONSTRAINT decision_consequences_rule_id_check
        CHECK (rule_id ~ '^[a-z][a-z0-9-]{0,63}$' OR rule_id ~ '^cx\.[a-z0-9][a-z0-9_.-]{0,63}$') NOT VALID,
    ADD CONSTRAINT decision_consequences_source
        CHECK (source = 'customer' OR rule_id NOT LIKE 'cx.%') NOT VALID;
-- Every row already there is a depth-1 package consequence with a package
-- rule id (the defaults above, and the old rule_id check): the scans below
-- find nothing to refuse, and validating blocks neither reads nor writes
-- (SHARE UPDATE EXCLUSIVE).
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.decision_consequences VALIDATE CONSTRAINT decision_consequences_depth;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.decision_consequences VALIDATE CONSTRAINT decision_consequences_parent_position;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.decision_consequences VALIDATE CONSTRAINT decision_consequences_source_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.decision_consequences VALIDATE CONSTRAINT decision_consequences_chain;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.decision_consequences VALIDATE CONSTRAINT decision_consequences_rule_id_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.decision_consequences VALIDATE CONSTRAINT decision_consequences_source;

COMMENT ON COLUMN pc.decision_consequences.source IS
    'The chain''s provenance (G0 M17 D145): customer when a customer rule gave the consequence or it is below one a customer rule gave, even from a package rule; such a consequence is never waived.';

GRANT SELECT ON pc.decision_consequences TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_source;
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_rule_id_check;
ALTER TABLE pc.decision_consequences
    ADD CONSTRAINT decision_consequences_rule_id_check CHECK (rule_id ~ '^[a-z][a-z0-9-]{0,63}$');
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_chain;
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_source_check;
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_parent_position;
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_depth;
ALTER TABLE pc.decision_consequences DROP COLUMN source;
ALTER TABLE pc.decision_consequences DROP COLUMN parent_position;
ALTER TABLE pc.decision_consequences DROP COLUMN depth;
