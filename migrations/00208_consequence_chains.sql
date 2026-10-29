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
    ADD COLUMN depth           smallint NOT NULL DEFAULT 1 CHECK (depth BETWEEN 1 AND 4),
    ADD COLUMN parent_position smallint NULL CHECK (parent_position BETWEEN 0 AND 254),
    ADD COLUMN source          text     NOT NULL DEFAULT 'package' CHECK (source IN ('package', 'customer'));
ALTER TABLE pc.decision_consequences
    ADD CONSTRAINT decision_consequences_chain
    CHECK ((depth = 1) = (parent_position IS NULL) AND (parent_position IS NULL OR parent_position < position));
-- A customer rule's id starts with cx. (00207), and only a customer rule's
-- does.
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_rule_id_check;
ALTER TABLE pc.decision_consequences
    ADD CONSTRAINT decision_consequences_rule_id_check
    CHECK (rule_id ~ '^[a-z][a-z0-9-]{0,63}$' OR rule_id ~ '^cx\.[a-z0-9][a-z0-9_.-]{0,63}$'),
    ADD CONSTRAINT decision_consequences_source
    CHECK ((source = 'customer') = (rule_id LIKE 'cx.%'));

GRANT SELECT ON pc.decision_consequences TO pc_audit_ro;

-- +goose Down
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_source;
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_rule_id_check;
ALTER TABLE pc.decision_consequences
    ADD CONSTRAINT decision_consequences_rule_id_check CHECK (rule_id ~ '^[a-z][a-z0-9-]{0,63}$');
ALTER TABLE pc.decision_consequences DROP CONSTRAINT decision_consequences_chain;
ALTER TABLE pc.decision_consequences DROP COLUMN source;
ALTER TABLE pc.decision_consequences DROP COLUMN parent_position;
ALTER TABLE pc.decision_consequences DROP COLUMN depth;
