-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- F352 discovery inventory (G0 M15 D21): what a gateway found an upstream
-- MCP server listing behind one of its connections, one row per (kind,
-- name, digest). A NEW item is inert (HR-414) and has an open TOOL_REVIEW
-- entry whose subject is the row; the entry closes only by coverage
-- (COVERED, APPROVED), a person's dismissal (DISMISSED, REJECTED with a
-- reason) or disappearance from a complete listing (VANISHED, EXPIRED)
-- (HR-417). The description is the upstream server's UNTRUSTED text, kept
-- with its injection scan and never served (HR-415).
-- +goose Up
CREATE TABLE pc.connection_inventory (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    connection_id    uuid        NOT NULL,
    kind             text        NOT NULL CHECK (kind IN ('TOOL', 'RESOURCE', 'RESOURCE_TEMPLATE')),
    -- The tool name, resource URI or URI template.
    name             text        NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 2048),
    -- UNTRUSTED: a resource's or template's listed name.
    display_name     text        NOT NULL DEFAULT '' CHECK (octet_length(display_name) <= 128),
    mime_type        text        NOT NULL DEFAULT '' CHECK (octet_length(mime_type) <= 128),
    digest           text        NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$'),
    -- UNTRUSTED: the upstream description, at most 8 KiB as the gateway cut it.
    description      text        NOT NULL DEFAULT '' CHECK (octet_length(description) <= 8192),
    description_scan text        NOT NULL CHECK (description_scan IN ('clean', 'flagged', 'partial', 'not_scanned')),
    state            text        NOT NULL DEFAULT 'NEW' CHECK (state IN ('NEW', 'COVERED', 'DISMISSED', 'VANISHED')),
    review_entry_id  uuid,
    dismissed_by     text        CHECK (char_length(dismissed_by) BETWEEN 1 AND 100),
    -- UNTRUSTED: the person's reason.
    dismiss_reason   text        CHECK (char_length(dismiss_reason) BETWEEN 1 AND 500),
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, connection_id, kind, name, digest),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id),
    FOREIGN KEY (org_id, review_entry_id) REFERENCES pc.waitlist_entries (org_id, id),
    CHECK ((state = 'DISMISSED') = (dismissed_by IS NOT NULL)),
    CHECK ((state = 'DISMISSED') = (dismiss_reason IS NOT NULL))
);
CREATE INDEX connection_inventory_connection ON pc.connection_inventory (org_id, connection_id, id);
CREATE INDEX connection_inventory_new ON pc.connection_inventory (org_id, connection_id) WHERE state = 'NEW';

ALTER TABLE pc.connection_inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.connection_inventory FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.connection_inventory
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.connection_inventory TO pc_app;
GRANT UPDATE (display_name, mime_type, description, description_scan, state, review_entry_id, dismissed_by, dismiss_reason,
    last_seen, updated_at) ON pc.connection_inventory TO pc_app;
GRANT SELECT ON pc.connection_inventory TO pc_audit_ro;

-- An inventory item's TOOL_REVIEW entry has the item as its subject.
ALTER TABLE pc.waitlist_entries
    DROP CONSTRAINT waitlist_entries_subject_type_check,
    DROP CONSTRAINT waitlist_entries_kind_subject,
    ADD CONSTRAINT waitlist_entries_subject_type_check CHECK (subject_type IN ('agent', 'instance', 'approval_request',
                                                                               'grant', 'package_version', 'transaction',
                                                                               'connection_inventory')) NOT VALID,
    ADD CONSTRAINT waitlist_entries_kind_subject CHECK (CASE kind
        WHEN 'ADMISSION' THEN subject_type IN ('agent', 'instance') AND agent_id IS NOT NULL
        WHEN 'ACCESS_REQUEST' THEN subject_type = 'grant' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND requested_by IS NOT NULL
        WHEN 'ACTION_HOLD' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id IS NOT NULL
        WHEN 'TOOL_REVIEW' THEN subject_type IN ('package_version', 'connection_inventory') AND agent_id IS NULL AND run_id IS NULL
        WHEN 'RESTORATION' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND requested_by IS NOT NULL
        WHEN 'RECONCILIATION' THEN subject_type = 'transaction' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id = subject_id
        WHEN 'AUTOMATION_GATE' THEN subject_type = 'approval_request' AND requested_by IS NULL
            AND requested_by_automation IS NOT NULL AND run_id IS NULL AND transaction_id IS NULL
        ELSE false
    END AND (kind = 'AUTOMATION_GATE') = (requested_by_automation IS NOT NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_subject_type_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.waitlist_entries VALIDATE CONSTRAINT waitlist_entries_kind_subject;

-- +goose Down
DELETE FROM pc.waitlist_routes WHERE entry_id IN (SELECT id FROM pc.waitlist_entries WHERE subject_type = 'connection_inventory');
DROP TABLE pc.connection_inventory;
DELETE FROM pc.waitlist_entries WHERE subject_type = 'connection_inventory';
ALTER TABLE pc.waitlist_entries
    DROP CONSTRAINT waitlist_entries_kind_subject,
    DROP CONSTRAINT waitlist_entries_subject_type_check,
    ADD CONSTRAINT waitlist_entries_subject_type_check CHECK (subject_type IN ('agent', 'instance', 'approval_request',
                                                                               'grant', 'package_version', 'transaction')),
    ADD CONSTRAINT waitlist_entries_kind_subject CHECK (CASE kind
        WHEN 'ADMISSION' THEN subject_type IN ('agent', 'instance') AND agent_id IS NOT NULL
        WHEN 'ACCESS_REQUEST' THEN subject_type = 'grant' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND requested_by IS NOT NULL
        WHEN 'ACTION_HOLD' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id IS NOT NULL
        WHEN 'TOOL_REVIEW' THEN subject_type = 'package_version' AND agent_id IS NULL AND run_id IS NULL
        WHEN 'RESTORATION' THEN subject_type = 'approval_request' AND agent_id IS NOT NULL AND requested_by IS NOT NULL
        WHEN 'RECONCILIATION' THEN subject_type = 'transaction' AND agent_id IS NOT NULL AND run_id IS NOT NULL
            AND transaction_id = subject_id
        WHEN 'AUTOMATION_GATE' THEN subject_type = 'approval_request' AND requested_by IS NULL
            AND requested_by_automation IS NOT NULL AND run_id IS NULL AND transaction_id IS NULL
        ELSE false
    END AND (kind = 'AUTOMATION_GATE') = (requested_by_automation IS NOT NULL));
