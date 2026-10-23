-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Data requests (G0 M13 D34, F2, PN-012.5, ADR-0035; HR-390, HR-391,
-- T-176, T-177): the org's exports and its deletion requests.
--
-- An export is BUILDING until the job stored its ZIP parts (each at most
-- 64 MiB, all at most 2 GiB) in data_request_parts and signed its
-- manifest (READY), or FAILED with an error code; its parts are removed 7
-- days after it is ready (EXPIRED). At most one export of an org is
-- BUILDING.
--
-- A deletion request is PENDING until the end of its cancellation window
-- (7 days for a request by an org admin, none for a plan lapsed 90 days),
-- then HELD while an org-wide legal hold is active, then DELETING once the
-- org is DELETED; it is CANCELED inside its window by any org admin, or
-- FAILED. At most one deletion request of an org is open. The org's rows
-- here are removed with the org; what is kept afterwards is the deletion
-- record in the platform org (00177).

-- +goose Up
CREATE TABLE pc.data_requests (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    id                 uuid        NOT NULL,
    kind               text        NOT NULL CHECK (kind IN ('EXPORT', 'DELETION')),
    state              text        NOT NULL CHECK (state IN ('BUILDING', 'READY', 'FAILED', 'EXPIRED',
                                                             'PENDING', 'CANCELED', 'HELD', 'DELETING')),
    -- The person who asked; NULL for a lapse deletion.
    created_by         uuid,
    -- The hosted account of that person, when linked.
    created_by_account uuid,
    -- Deletion: why, and the end of its window (created_at for a lapse).
    reason             text        CHECK (reason IS NULL OR reason IN ('requested', 'lapse_90d')),
    window_end         timestamptz,
    -- Deletion of a lapsed plan: the lapse it was created for.
    lapsed_at          timestamptz,
    -- Deletion: the accounts linked to the org's admins when it was
    -- requested (a lapse: when it runs); they may fetch the deletion record.
    admin_accounts     uuid[]      NOT NULL DEFAULT '{}' CHECK (cardinality(admin_accounts) <= 10000),
    canceled_by        uuid,
    canceled_at        timestamptz,
    -- Export: when it became ready and when its parts go.
    ready_at           timestamptz,
    expires_at         timestamptz,
    parts              integer     NOT NULL DEFAULT 0 CHECK (parts BETWEEN 0 AND 64),
    total_size         bigint      NOT NULL DEFAULT 0 CHECK (total_size BETWEEN 0 AND 2147483648),
    manifest           text        CHECK (manifest IS NULL OR char_length(manifest) <= 1048576),
    error_code         text        CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CHECK (CASE kind
               WHEN 'EXPORT' THEN state IN ('BUILDING', 'READY', 'FAILED', 'EXPIRED') AND reason IS NULL
                   AND window_end IS NULL AND lapsed_at IS NULL AND canceled_by IS NULL AND canceled_at IS NULL
                   AND created_by IS NOT NULL
               ELSE state IN ('PENDING', 'CANCELED', 'HELD', 'DELETING', 'FAILED') AND reason IS NOT NULL
                   AND window_end IS NOT NULL AND ready_at IS NULL AND expires_at IS NULL AND parts = 0
                   AND manifest IS NULL
           END),
    CHECK ((reason = 'lapse_90d') = (lapsed_at IS NOT NULL)),
    CHECK (reason IS DISTINCT FROM 'requested' OR created_by IS NOT NULL),
    CHECK (state NOT IN ('READY', 'EXPIRED') OR (ready_at IS NOT NULL AND expires_at IS NOT NULL AND manifest IS NOT NULL)),
    CHECK (state IN ('READY', 'EXPIRED') OR ready_at IS NULL),
    CHECK ((state = 'CANCELED') = (canceled_at IS NOT NULL) AND (canceled_at IS NULL) = (canceled_by IS NULL)),
    CHECK ((state = 'FAILED') = (error_code IS NOT NULL))
);
CREATE INDEX data_requests_recent ON pc.data_requests (org_id, created_at DESC, id DESC);
-- At most one export building and one deletion open per org.
CREATE UNIQUE INDEX data_requests_one_export ON pc.data_requests (org_id)
    WHERE kind = 'EXPORT' AND state = 'BUILDING';
CREATE UNIQUE INDEX data_requests_one_deletion ON pc.data_requests (org_id)
    WHERE kind = 'DELETION' AND state IN ('PENDING', 'HELD', 'DELETING');

CREATE TABLE pc.data_request_parts (
    org_id     uuid        NOT NULL REFERENCES pc.orgs (id),
    request_id uuid        NOT NULL,
    number     integer     NOT NULL CHECK (number BETWEEN 1 AND 64),
    content    bytea       NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 67108864),
    sha256     bytea       NOT NULL CHECK (octet_length(sha256) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, request_id, number),
    FOREIGN KEY (org_id, request_id) REFERENCES pc.data_requests (org_id, id)
);
-- Parts are stored as they are written; compressing ZIP content again is
-- wasted work.
ALTER TABLE pc.data_request_parts ALTER COLUMN content SET STORAGE EXTERNAL;

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['data_requests', 'data_request_parts']
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

GRANT SELECT, INSERT ON pc.data_requests TO pc_app;
GRANT UPDATE (state, admin_accounts, canceled_by, canceled_at, ready_at, expires_at, parts, total_size, manifest, error_code,
              updated_at)
    ON pc.data_requests TO pc_app;
-- Expired parts are removed by the server; nothing else deletes them.
GRANT SELECT, INSERT, DELETE ON pc.data_request_parts TO pc_app;
GRANT SELECT ON pc.data_requests TO pc_audit_ro;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_backup') THEN
        GRANT SELECT ON pc.data_requests, pc.data_request_parts TO pc_backup;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.data_request_parts;
DROP TABLE pc.data_requests;
