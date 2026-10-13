-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Evidence packs (G0 M7 track B, design decision 15; HR-196; F525–F532;
-- Team edition). A person holding evidence.export asks for a pack of a scope
-- (transactions, a run, an agent, a time range); a worker job builds it from
-- that person's permissions at that moment and stores the signed manifest
-- (a JWS of type pap-pack+jwt by the evidence_packs key) and the content (a
-- ZIP of canonical JSON, at most 64 MiB). The pack can be downloaded for 7
-- days after it is ready; then it expires and its content is removed.
--
-- A pack is an export, not evidence itself: its state changes (BUILDING to
-- READY, FAILED or EXPIRED) and an expired pack loses its content, so
-- pc_app updates exactly those columns and never deletes a row. Numbered
-- 00074 by the founder's decision of 2026-10-10 (after A11's 00071,
-- retention's 00072 and capture's 00073).

-- +goose Up
CREATE TABLE pc.evidence_packs (
    org_id          uuid        NOT NULL REFERENCES pc.orgs (id),
    id              uuid        NOT NULL,
    -- The person who asked for it (evidence.export is human only).
    created_by      uuid        NOT NULL,
    scope_kind      text        NOT NULL CHECK (scope_kind IN ('transactions', 'run', 'agent', 'time_range')),
    -- The scope's ids and time range, canonical JSON.
    scope           jsonb       NOT NULL CHECK (jsonb_typeof(scope) = 'object' AND octet_length(scope::text) <= 65536),
    -- What to include: receipts, versions, approvals, containment, captures.
    include         jsonb       NOT NULL CHECK (jsonb_typeof(include) = 'object' AND octet_length(include::text) <= 1024),
    state           text        NOT NULL DEFAULT 'BUILDING' CHECK (state IN ('BUILDING', 'READY', 'FAILED', 'EXPIRED')),
    error_code      text        CHECK (error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
    manifest        text        CHECK (manifest IS NULL OR octet_length(manifest) BETWEEN 16 AND 16777216),
    manifest_sha256 bytea       CHECK (manifest_sha256 IS NULL OR octet_length(manifest_sha256) = 32),
    content         bytea       CHECK (content IS NULL OR octet_length(content) BETWEEN 22 AND 67108864),
    content_sha256  bytea       CHECK (content_sha256 IS NULL OR octet_length(content_sha256) = 32),
    content_size    bigint      CHECK (content_size IS NULL OR content_size BETWEEN 22 AND 67108864),
    items           integer     CHECK (items IS NULL OR items BETWEEN 0 AND 20000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    ready_at        timestamptz,
    expires_at      timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    CHECK (state <> 'READY' OR (manifest IS NOT NULL AND content IS NOT NULL AND ready_at IS NOT NULL AND expires_at IS NOT NULL)),
    CHECK (state <> 'FAILED' OR error_code IS NOT NULL),
    CHECK (state <> 'EXPIRED' OR content IS NULL),
    CHECK (expires_at IS NULL OR expires_at = ready_at + interval '7 days')
);

CREATE INDEX evidence_packs_expiring ON pc.evidence_packs (org_id, expires_at) WHERE state = 'READY';

ALTER TABLE pc.evidence_packs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.evidence_packs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.evidence_packs
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- No DELETE; only the build's outcome and the expiry change a row.
GRANT SELECT, INSERT ON pc.evidence_packs TO pc_app;
GRANT UPDATE (state, error_code, manifest, manifest_sha256, content, content_sha256, content_size, items, ready_at, expires_at)
    ON pc.evidence_packs TO pc_app;
-- Auditors see packs and their manifests, never the content.
GRANT SELECT (org_id, id, created_by, scope_kind, scope, include, state, error_code, manifest, manifest_sha256, content_sha256,
              content_size, items, created_at, ready_at, expires_at)
    ON pc.evidence_packs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.evidence_packs;
