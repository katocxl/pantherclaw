-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- M17 continuous discovery (PN-001.3, D114, D115; HR-458, HR-459):
-- - missed_scans counts the complete scans in a row that did not see a scan
--   discovery; a scan that sees it resets it to 0. last_scan_run is the org
--   scan that last saw it.
-- - vanish_notified_at is set once, when missed_scans reaches 3: the people
--   are told; the agent's state and authority do not change (G3). It is
--   cleared when the discovery is seen again.
-- - scan_scope is a CI-mode scan's scope (a repository or host), and source
--   ci_scan is a complete CI-mode submit: its discoveries count misses
--   within their scope only.
-- +goose Up
ALTER TABLE pc.discoveries
    ADD COLUMN missed_scans integer NOT NULL DEFAULT 0 CHECK (missed_scans >= 0),
    ADD COLUMN last_scan_run uuid,
    ADD COLUMN scan_scope text CHECK (scan_scope IS NULL OR char_length(scan_scope) BETWEEN 1 AND 256),
    ADD COLUMN vanish_notified_at timestamptz,
    DROP CONSTRAINT discoveries_source,
    DROP CONSTRAINT discoveries_source_key,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan', 'ci_scan')) NOT VALID,
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan', 'ci_scan') AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL))
        NOT VALID,
    ADD CONSTRAINT discoveries_ci_scope CHECK ((source = 'ci_scan') = (scan_scope IS NOT NULL)) NOT VALID;
-- Discoveries are few (open ones are capped per source and org, HR-148), so
-- validating and indexing them holds the lock briefly.
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_source;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_source_key;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.discoveries VALIDATE CONSTRAINT discoveries_ci_scope;
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX discoveries_ci_scope_idx ON pc.discoveries (org_id, scan_scope) WHERE source = 'ci_scan';

GRANT UPDATE (missed_scans, last_scan_run, vanish_notified_at) ON pc.discoveries TO pc_app;

-- +goose Down
DELETE FROM pc.discoveries WHERE source = 'ci_scan';
REVOKE UPDATE (missed_scans, last_scan_run, vanish_notified_at) ON pc.discoveries FROM pc_app;
DROP INDEX pc.discoveries_ci_scope_idx;
ALTER TABLE pc.discoveries
    DROP CONSTRAINT discoveries_ci_scope,
    DROP CONSTRAINT discoveries_source_key,
    DROP CONSTRAINT discoveries_source,
    ADD CONSTRAINT discoveries_source CHECK (source IN ('gateway', 'scan', 'github_scan')),
    ADD CONSTRAINT discoveries_source_key CHECK (
        (source = 'gateway' AND key_jkt IS NOT NULL AND public_jwk IS NOT NULL AND scan_key IS NULL)
        OR (source IN ('scan', 'github_scan') AND scan_key IS NOT NULL AND key_jkt IS NULL AND public_jwk IS NULL)),
    DROP COLUMN vanish_notified_at,
    DROP COLUMN scan_scope,
    DROP COLUMN last_scan_run,
    DROP COLUMN missed_scans;
