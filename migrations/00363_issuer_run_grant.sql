-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The run grant of a Kubernetes trusted-issuer entry (G0 M32 D973): the
-- grant a pod's run is started under (KubernetesService.StartPodRun). It is
-- part of the entry's revision, so it changes only through a new revision
-- and that revision's approval, never by a direct write; NULL: the entry
-- starts no runs. The grant must be the same org's.

-- +goose Up
ALTER TABLE pc.trusted_issuers ADD COLUMN run_grant_id uuid;
-- The new column is NULL in every row and trusted_issuers is a small
-- table, so the foreign key holds at once and its lock is short.
-- squawk-ignore adding-foreign-key-constraint
ALTER TABLE pc.trusted_issuers
    ADD CONSTRAINT trusted_issuers_run_grant_fkey FOREIGN KEY (org_id, run_grant_id) REFERENCES pc.grants (org_id, id);

-- +goose Down
ALTER TABLE pc.trusted_issuers DROP CONSTRAINT trusted_issuers_run_grant_fkey;
ALTER TABLE pc.trusted_issuers DROP COLUMN run_grant_id;
