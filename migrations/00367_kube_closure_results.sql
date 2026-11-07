-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The probe results of a stored Kubernetes closure (G0 M32 D970c):
-- [{"name","role","expect","observed","detail"}], at most 64 KiB, as the
-- server verified them from the signed report. A sandbox report's closure
-- merges the newest unexpired PASSED control row's results of the same
-- cluster as its positive twins, the way the Docker sandbox merges its
-- control report. Rows recorded before this migration have none.

-- +goose Up
ALTER TABLE pc.kube_closures
    ADD COLUMN results jsonb CHECK (results IS NULL OR (jsonb_typeof(results) = 'array'
                                                        AND octet_length(results::text) <= 65536));
-- kube_closures is new in this milestone (00362) and holds one row per
-- signed pod report, so building the index locks it only briefly.
-- squawk-ignore require-concurrent-index-creation
CREATE INDEX kube_closures_control ON pc.kube_closures (org_id, cluster, evaluated_at DESC)
    WHERE kind = 'control' AND result = 'PASSED';

-- +goose Down
DROP INDEX pc.kube_closures_control;
ALTER TABLE pc.kube_closures DROP COLUMN results;
