-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- A request whose action hash differs from the stored one for the same
-- (run, action) closes an OPEN transaction with DENY ACTION_TAMPERED
-- (HR-006). Only the decision changes: the mode, grant and hashes of the
-- evaluation before it stay. Conditional on the evaluation it saw (HR-004).

-- name: CloseTampered :execresult
UPDATE pc.transactions
SET decision = 'DENY', reason_code = 'ACTION_TAMPERED', state = 'FINAL', evaluations = evaluations + 1
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'OPEN' AND evaluations = sqlc.arg(prev_evaluations);
