-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Approvals at the gateway (G0 M6 slice 23): the assertions a permit
-- carries (HR-038), the keys a customer pins to verify them, and restoring
-- an approval whose permit was never used (HR-011).

-- ApprovalAssertions are the WebAuthn assertions of the responses that
-- count toward a request, with the credential id the authenticator signed
-- with (HR-038). A batch approval's assertion signed the batch hash.
-- name: ApprovalAssertions :many
SELECT x.requirement::integer AS requirement, c.credential_id AS webauthn_id, x.authenticator_data, x.client_data_json,
       x.signature, x.batch_id
FROM pc.approval_responses x
JOIN pc.webauthn_credentials c ON c.org_id = x.org_id AND c.id = x.credential_id
WHERE x.org_id = sqlc.arg(org_id) AND x.request_id = sqlc.arg(request_id) AND x.kind IN ('APPROVE', 'STEP_UP')
  AND x.voided_at IS NULL
ORDER BY x.created_at, x.id;

-- BatchBindings are the bindings of a batch's requests, whose batch hash
-- its one assertion signed (PAP-1 §8).
-- name: BatchBindings :many
SELECT r.binding FROM pc.approval_batches b
JOIN pc.approval_requests r ON r.org_id = b.org_id AND r.id = ANY (b.request_ids)
WHERE b.org_id = sqlc.arg(org_id) AND b.id = sqlc.arg(id)
ORDER BY r.binding;

-- ApproverKeys are the active security keys of the org's enabled people,
-- for the approver keys file a customer-hosted gateway pins (HR-038).
-- name: ApproverKeys :many
SELECT c.id, c.user_id, c.credential_id, c.public_key, c.alg, c.name, c.created_at, u.email, u.display_name
FROM pc.webauthn_credentials c
JOIN pc.users u ON u.org_id = c.org_id AND u.id = c.user_id
WHERE c.org_id = sqlc.arg(org_id) AND c.state = 'ACTIVE' AND u.state = 'ACTIVE'
  AND c.id > coalesce(sqlc.arg(after_id)::uuid, '00000000-0000-0000-0000-000000000000')
ORDER BY c.id
LIMIT sqlc.arg(max_rows);

-- RestorableApproval is the approval a released permit consumed, when it
-- may return to APPROVED (HR-011): the permit never reached DISPATCHING
-- (RELEASED is reached only from ISSUED), the approval may still be used,
-- its transaction is an approval-based ALLOW that can be evaluated again,
-- and the transaction has no other live request.
-- name: RestorableApproval :one
SELECT r.id, r.grant_id, r.run_id, r.transaction_id
FROM pc.approval_requests r
JOIN pc.permits p ON p.org_id = r.org_id AND p.id = r.permit_id
JOIN pc.transactions t ON t.org_id = r.org_id AND t.id = r.transaction_id
WHERE r.org_id = sqlc.arg(org_id) AND r.permit_id = sqlc.arg(permit_id) AND r.subject_kind = 'ACTION'
  AND r.state = 'CONSUMED' AND r.consume_by > now() AND r.deadline_at > now() AND p.state = 'RELEASED'
  AND t.state = 'FINAL' AND t.decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS')
  AND t.evaluations < sqlc.arg(max_evaluations)::integer
  AND NOT EXISTS (SELECT 1 FROM pc.approval_requests o
                  WHERE o.org_id = r.org_id AND o.transaction_id = r.transaction_id
                    AND o.state IN ('PENDING', 'EVIDENCE_REQUESTED', 'APPROVED'))
FOR UPDATE OF r, t;

-- RestoreApprovalRequest is the edge CONSUMED -> APPROVED (HR-011): the
-- request forgets the permit and waits for its resubmission again.
-- name: RestoreApprovalRequest :execrows
UPDATE pc.approval_requests SET state = 'APPROVED', consumed_at = NULL, permit_id = NULL, ended_at = NULL
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'CONSUMED' AND consume_by > now();

-- ReopenTransaction lets the resubmission of a transaction whose approval
-- was restored be evaluated again (PAP-1 §7.1).
-- name: ReopenTransaction :execrows
UPDATE pc.transactions SET state = 'OPEN'
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'FINAL' AND decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS');

-- ReleaseRefusedPermit releases a permit BeginDispatch refused that can
-- never pass: it expired, or containment moved past its epoch. It was
-- never DISPATCHING, so nothing was sent (HR-011).
-- name: ReleaseRefusedPermit :one
UPDATE pc.permits p
SET state = 'RELEASED', finished_at = now()
FROM pc.org_containment c
WHERE p.org_id = sqlc.arg(org_id) AND p.id = sqlc.arg(id) AND p.gateway_id = sqlc.arg(gateway_id) AND p.state = 'ISSUED'
  AND p.budget_id IS NULL AND c.org_id = p.org_id AND (p.expires_at <= clock_timestamp() OR p.epoch <> c.epoch)
RETURNING p.id, p.transaction_id;

-- ReplaceReleasedPermits marks a transaction's released permits replaced
-- before its next permit is issued, so it has one current permit.
-- name: ReplaceReleasedPermits :execrows
UPDATE pc.permits SET replaced = true
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND state = 'RELEASED' AND NOT replaced;
