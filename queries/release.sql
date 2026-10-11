-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- The release of an unknown outcome and its waitlist entry (G0 M7 slice
-- A11, design decision 3, HR-192).

-- ReleaseParties are the people who may not release a transaction's
-- unknown outcome: the run's launcher and represented principal, and the
-- agent's owner and backup owner (users only; a service account never
-- releases anything).
-- name: ReleaseParties :one
SELECT r.launcher_user_id, r.principal_user_id, a.owner_user_id, a.backup_owner_user_id
FROM pc.transactions t
JOIN pc.runs r ON r.org_id = t.org_id AND r.id = t.run_id
JOIN pc.agents a ON a.org_id = r.org_id AND a.id = r.agent_id
WHERE t.org_id = sqlc.arg(org_id) AND t.id = sqlc.arg(id);

-- ReleaseCeremony is the person's open BINDING ceremony for a
-- reconciliation in this browser session, locked: what their key signed.
-- name: ReleaseCeremony :one
SELECT challenge, expires_at > now() AS live
FROM pc.webauthn_ceremonies
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND reconciliation_id = sqlc.arg(reconciliation_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND consumed_at IS NULL
FOR UPDATE;

-- ConsumeReleaseCeremony consumes the ceremony once, in the transaction
-- that records the release (HR-033, HR-153, HR-004): this person, browser
-- session and reconciliation, the release's binding as its challenge,
-- within its 5 minutes.
-- name: ConsumeReleaseCeremony :execrows
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND reconciliation_id = sqlc.arg(reconciliation_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND challenge = sqlc.arg(challenge) AND consumed_at IS NULL
  AND expires_at > now();

-- SpendReleaseCeremony spends the ceremony of a refused release, so one
-- assertion is never tried twice.
-- name: SpendReleaseCeremony :exec
UPDATE pc.webauthn_ceremonies SET consumed_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND purpose = 'BINDING'
  AND reconciliation_id = sqlc.arg(reconciliation_id) AND user_id = sqlc.arg(user_id)
  AND session_id = sqlc.arg(session_id) AND consumed_at IS NULL;

-- ReleaseReconciliation records a person's release ("did not occur") with
-- their browser session, credential, the full assertion, the basis they
-- wrote and the observations they were shown; only an open unknown outcome
-- changes, once (HR-004).
-- name: ReleaseReconciliation :execrows
UPDATE pc.reconciliation_tasks
SET state = 'NOT_OCCURRED', resolved_via = 'person', user_id = sqlc.arg(user_id), session_id = sqlc.arg(session_id),
    credential_id = sqlc.arg(credential_id), authenticator_data = sqlc.arg(authenticator_data),
    client_data_json = sqlc.arg(client_data_json), signature = sqlc.arg(signature), basis = sqlc.arg(basis),
    evidence = sqlc.arg(evidence)::uuid[], resolved_at = now()
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND kind = 'unknown_outcome' AND state = 'OPEN';

-- LinkReconciliationEntry names the RECONCILIATION waitlist entry people
-- work a transaction's open unknown outcome from (M5 part 2 audit finding
-- F1).
-- name: LinkReconciliationEntry :exec
UPDATE pc.reconciliation_tasks SET waitlist_entry_id = sqlc.arg(entry_id)
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND kind = 'unknown_outcome'
  AND state = 'OPEN' AND waitlist_entry_id IS NULL;

-- ReconciliationOfTransaction is the latest unknown-outcome reconciliation
-- of a transaction: the page a RECONCILIATION entry's notices link to.
-- name: ReconciliationOfTransaction :one
SELECT id FROM pc.reconciliation_tasks
WHERE org_id = sqlc.arg(org_id) AND transaction_id = sqlc.arg(transaction_id) AND kind = 'unknown_outcome'
ORDER BY opened_at DESC, id DESC
LIMIT 1;
