-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Merchant caps for agent payments (G0 M39 D1124, D1124a; HR-835,
-- HR-836). A cap is proposed DRAFT, made ACTIVE only by its confirmed
-- PAYMENT_CAP change request with two distinct people, and retired. Every
-- state change is a conditional update.

-- name: InsertPaymentMerchantCap :exec
INSERT INTO pc.payment_merchant_caps (org_id, id, merchant, currency, max_per_payment_minor, max_per_day_minor, created_by)
VALUES (sqlc.arg(org_id), sqlc.arg(id), sqlc.arg(merchant), sqlc.arg(currency), sqlc.arg(max_per_payment_minor),
        sqlc.arg(max_per_day_minor), sqlc.arg(created_by));

-- name: GetPaymentMerchantCap :one
SELECT id, merchant, currency, max_per_payment_minor, max_per_day_minor, state, created_by, created_at, change_request_id,
       approved_by, activated_at, retired_at, retired_by
FROM pc.payment_merchant_caps
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id);

-- name: LockPaymentMerchantCap :one
SELECT id, merchant, currency, max_per_payment_minor, max_per_day_minor, state
FROM pc.payment_merchant_caps
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id)
FOR UPDATE;

-- name: ListPaymentMerchantCaps :many
SELECT id, merchant, currency, max_per_payment_minor, max_per_day_minor, state, created_by, created_at, change_request_id,
       approved_by, activated_at, retired_at, retired_by
FROM pc.payment_merchant_caps
WHERE org_id = sqlc.arg(org_id)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(merchant)::text IS NULL OR merchant = sqlc.narg(merchant)::text)
  AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id)::uuid)
ORDER BY id
LIMIT sqlc.arg(max_rows)::int;

-- name: ActivePaymentMerchantCap :one
-- The ACTIVE cap of a merchant in a currency, which the payment step reads.
SELECT id, max_per_payment_minor, max_per_day_minor
FROM pc.payment_merchant_caps
WHERE org_id = sqlc.arg(org_id) AND merchant = sqlc.arg(merchant) AND currency = sqlc.arg(currency) AND state = 'ACTIVE';

-- name: RetireActivePaymentMerchantCaps :execrows
-- Activating a cap retires the merchant's earlier ACTIVE cap in that
-- currency, in the same transaction.
UPDATE pc.payment_merchant_caps SET state = 'RETIRED', retired_by = sqlc.arg(retired_by)
WHERE org_id = sqlc.arg(org_id) AND merchant = sqlc.arg(merchant) AND currency = sqlc.arg(currency) AND state = 'ACTIVE';

-- name: ActivatePaymentMerchantCap :execrows
-- The confirmed change request activates a DRAFT cap; the guard requires
-- two distinct approvers and sets activated_at by the database clock.
UPDATE pc.payment_merchant_caps
SET state = 'ACTIVE', change_request_id = sqlc.arg(change_request_id), approved_by = sqlc.arg(approved_by)::uuid[]
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state = 'DRAFT';

-- name: RetirePaymentMerchantCap :execrows
UPDATE pc.payment_merchant_caps SET state = 'RETIRED', retired_by = sqlc.arg(retired_by)
WHERE org_id = sqlc.arg(org_id) AND id = sqlc.arg(id) AND state <> 'RETIRED';

-- name: UsePaymentMandate :execrows
-- Records a verified mandate's single use (G0 M39 D1124b, HR-834): no row
-- when the digest was already used in this org.
INSERT INTO pc.payment_mandate_uses (org_id, mandate_digest, transaction_id, merchant, currency, amount_minor, ap2_transaction_id)
VALUES (@org_id, @mandate_digest, @transaction_id, @merchant, @currency, @amount_minor, @ap2_transaction_id)
ON CONFLICT (org_id, mandate_digest) DO NOTHING;

-- name: PaymentMandateUse :one
-- The transaction that used a mandate digest, which the payment step reads.
SELECT transaction_id FROM pc.payment_mandate_uses
WHERE org_id = @org_id AND mandate_digest = @mandate_digest;

-- name: PaymentMandateUseOfTransaction :one
-- The use a settled transaction recorded, for payments.effect.
SELECT mandate_digest, merchant, currency, amount_minor, ap2_transaction_id FROM pc.payment_mandate_uses
WHERE org_id = @org_id AND transaction_id = @transaction_id
LIMIT 1;

-- name: ConnectionMerchantAudience :one
SELECT merchant_audience FROM pc.connection_agentpay
WHERE org_id = @org_id AND connection_id = @connection_id;

-- name: SetConnectionMerchantAudience :exec
INSERT INTO pc.connection_agentpay (org_id, connection_id, merchant_audience, updated_by)
VALUES (@org_id, @connection_id, @merchant_audience, @updated_by)
ON CONFLICT (org_id, connection_id) DO UPDATE
SET merchant_audience = EXCLUDED.merchant_audience, updated_by = EXCLUDED.updated_by, updated_at = now();
