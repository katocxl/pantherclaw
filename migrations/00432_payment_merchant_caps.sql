-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Merchant caps for agent payments (G0 M39 D1124, D1124a; FQ39-2;
-- HR-835, HR-836). Every agent payment holds for a person by default. An
-- org may let payments to one merchant, in one currency, go through without
-- a person while each is at most max_per_payment_minor and the day's total
-- of such payments stays at most max_per_day_minor (in the currency's minor
-- units, UTC days). A cap is proposed DRAFT through PaymentCapService by a
-- person holding payments.manage, and becomes ACTIVE only when its
-- PAYMENT_CAP change request is confirmed by two distinct people with
-- distinct security keys (approved_by, change_request_id): creating or
-- raising a cap is a loosening. A request that could be confirmed by one
-- person is voided (TWO_PEOPLE_REQUIRED). Activating a cap retires the
-- merchant's earlier ACTIVE cap in that currency, so at most one is ACTIVE.
-- RETIRED is final. merchant is the payment's normalized merchant id, as the
-- pc.agentpay merchant param spells it (lowercase).
--
-- A cap's day total is a budget account owned by the cap (owner_kind
-- 'payment_cap', rule merchant_day, grouped by merchant), locked last (rank
-- 7, after a run's token account at 6). Only payments the cap let through
-- without a person debit it.
--
-- pc.payment_mandate_uses records each verified mandate's single use per
-- org (D1124b): a second dispatch of the same mandate digest is refused
-- (MANDATE_REPLAYED).
--
-- pc.policy_change_requests gains the kind PAYMENT_CAP. M37 and M38 may
-- widen the same CHECK; the list below must be their union at assembly.

-- +goose Up
CREATE TABLE pc.payment_merchant_caps (
    org_id                uuid        NOT NULL REFERENCES pc.orgs (id),
    id                    uuid        NOT NULL,
    merchant              text        NOT NULL CHECK (merchant ~ '^[a-z0-9][a-z0-9._:-]{0,127}$'),
    currency              text        NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    max_per_payment_minor bigint      NOT NULL CHECK (max_per_payment_minor BETWEEN 1 AND 100000000000),
    max_per_day_minor     bigint      NOT NULL CHECK (max_per_day_minor BETWEEN 1 AND 100000000000),
    state                 text        NOT NULL DEFAULT 'DRAFT' CHECK (state IN ('DRAFT', 'ACTIVE', 'RETIRED')),
    created_by            text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at            timestamptz NOT NULL DEFAULT now(),
    change_request_id     uuid,
    approved_by           uuid[]      NOT NULL DEFAULT '{}' CHECK (array_position(approved_by, NULL) IS NULL),
    activated_at          timestamptz,
    retired_at            timestamptz,
    retired_by            text        CHECK (retired_by IS NULL OR char_length(retired_by) BETWEEN 1 AND 128),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    CHECK (max_per_payment_minor <= max_per_day_minor),
    CHECK ((activated_at IS NULL) = (cardinality(approved_by) = 0)),
    CHECK (cardinality(approved_by) = 0 OR (cardinality(approved_by) >= 2 AND change_request_id IS NOT NULL)),
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
    CHECK ((state = 'RETIRED') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX payment_merchant_caps_one_active ON pc.payment_merchant_caps (org_id, merchant, currency)
    WHERE state = 'ACTIVE';
CREATE INDEX payment_merchant_caps_created ON pc.payment_merchant_caps (org_id, created_at DESC);

-- A cap's merchant, currency, limits and creator never change; it is
-- inserted DRAFT; it becomes ACTIVE only from DRAFT, once, with two
-- distinct approvers and its change request; RETIRED is final.
-- +goose StatementBegin
CREATE FUNCTION pc.payment_merchant_cap_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state IS DISTINCT FROM 'DRAFT' OR cardinality(NEW.approved_by) <> 0 OR NEW.change_request_id IS NOT NULL
                OR NEW.retired_at IS NOT NULL THEN
            RAISE EXCEPTION 'a merchant cap is inserted DRAFT' USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := now();
        NEW.updated_at := now();
        RETURN NEW;
    END IF;
    IF NEW.merchant IS DISTINCT FROM OLD.merchant OR NEW.currency IS DISTINCT FROM OLD.currency
            OR NEW.max_per_payment_minor IS DISTINCT FROM OLD.max_per_payment_minor
            OR NEW.max_per_day_minor IS DISTINCT FROM OLD.max_per_day_minor
            OR NEW.created_by IS DISTINCT FROM OLD.created_by OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
        RAISE EXCEPTION 'a merchant cap''s merchant, currency and limits never change' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state = 'RETIRED' AND (NEW.state IS DISTINCT FROM 'RETIRED' OR NEW.retired_at IS DISTINCT FROM OLD.retired_at
            OR NEW.retired_by IS DISTINCT FROM OLD.retired_by) THEN
        RAISE EXCEPTION 'a retired merchant cap stays retired' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'DRAFT' AND OLD.state IS DISTINCT FROM 'DRAFT' THEN
        RAISE EXCEPTION 'a merchant cap cannot return to DRAFT' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.state = 'ACTIVE' AND OLD.state = 'DRAFT' THEN
        IF NEW.change_request_id IS NULL OR cardinality(NEW.approved_by) < 2
                OR (SELECT count(DISTINCT x) FROM unnest(NEW.approved_by) AS x) < 2 THEN
            RAISE EXCEPTION 'a merchant cap is activated by its change request and two distinct people' USING ERRCODE = 'check_violation';
        END IF;
        NEW.activated_at := now();
    ELSIF OLD.activated_at IS NOT NULL AND (NEW.activated_at IS DISTINCT FROM OLD.activated_at
            OR NEW.approved_by IS DISTINCT FROM OLD.approved_by OR NEW.change_request_id IS DISTINCT FROM OLD.change_request_id) THEN
        RAISE EXCEPTION 'a merchant cap is activated once' USING ERRCODE = 'check_violation';
    ELSIF OLD.activated_at IS NULL AND (cardinality(NEW.approved_by) <> 0 OR NEW.change_request_id IS NOT NULL) THEN
        RAISE EXCEPTION 'only activation sets a merchant cap''s approvers' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.state IS DISTINCT FROM 'RETIRED' AND NEW.state = 'RETIRED' THEN
        NEW.retired_at := now();
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER payment_merchant_caps_guard BEFORE INSERT OR UPDATE ON pc.payment_merchant_caps
    FOR EACH ROW EXECUTE FUNCTION pc.payment_merchant_cap_guard();

ALTER TABLE pc.payment_merchant_caps ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.payment_merchant_caps FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.payment_merchant_caps
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.payment_merchant_caps TO pc_app;
GRANT UPDATE (state, change_request_id, approved_by, activated_at, retired_at, retired_by, updated_at)
    ON pc.payment_merchant_caps TO pc_app;
GRANT SELECT ON pc.payment_merchant_caps TO pc_audit_ro;

-- Single use (D1124b, HR-834): a verified mandate (by its digest) is
-- dispatched at most once per org. The row is written in the transaction
-- that records the payment's permit; a second use is MANDATE_REPLAYED,
-- whether or not a person approved it. Rows are never updated or deleted.
-- The verified facts kept beside the digest feed the payments.effect
-- evidence when the dispatch is settled (HR-840): never the mandate.
CREATE TABLE pc.payment_mandate_uses (
    org_id             uuid        NOT NULL REFERENCES pc.orgs (id),
    mandate_digest     text        NOT NULL CHECK (mandate_digest ~ '^sha256:[0-9a-f]{64}$'),
    transaction_id     uuid        NOT NULL,
    merchant           text        NOT NULL CHECK (char_length(merchant) BETWEEN 1 AND 256),
    currency           text        NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    amount_minor       bigint      NOT NULL CHECK (amount_minor >= 0),
    ap2_transaction_id text        NOT NULL CHECK (char_length(ap2_transaction_id) BETWEEN 1 AND 256),
    used_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, mandate_digest),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id)
);
CREATE INDEX payment_mandate_uses_transaction ON pc.payment_mandate_uses (org_id, transaction_id);

ALTER TABLE pc.payment_mandate_uses ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.payment_mandate_uses FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.payment_mandate_uses
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.payment_mandate_uses TO pc_app;
GRANT SELECT ON pc.payment_mandate_uses TO pc_audit_ro;

-- The audience a pc.agentpay connection's mandates must name (D1124c,
-- D1124d): the KB-JWT aud the server pins with ap2.WithAudiences. No row
-- means no audience, so every mandate on the connection is refused (fail
-- closed). Set by a person with payments.manage (payments.audience_set).
CREATE TABLE pc.connection_agentpay (
    org_id            uuid        NOT NULL,
    connection_id     uuid        NOT NULL,
    merchant_audience text        NOT NULL CHECK (merchant_audience ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$'),
    updated_by        text        NOT NULL CHECK (char_length(updated_by) BETWEEN 1 AND 128),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, connection_id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);

ALTER TABLE pc.connection_agentpay ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.connection_agentpay FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.connection_agentpay
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.connection_agentpay TO pc_app;
GRANT UPDATE (merchant_audience, updated_by, updated_at) ON pc.connection_agentpay TO pc_app;
GRANT SELECT ON pc.connection_agentpay TO pc_audit_ro;

-- squawk: each CHECK only widens a value list; goose runs each migration in
-- one transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.policy_change_requests
    DROP CONSTRAINT policy_change_requests_kind_check,
    ADD CONSTRAINT policy_change_requests_kind_check
        CHECK (kind IN ('PUBLISH', 'ROLLOUT', 'EXCEPTION', 'PAYMENT_CAP')) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.policy_change_requests VALIDATE CONSTRAINT policy_change_requests_kind_check;

ALTER TABLE pc.budget_accounts
    DROP CONSTRAINT budget_accounts_owner_kind_check,
    ADD CONSTRAINT budget_accounts_owner_kind_check
        CHECK (owner_kind IN ('grant', 'envelope', 'run', 'payment_cap')) NOT VALID,
    DROP CONSTRAINT budget_accounts_rank_check,
    ADD CONSTRAINT budget_accounts_rank_check CHECK (rank BETWEEN 0 AND 7) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.budget_accounts VALIDATE CONSTRAINT budget_accounts_owner_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.budget_accounts VALIDATE CONSTRAINT budget_accounts_rank_check;

-- +goose Down
-- Merchant cap accounts and PAYMENT_CAP requests have no meaning before this
-- migration.
DELETE FROM pc.reservations r USING pc.budget_accounts a
    WHERE r.org_id = a.org_id AND r.account_id = a.id AND (a.owner_kind = 'payment_cap' OR a.rank = 7);
DELETE FROM pc.budget_accounts a WHERE a.owner_kind = 'payment_cap' OR a.rank = 7;
ALTER TABLE pc.budget_accounts
    DROP CONSTRAINT budget_accounts_rank_check,
    ADD CONSTRAINT budget_accounts_rank_check CHECK (rank BETWEEN 0 AND 6),
    DROP CONSTRAINT budget_accounts_owner_kind_check,
    ADD CONSTRAINT budget_accounts_owner_kind_check CHECK (owner_kind IN ('grant', 'envelope', 'run'));
DELETE FROM pc.policy_change_confirmations c USING pc.policy_change_requests r
    WHERE c.org_id = r.org_id AND c.request_id = r.id AND r.kind = 'PAYMENT_CAP';
DELETE FROM pc.webauthn_ceremonies c USING pc.policy_change_requests r
    WHERE c.org_id = r.org_id AND c.policy_change_request_id = r.id AND r.kind = 'PAYMENT_CAP';
DELETE FROM pc.policy_change_requests WHERE kind = 'PAYMENT_CAP';
ALTER TABLE pc.policy_change_requests
    DROP CONSTRAINT policy_change_requests_kind_check,
    ADD CONSTRAINT policy_change_requests_kind_check CHECK (kind IN ('PUBLISH', 'ROLLOUT', 'EXCEPTION'));
DROP TABLE pc.connection_agentpay;
DROP TABLE pc.payment_mandate_uses;
DROP TABLE pc.payment_merchant_caps;
DROP FUNCTION pc.payment_merchant_cap_guard();
