-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Walking-skeleton authority tables (BUILD_GUIDE §8 M1.5): containment epoch,
-- budgets and their ledger, transactions (one per (org, run, action)),
-- decision receipts, single-use dispatch permits and execution attempts.
-- State changes are conditional updates (HR-004); receipts, attempts and the
-- budget ledger are append-only for pc_app (HR-055). The CHECK on budgets is a
-- second line of defense against overspend (T-011); the finalization code's
-- conditional UPDATE is the first.

-- +goose Up
CREATE TABLE pc.org_containment (
    org_id      uuid        NOT NULL REFERENCES pc.orgs (id),
    epoch       bigint      NOT NULL DEFAULT 1 CHECK (epoch > 0),
    kill_switch boolean     NOT NULL DEFAULT false,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id)
);

CREATE TABLE pc.budgets (
    org_id         uuid          NOT NULL REFERENCES pc.orgs (id),
    id             uuid          NOT NULL,
    name           text          NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    currency       text          NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    limit_amount   numeric(26,8) NOT NULL CHECK (limit_amount >= 0),
    reserved       numeric(26,8) NOT NULL DEFAULT 0 CHECK (reserved >= 0),
    spent          numeric(26,8) NOT NULL DEFAULT 0 CHECK (spent >= 0),
    max_count      integer       CHECK (max_count IS NULL OR max_count >= 0),
    reserved_count integer       NOT NULL DEFAULT 0 CHECK (reserved_count >= 0),
    spent_count    integer       NOT NULL DEFAULT 0 CHECK (spent_count >= 0),
    created_at     timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, name),
    CONSTRAINT budgets_no_overspend CHECK (spent + reserved <= limit_amount),
    CONSTRAINT budgets_no_overcount CHECK (max_count IS NULL OR spent_count + reserved_count <= max_count)
);

CREATE TABLE pc.transactions (
    org_id         uuid          NOT NULL REFERENCES pc.orgs (id),
    id             uuid          NOT NULL,
    run_id         uuid          NOT NULL,
    action_id      uuid          NOT NULL,
    action_hash    bytea         NOT NULL CHECK (octet_length(action_hash) = 32),
    operation      text          NOT NULL,
    decision       text          NOT NULL CHECK (decision IN ('ALLOW', 'ALLOW_WITH_OBLIGATIONS', 'REQUIRE_APPROVAL',
                                                              'REQUIRE_STEP_UP', 'DENY', 'CANNOT_AUTHORIZE')),
    reason_code    text          NOT NULL CHECK (char_length(reason_code) BETWEEN 1 AND 64),
    budget_id      uuid,
    amount         numeric(26,8),
    currency       text,
    gateway_id     text          NOT NULL,
    created_at     timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, run_id, action_id),
    FOREIGN KEY (org_id, budget_id) REFERENCES pc.budgets (org_id, id)
);

CREATE TABLE pc.budget_ledger (
    org_id         uuid          NOT NULL,
    id             uuid          NOT NULL,
    budget_id      uuid          NOT NULL,
    transaction_id uuid          NOT NULL,
    kind           text          NOT NULL CHECK (kind IN ('reserve', 'commit', 'release', 'hold_unknown')),
    amount         numeric(26,8) NOT NULL CHECK (amount >= 0),
    created_at     timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, budget_id) REFERENCES pc.budgets (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id)
);

CREATE TABLE pc.decision_receipts (
    org_id          uuid        NOT NULL,
    transaction_id  uuid        NOT NULL,
    receipt_jws     text        NOT NULL CHECK (octet_length(receipt_jws) <= 65536),
    ledger_entry_id uuid        NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, transaction_id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, ledger_entry_id) REFERENCES pc.ledger_entries (org_id, id)
);

CREATE TABLE pc.permits (
    org_id          uuid          NOT NULL,
    id              uuid          NOT NULL,
    transaction_id  uuid          NOT NULL,
    gateway_id      text          NOT NULL,
    epoch           bigint        NOT NULL,
    state           text          NOT NULL DEFAULT 'ISSUED'
                                  CHECK (state IN ('ISSUED', 'DISPATCHING', 'DISPATCHED', 'UNKNOWN', 'RELEASED')),
    budget_id       uuid          NOT NULL,
    amount          numeric(26,8) NOT NULL,
    issued_at       timestamptz   NOT NULL DEFAULT now(),
    expires_at      timestamptz   NOT NULL,
    dispatching_at  timestamptz,
    finished_at     timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, transaction_id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, budget_id) REFERENCES pc.budgets (org_id, id)
);
CREATE INDEX permits_open ON pc.permits (org_id, state, expires_at) WHERE state IN ('ISSUED', 'DISPATCHING');

CREATE TABLE pc.execution_attempts (
    org_id          uuid        NOT NULL,
    id              uuid        NOT NULL,
    permit_id       uuid        NOT NULL,
    transaction_id  uuid        NOT NULL,
    outcome         text        NOT NULL CHECK (outcome IN ('accepted', 'failed', 'unknown')),
    target_status   integer,
    response_digest bytea       CHECK (response_digest IS NULL OR octet_length(response_digest) = 32),
    dispatch_ms     integer     CHECK (dispatch_ms IS NULL OR dispatch_ms >= 0),
    recorded_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, permit_id),
    FOREIGN KEY (org_id, permit_id) REFERENCES pc.permits (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id)
);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_containment', 'budgets', 'transactions', 'budget_ledger',
                             'decision_receipts', 'permits', 'execution_attempts']
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

GRANT SELECT, INSERT ON pc.org_containment, pc.budgets, pc.transactions, pc.budget_ledger,
    pc.decision_receipts, pc.permits, pc.execution_attempts TO pc_app;
GRANT UPDATE (epoch, kill_switch, updated_at) ON pc.org_containment TO pc_app;
GRANT UPDATE (reserved, spent, reserved_count, spent_count) ON pc.budgets TO pc_app;
GRANT UPDATE (state, dispatching_at, finished_at) ON pc.permits TO pc_app;
GRANT SELECT ON pc.transactions, pc.decision_receipts, pc.permits, pc.execution_attempts, pc.budget_ledger TO pc_audit_ro;

-- The sweeper finds orgs with expired ISSUED or stale DISPATCHING permits.
GRANT SELECT (org_id, state, expires_at, dispatching_at) ON pc.permits TO pc_lister;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        WHEN 'permits_sweep' THEN
            RETURN QUERY
                SELECT DISTINCT p.org_id, p.org_id
                FROM pc.permits p
                WHERE (p.state = 'ISSUED' AND p.expires_at < now())
                   OR (p.state = 'DISPATCHING' AND p.dispatching_at < now() - interval '30 seconds')
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pc.cross_org_list(p_purpose text, p_max_rows integer)
RETURNS TABLE (org_id uuid, id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pc, pg_temp
AS $$
BEGIN
    IF p_max_rows IS NULL OR p_max_rows < 1 OR p_max_rows > 10000 THEN
        RAISE EXCEPTION 'cross_org_list: max_rows must be between 1 and 10000';
    END IF;
    INSERT INTO pc.cross_org_list_audit (purpose, max_rows, caller)
    VALUES (left(p_purpose, 64), p_max_rows, session_user);
    CASE p_purpose
        WHEN 'orgs' THEN
            RETURN QUERY SELECT o.id, o.id FROM pc.orgs o WHERE o.state = 'ACTIVE' ORDER BY o.id LIMIT p_max_rows;
        WHEN 'ledger_unchained' THEN
            -- One row per org that has entries above its chain watermark; the
            -- id column repeats the org id.
            RETURN QUERY
                SELECT DISTINCT e.org_id, e.org_id
                FROM pc.ledger_entries e
                LEFT JOIN pc.ledger_heads h ON h.org_id = e.org_id
                WHERE e.xid >= coalesce(h.xid_watermark, '0'::xid8)
                ORDER BY 1
                LIMIT p_max_rows;
        ELSE
            RAISE EXCEPTION 'cross_org_list: unknown purpose';
    END CASE;
END;
$$;
-- +goose StatementEnd
DROP TABLE pc.execution_attempts;
DROP TABLE pc.permits;
DROP TABLE pc.decision_receipts;
DROP TABLE pc.budget_ledger;
DROP TABLE pc.transactions;
DROP TABLE pc.budgets;
DROP TABLE pc.org_containment;
