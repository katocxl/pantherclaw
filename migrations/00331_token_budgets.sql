-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Token budgets (G0 M29 D821, D822; F982, F983; HR-693). A budget account
-- counts money ('currency', the default, every existing row) or model tokens
-- ('tokens', no currency). A run may carry a token cap, set at creation and
-- never changed (pc.runs.max_tokens, D822); its account is owned by the run
-- that set the cap and shared with its descendants (owner_kind 'run', D875) and is locked last in the HR-048 order, so its rank
-- is one past the deepest grant's (grants rank depth + 1, depth at most 4).
-- A model call reserves an estimate and settles at the usage the provider
-- reported: settled_amount is what a token reservation commits instead of
-- its whole amount (NULL commits the whole reservation).

-- +goose Up
-- squawk: each CHECK only widens a value list or holds for every existing
-- row (unit defaults to 'currency'); goose runs each migration in one
-- transaction, and NOT VALID then VALIDATE keeps the lock short.
ALTER TABLE pc.budget_accounts
    ADD COLUMN unit text NOT NULL DEFAULT 'currency' CHECK (unit IN ('currency', 'tokens')),
    ADD CONSTRAINT budget_accounts_unit_currency CHECK (unit = 'currency' OR currency IS NULL) NOT VALID,
    DROP CONSTRAINT budget_accounts_owner_kind_check,
    ADD CONSTRAINT budget_accounts_owner_kind_check
        CHECK (owner_kind IN ('grant', 'envelope', 'run')) NOT VALID,
    DROP CONSTRAINT budget_accounts_rank_check,
    ADD CONSTRAINT budget_accounts_rank_check CHECK (rank BETWEEN 0 AND 6) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.budget_accounts VALIDATE CONSTRAINT budget_accounts_unit_currency;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.budget_accounts VALIDATE CONSTRAINT budget_accounts_owner_kind_check;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.budget_accounts VALIDATE CONSTRAINT budget_accounts_rank_check;

ALTER TABLE pc.reservations
    ADD COLUMN settled_amount numeric(26,8) CHECK (settled_amount >= 0);
GRANT UPDATE (settled_amount) ON pc.reservations TO pc_app;

-- A capped run and all its descendants share one token account, owned by
-- the run that set the cap (token_cap_run_id, D875): a child run copies
-- both columns from its parent, so its model calls cannot escape the cap.
ALTER TABLE pc.runs
    ADD COLUMN max_tokens bigint CHECK (max_tokens BETWEEN 1 AND 1000000000000),
    ADD COLUMN token_cap_run_id uuid,
    ADD CONSTRAINT runs_token_cap_check CHECK ((max_tokens IS NULL) = (token_cap_run_id IS NULL)) NOT VALID;
-- squawk-ignore constraint-missing-not-valid
ALTER TABLE pc.runs VALIDATE CONSTRAINT runs_token_cap_check;

-- +goose Down
ALTER TABLE pc.runs DROP CONSTRAINT runs_token_cap_check;
ALTER TABLE pc.runs DROP COLUMN token_cap_run_id;
ALTER TABLE pc.runs DROP COLUMN max_tokens;
REVOKE UPDATE (settled_amount) ON pc.reservations FROM pc_app;
ALTER TABLE pc.reservations DROP COLUMN settled_amount;
-- Token and run accounts have no meaning before this migration.
DELETE FROM pc.reservations r USING pc.budget_accounts a
    WHERE r.org_id = a.org_id AND r.account_id = a.id
      AND (a.unit = 'tokens' OR a.owner_kind = 'run' OR a.rank = 6);
DELETE FROM pc.budget_accounts a
    WHERE a.unit = 'tokens' OR a.owner_kind = 'run' OR a.rank = 6;
ALTER TABLE pc.budget_accounts
    DROP CONSTRAINT budget_accounts_rank_check,
    ADD CONSTRAINT budget_accounts_rank_check CHECK (rank BETWEEN 0 AND 5),
    DROP CONSTRAINT budget_accounts_owner_kind_check,
    ADD CONSTRAINT budget_accounts_owner_kind_check CHECK (owner_kind IN ('grant', 'envelope')),
    DROP CONSTRAINT budget_accounts_unit_currency,
    DROP COLUMN unit;
