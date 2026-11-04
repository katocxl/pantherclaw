-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Model usage rows (G0 M29 D825; F987, F988; HR-693, HR-698). One row per
-- model create or count call through a model connection, written in the
-- transaction that records its outcome: the token counts the provider
-- reported (zeros and reported = false when it reported none, or when the
-- outcome is UNKNOWN), and, on Team, an estimate from the connection's
-- prices. The agent's team is the one it had at write. Rows are
-- append-only; the monthly token report sums them. No prompt or reply is
-- ever stored (HR-695): metadata and counts only.

-- +goose Up
CREATE TABLE pc.model_usage (
    org_id             uuid          NOT NULL REFERENCES pc.orgs (id),
    id                 uuid          NOT NULL,
    transaction_id     uuid          NOT NULL,
    run_id             uuid,
    agent_id           uuid,
    team_id            uuid,
    connection_id      uuid          NOT NULL,
    operation          text          NOT NULL CHECK (char_length(operation) BETWEEN 1 AND 256),
    model              text          NOT NULL CHECK (length(model) <= 256),
    outcome            text          NOT NULL CHECK (outcome IN ('ACCEPTED', 'DELEGATED', 'FAILED', 'UNKNOWN')),
    reported           boolean       NOT NULL,
    input_tokens       bigint        NOT NULL CHECK (input_tokens >= 0),
    output_tokens      bigint        NOT NULL CHECK (output_tokens >= 0),
    cache_read_tokens  bigint        NOT NULL CHECK (cache_read_tokens >= 0),
    cache_write_tokens bigint        NOT NULL CHECK (cache_write_tokens >= 0),
    estimate           numeric(26,8) CHECK (estimate >= 0),
    estimate_currency  text          CHECK (estimate_currency ~ '^[A-Z]{3}$'),
    recorded_at        timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, transaction_id),
    CONSTRAINT model_usage_estimate CHECK ((estimate IS NULL) = (estimate_currency IS NULL))
);
CREATE INDEX model_usage_recorded ON pc.model_usage (org_id, recorded_at);
-- The run inspector's estimate reads one run's rows (D824).
CREATE INDEX model_usage_run ON pc.model_usage (org_id, run_id) WHERE run_id IS NOT NULL;

ALTER TABLE pc.model_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.model_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.model_usage
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.model_usage
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();

-- Append-only: the application inserts and reads, never updates or deletes.
GRANT SELECT, INSERT ON pc.model_usage TO pc_app;
GRANT SELECT ON pc.model_usage TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.model_usage TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.model_usage;
