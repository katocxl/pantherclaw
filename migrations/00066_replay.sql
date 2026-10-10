-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Replay inputs (G0 M7 track B, design decision 11, founder decision 5,
-- HR-197). Every evaluation keeps what the decision pipeline read (the
-- canonical action, the run, agent, grant chain, guardrails, connection,
-- containment, claim, hold and variant reads, the facts and the counter and
-- budget values) and the policy and definition by version and digest, as
-- one row written in the same transaction as its decision receipt. The
-- recording is compressed and sealed with the org's evaluation_inputs key
-- (AES-256-GCM, the AAD binds org, table, column and transaction/evaluation,
-- HR-062). A recording larger than 32 KiB compressed is stored truncated:
-- only its digest, and a replay of it is incomplete. Rows are evidence:
-- pc_app inserts and reads them and never changes or deletes them (HR-055);
-- they are kept under the normalized_facts retention category (B8).

-- +goose Up
CREATE TABLE pc.evaluation_inputs (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    transaction_id   uuid        NOT NULL,
    evaluation       integer     NOT NULL CHECK (evaluation BETWEEN 1 AND 64),
    format_version   integer     NOT NULL CHECK (format_version BETWEEN 1 AND 1000),
    pipeline_version integer     NOT NULL CHECK (pipeline_version BETWEEN 1 AND 1000),
    -- version(1) || dek_version(4) || nonce(12) || ciphertext || tag(16) of
    -- at most 32 KiB of compressed recording.
    inputs           bytea       CHECK (inputs IS NULL OR octet_length(inputs) BETWEEN 34 AND 32801),
    -- SHA-256 of the recording before compression, checked when it is opened.
    inputs_sha256    bytea       NOT NULL CHECK (octet_length(inputs_sha256) = 32),
    truncated        boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, transaction_id, evaluation),
    FOREIGN KEY (org_id, transaction_id, evaluation) REFERENCES pc.decision_receipts (org_id, transaction_id, evaluation),
    CHECK (truncated = (inputs IS NULL))
);

ALTER TABLE pc.evaluation_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.evaluation_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.evaluation_inputs
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- Append-only for the application (HR-055, HR-197).
GRANT SELECT, INSERT ON pc.evaluation_inputs TO pc_app;
-- Auditors see that inputs exist and their digests, never the sealed bytes.
GRANT SELECT (org_id, transaction_id, evaluation, format_version, pipeline_version, inputs_sha256, truncated, created_at)
    ON pc.evaluation_inputs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.evaluation_inputs;
