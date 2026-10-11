-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Restricted payload capture (G0 M7 track B slice B9, design decision 10,
-- founder decision 7; HR-199, HR-062, HR-076, T-076, T-043). Numbered after
-- B8's 00072, founder decision 2026-10-10.
--
-- Capture is off unless a person holding evidence.capture.manage creates a
-- capture profile: a purpose, the connections and operations it covers,
-- the request and/or the response, a byte cap of at most 64 KiB per body, a
-- retention of at most 30 days and an expiry of at most 90 days. A profile
-- only changes by being disabled (or marked expired); it reaches the
-- gateways serving its connections in their configuration.
--
-- A payload capture is one body of one execution attempt: the outbound
-- body the gateway built (never headers or credentials) or the target's
-- response after secret-echo redaction, truncated to the cap. Its content
-- is sealed per row with the org's payload_captures key (AES-256-GCM, AAD
-- org|payload_captures|content|id, HR-062); pc_app inserts and reads rows
-- and never changes or deletes them (HR-055), pc_audit_ro never sees the
-- content, and remove_at (at most 30 days after it was taken) is when the
-- retention job deletes it through pc_retention, unless a legal hold covers
-- its transaction (HR-198).

-- +goose Up
CREATE TABLE pc.capture_profiles (
    org_id           uuid        NOT NULL REFERENCES pc.orgs (id),
    id               uuid        NOT NULL,
    purpose          text        NOT NULL CHECK (char_length(purpose) BETWEEN 1 AND 500),
    connections      uuid[]      NOT NULL CHECK (cardinality(connections) BETWEEN 1 AND 32),
    operations       text[]      NOT NULL CHECK (cardinality(operations) BETWEEN 1 AND 64),
    capture_request  boolean     NOT NULL,
    capture_response boolean     NOT NULL,
    byte_cap         integer     NOT NULL CHECK (byte_cap BETWEEN 1 AND 65536),
    retention_days   integer     NOT NULL CHECK (retention_days BETWEEN 1 AND 30),
    expires_at       timestamptz NOT NULL,
    state            text        NOT NULL DEFAULT 'ACTIVE' CHECK (state IN ('ACTIVE', 'DISABLED', 'EXPIRED')),
    created_by       uuid        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    disabled_by      uuid,
    disabled_at      timestamptz,
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, created_by) REFERENCES pc.users (org_id, id),
    FOREIGN KEY (org_id, disabled_by) REFERENCES pc.users (org_id, id),
    CHECK (capture_request OR capture_response),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days'),
    CHECK ((state = 'DISABLED') = (disabled_by IS NOT NULL AND disabled_at IS NOT NULL))
);
CREATE INDEX capture_profiles_active ON pc.capture_profiles (org_id, expires_at) WHERE state = 'ACTIVE';

CREATE TABLE pc.payload_captures (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    attempt_id     uuid        NOT NULL,
    transaction_id uuid        NOT NULL,
    profile_id     uuid        NOT NULL,
    direction      text        NOT NULL CHECK (direction IN ('request', 'response')),
    -- version(1) || dek_version(4) || nonce(12) || ciphertext || tag(16) of
    -- at most 64 KiB.
    content        bytea       NOT NULL CHECK (octet_length(content) BETWEEN 34 AND 65569),
    -- The body's size before truncation.
    size           integer     NOT NULL CHECK (size BETWEEN 1 AND 1073741824),
    truncated      boolean     NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    remove_at      timestamptz NOT NULL,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, attempt_id, direction),
    FOREIGN KEY (org_id, attempt_id) REFERENCES pc.execution_attempts (org_id, id),
    FOREIGN KEY (org_id, transaction_id) REFERENCES pc.transactions (org_id, id),
    FOREIGN KEY (org_id, profile_id) REFERENCES pc.capture_profiles (org_id, id),
    CHECK (remove_at > created_at AND remove_at <= created_at + interval '30 days')
);
CREATE INDEX payload_captures_transaction ON pc.payload_captures (org_id, transaction_id);
CREATE INDEX payload_captures_retention ON pc.payload_captures (org_id, remove_at);

ALTER TABLE pc.capture_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.capture_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.capture_profiles
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
ALTER TABLE pc.payload_captures ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.payload_captures FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.payload_captures
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

-- Profiles change only their state; captures are evidence (HR-055).
GRANT SELECT, INSERT ON pc.capture_profiles, pc.payload_captures TO pc_app;
GRANT UPDATE (state, disabled_by, disabled_at) ON pc.capture_profiles TO pc_app;
GRANT SELECT ON pc.capture_profiles TO pc_audit_ro;
-- Auditors see that captures exist, never their content.
GRANT SELECT (org_id, id, attempt_id, transaction_id, profile_id, direction, size, truncated, created_at, remove_at)
    ON pc.payload_captures TO pc_audit_ro;
-- The retention job deletes expired captures (design decision 9).
GRANT SELECT (org_id, id, transaction_id, created_at, remove_at) ON pc.payload_captures TO pc_retention;
GRANT DELETE ON pc.payload_captures TO pc_retention;

-- +goose Down
DROP TABLE pc.payload_captures;
DROP TABLE pc.capture_profiles;
