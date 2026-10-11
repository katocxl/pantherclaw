-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Probe reports (G0 M9 track B slice B4; HR-215, HR-121; T-087). Every
-- report, from the probe container (SANDBOX), the control run (CONTROL) or
-- the canary (CANARY), must carry a fresh server nonce: probe_nonces keeps
-- each one's SHA-256, its session and kind, and when it was used. A nonce
-- is valid 15 minutes and used once; a replayed or stale report is
-- rejected and recorded.
--
-- probe_runs keeps each verified report exactly as signed (a compact JWS),
-- and its digest. The parsed results are stored only in the closure
-- (coverage_closures.probes, through the closure contract), never twice.

-- +goose Up
CREATE TABLE pc.probe_nonces (
    org_id       uuid        NOT NULL REFERENCES pc.orgs (id),
    id           uuid        NOT NULL,
    session_id   uuid        NOT NULL,
    kind         text        NOT NULL CHECK (kind IN ('SANDBOX', 'CONTROL', 'CANARY')),
    nonce_sha256 bytea       NOT NULL CHECK (octet_length(nonce_sha256) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    used_at      timestamptz,
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, nonce_sha256),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sandbox_sessions (org_id, id),
    CONSTRAINT probe_nonces_ttl CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);
CREATE INDEX probe_nonces_session ON pc.probe_nonces (org_id, session_id);

CREATE TABLE pc.probe_runs (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    session_id    uuid        NOT NULL,
    nonce_id      uuid        NOT NULL,
    kind          text        NOT NULL CHECK (kind IN ('SANDBOX', 'CONTROL', 'CANARY')),
    -- The report as signed: a compact JWS, typ pap-probe+jwt.
    report        text        NOT NULL CHECK (char_length(report) BETWEEN 1 AND 65536),
    report_sha256 bytea       NOT NULL CHECK (octet_length(report_sha256) = 32),
    received_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    UNIQUE (org_id, nonce_id),
    FOREIGN KEY (org_id, session_id) REFERENCES pc.sandbox_sessions (org_id, id),
    FOREIGN KEY (org_id, nonce_id) REFERENCES pc.probe_nonces (org_id, id)
);
CREATE INDEX probe_runs_session ON pc.probe_runs (org_id, session_id, kind, id DESC);

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['probe_nonces', 'probe_runs']
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

-- Reports are evidence (HR-055): inserted, never changed.
GRANT SELECT, INSERT ON pc.probe_nonces, pc.probe_runs TO pc_app;
GRANT UPDATE (used_at) ON pc.probe_nonces TO pc_app;
GRANT SELECT ON pc.probe_nonces, pc.probe_runs TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.probe_runs;
DROP TABLE pc.probe_nonces;
