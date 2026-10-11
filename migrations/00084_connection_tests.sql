-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Connection tests (G0 M8 track C, slice C2; F350, F354, F358). A person
-- holding connection.manage tests a connection: PantherClaw checks what the
-- connection depends on (its state, its gateway and the gateway's current
-- certificate, the pinned package, the credential sealed to the gateway's
-- current broker key, the circuit) without calling the target, so the test
-- never changes anything there. Each result is kept: the latest PASSED one
-- is the connection's last successful test, and connection health shows
-- both. A test result is evidence: pc_app never updates or deletes one.

-- +goose Up
CREATE TABLE pc.connection_tests (
    org_id        uuid        NOT NULL REFERENCES pc.orgs (id),
    id            uuid        NOT NULL,
    connection_id uuid        NOT NULL,
    result        text        NOT NULL CHECK (result IN ('PASSED', 'FAILED')),
    -- One {check, passed, detail} object per check, in order.
    checks        jsonb       NOT NULL CHECK (jsonb_typeof(checks) = 'array' AND octet_length(checks::text) <= 16384),
    tested_by     text        NOT NULL CHECK (char_length(tested_by) BETWEEN 1 AND 100),
    tested_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, connection_id) REFERENCES pc.connections (org_id, id)
);

CREATE INDEX connection_tests_latest ON pc.connection_tests (org_id, connection_id, tested_at DESC);

ALTER TABLE pc.connection_tests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.connection_tests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.connection_tests
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));

GRANT SELECT, INSERT ON pc.connection_tests TO pc_app;
GRANT SELECT ON pc.connection_tests TO pc_audit_ro;

-- +goose Down
DROP TABLE pc.connection_tests;
