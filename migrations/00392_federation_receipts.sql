-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
--
-- Federation receipts (G0 M35 D1023, D1024; FQ35-2; HR-776). OUT: the
-- minimal pap-fed-receipt+jwt a peer org returned for a message our agent
-- sent, checked against the pinned peer keys (VALID), or MISSING or INVALID
-- when it did not come back or did not verify. IN: the peer's pap-fed+jwt a
-- message to our agent was decided on, with the decision we answered. The
-- JWS is stored as received; a row never changes.

-- +goose Up
CREATE TABLE pc.federation_receipts (
    org_id         uuid        NOT NULL REFERENCES pc.orgs (id),
    id             uuid        NOT NULL,
    direction      text        NOT NULL CHECK (direction IN ('OUT', 'IN')),
    trust_id       uuid        NOT NULL,
    peer_org_id    uuid        NOT NULL,
    action_id      uuid,
    peer_action_id text        CHECK (char_length(peer_action_id) BETWEEN 1 AND 128),
    decision       text        CHECK (decision IN ('ALLOW', 'DENY', 'HELD')),
    receipt_jws    text        CHECK (char_length(receipt_jws) BETWEEN 1 AND 16384),
    state          text        NOT NULL CHECK (state IN ('VALID', 'MISSING', 'INVALID')),
    received_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, id),
    FOREIGN KEY (org_id, trust_id) REFERENCES pc.federation_trusts (org_id, id),
    CONSTRAINT federation_receipts_jws CHECK ((state = 'MISSING') = (receipt_jws IS NULL)),
    CONSTRAINT federation_receipts_valid CHECK (state <> 'VALID' OR decision IS NOT NULL)
);
CREATE INDEX federation_receipts_action ON pc.federation_receipts (org_id, action_id) WHERE action_id IS NOT NULL;
CREATE INDEX federation_receipts_recent ON pc.federation_receipts (org_id, received_at DESC);

ALTER TABLE pc.federation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.federation_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON pc.federation_receipts
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.federation_receipts
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
GRANT SELECT, INSERT ON pc.federation_receipts TO pc_app;
GRANT SELECT ON pc.federation_receipts TO pc_audit_ro;
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.federation_receipts TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE pc.federation_receipts;
