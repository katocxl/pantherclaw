-- SPDX-License-Identifier: BUSL-1.1
-- Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.
-- Durable filtered security events (M13 F15/D53). An emission attempt is
-- never a remote durability acknowledgement. Rows are retained after ACK.
-- +goose Up
CREATE TABLE pc.security_event_outbox (
    org_id uuid NOT NULL REFERENCES pc.orgs(id),
    ledger_seq bigint NOT NULL CHECK (ledger_seq > 0),
    payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_emitted_at timestamptz,
    acknowledged_at timestamptz,
    PRIMARY KEY (org_id, ledger_seq),
    FOREIGN KEY (org_id, ledger_seq) REFERENCES pc.ledger_chain(org_id, seq)
);
ALTER TABLE pc.security_event_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE pc.security_event_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant ON pc.security_event_outbox
    USING (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid))
    WITH CHECK (org_id = (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid));
GRANT SELECT, INSERT ON pc.security_event_outbox TO pc_app;
GRANT UPDATE (attempts, last_emitted_at, acknowledged_at) ON pc.security_event_outbox TO pc_app;
CREATE INDEX security_event_outbox_due ON pc.security_event_outbox (org_id, last_emitted_at, ledger_seq)
    WHERE acknowledged_at IS NULL;
CREATE INDEX security_event_outbox_intent ON pc.security_event_outbox
    (org_id, (payload->>'kind'), (payload->'object'->>'id'), (payload->>'journal_digest'))
    WHERE payload->>'kind' IN ('org.deletion_started', 'account.deletion_started');
-- 00181 is required: never silently omit the tenant write freeze.
CREATE TRIGGER org_write_guard BEFORE INSERT OR UPDATE ON pc.security_event_outbox
    FOR EACH ROW EXECUTE FUNCTION pc.org_write_guard();
-- The login role is optional until db bootstrap --deleter-password-file.
-- Bootstrap grants it all tenant tables when it is configured later.
-- +goose StatementBegin
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'pc_deleter') THEN
        GRANT SELECT, DELETE ON pc.security_event_outbox TO pc_deleter;
    END IF;
END $$;
-- +goose StatementEnd
-- +goose Down
DROP TABLE pc.security_event_outbox;

